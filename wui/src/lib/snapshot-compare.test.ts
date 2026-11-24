import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  alignCallgraphEdges,
  alignFunctions,
  alignSymbols,
  alignVariables,
  buildCallgraphLayout,
  buildCompareUrl,
  computeUnifiedDiff,
  countSnapshotStats,
  normalizeSnapshotAddr,
  parseCompareUrl,
  parseJsonl,
  type LoadedSnapshot,
  type SnapshotFunction,
} from './snapshot-compare.ts';

function makeSnapshot(overrides: Partial<LoadedSnapshot> & { id: string; label: string }): LoadedSnapshot {
  return {
    sourceKind: 'path',
    dirPath: `/tmp/${overrides.id}`,
    manifest: {
      version: 0,
      binary_name: 'sample',
      export_layout_version: 2,
      files: ['manifest.json', 'functions.jsonl', 'symbols.json', 'callgraph.jsonl', 'types.h'],
    },
    functions: [],
    symbols: {
      globals: [],
      strings: [],
      imports: [],
      exports: [],
      classes: [],
      namespaces: [],
    },
    callgraph: [],
    typesHeader: '',
    sources: {},
    sourcesComplete: true,
    loadSource: async () => null,
    ...overrides,
  };
}

describe('snapshot-compare core helpers', () => {
  it('parses JSONL skipping blank lines and CRLF', () => {
    const rows = parseJsonl<{ a: number }>('{"a":1}\r\n\r\n  {"a":2} \n');
    assert.deepEqual(rows, [{ a: 1 }, { a: 2 }]);
  });

  it('normalizes addresses while preserving EXTERNAL: space prefix', () => {
    assert.equal(normalizeSnapshotAddr('00401129'), '401129');
    assert.equal(normalizeSnapshotAddr('0x00401129'), '401129');
    assert.equal(normalizeSnapshotAddr('EXTERNAL:00000001'), 'external:1');
  });

  it('round-trips compare URL query parameters across 3+ snapshots', () => {
    const query = buildCompareUrl(
      [
        { path: '/tmp/stripped', label: 'Stripped' },
        { path: '/tmp/v1', label: 'Agent v1' },
        { path: '/tmp/unstripped', label: 'Unstripped' },
      ],
      1,
    );
    const parsed = parseCompareUrl(query);
    assert.equal(parsed.baselineIndex, 1);
    assert.deepEqual(parsed.entries, [
      { dir: '/tmp/stripped', label: 'Stripped' },
      { dir: '/tmp/v1', label: 'Agent v1' },
      { dir: '/tmp/unstripped', label: 'Unstripped' },
    ]);
  });

  it('aligns functions by entry_offset and aligns variables by storage', () => {
    const strippedFn: SnapshotFunction = {
      entry_address: '00401129',
      entry_offset: '001129',
      size: 42,
      name: 'FUN_00401129',
      signature: 'uint FUN_00401129(uint param_1)',
      src_file: 'src/001129.c',
      decompile_status: 'complete',
      variables: [{ kind: 'parameter', storage: 'EDI:4', name: 'param_1', data_type: 'uint' }],
    };
    const unstrippedFn: SnapshotFunction = {
      entry_address: '00401129',
      entry_offset: '001129',
      size: 42,
      name: 'mix',
      signature: 'uint32_t mix(uint32_t value)',
      src_file: 'src/001129.c',
      decompile_status: 'complete',
      variables: [{ kind: 'parameter', storage: 'EDI:4', name: 'value', data_type: 'uint32_t' }],
      lines: [{ file: 'main.c', line: 5, start: '00401129', end: '00401130' }],
    };
    const onlyMain: SnapshotFunction = {
      entry_address: '0040119a',
      entry_offset: '00119a',
      size: 20,
      name: 'main',
      signature: 'int main(void)',
      decompile_status: 'complete',
    };

    const s0 = makeSnapshot({
      id: 's0',
      label: 'Stripped',
      functions: [strippedFn],
      sources: { 'src/001129.c': 'uint FUN_00401129(uint param_1) { return param_1; }' },
    });
    const s1 = makeSnapshot({
      id: 's1',
      label: 'Unstripped',
      functions: [unstrippedFn, onlyMain],
      sources: { 'src/001129.c': 'uint32_t mix(uint32_t value) { return value; }' },
    });

    const rows = alignFunctions([s0, s1], 0);
    assert.deepEqual(
      rows.map((r) => r.key),
      ['001129', '00119a'],
    );
    assert.equal(rows[0].status, 'differs');
    assert.equal(rows[0].displayName, 'FUN_00401129 → mix');
    assert.ok(rows[0].diffReasons.includes('name'));
    assert.ok(rows[0].diffReasons.includes('vars'));
    assert.ok(rows[0].diffReasons.includes('code'));
    assert.equal(rows[1].status, 'missing');

    const varRows = alignVariables(rows[0].entries);
    assert.equal(varRows.length, 1);
    assert.equal(varRows[0].status, 'differs');
    assert.equal(varRows[0].entries[0]?.name, 'param_1');
    assert.equal(varRows[0].entries[1]?.name, 'value');
  });

  it('aligns all symbol categories and detects renames vs missing', () => {
    const s0 = makeSnapshot({
      id: 's0',
      label: 'A',
      symbols: {
        globals: [{ name: 'DAT_00404018', address: '00404018', data_type: 'uint', size: 4 }],
        strings: [{ address: '00400001', value: '"ELF"', length: 3 }],
        imports: [{ name: 'puts', address: 'EXTERNAL:00000001', type: 'Function' }],
        exports: [],
        classes: [{ name: 'Foo', full_name: 'ns::Foo', id: 1 }],
        namespaces: [],
      },
    });
    const s1 = makeSnapshot({
      id: 's1',
      label: 'B',
      symbols: {
        globals: [{ name: 'probe_state', address: '00404018', data_type: 'ProbeState', size: 8 }],
        strings: [
          { address: '00400001', value: '"ELF"', length: 3 },
          { address: '00402000', value: '"hello"', length: 6 },
        ],
        imports: [{ name: 'puts', address: 'EXTERNAL:00000001', type: 'Function' }],
        exports: [],
        classes: [{ name: 'Foo', full_name: 'ns::Foo', id: 1 }],
        namespaces: [{ name: 'ns', full_name: 'ns', id: 2 }],
      },
    });

    assert.equal(alignSymbols([s0, s1], 'globals')[0].status, 'differs');
    assert.deepEqual(
      alignSymbols([s0, s1], 'strings').map((r) => r.status),
      ['identical', 'missing'],
    );
    assert.equal(alignSymbols([s0, s1], 'imports')[0].status, 'identical');
    assert.equal(alignSymbols([s0, s1], 'classes')[0].status, 'identical');
    assert.equal(alignSymbols([s0, s1], 'namespaces')[0].status, 'missing');
  });

  it('aggregates callgraph edges and produces cycle-safe layered graph coordinates', () => {
    const s0 = makeSnapshot({
      id: 's0',
      label: 'Stripped',
      functions: [
        { entry_address: '00401129', entry_offset: '001129', size: 10, name: 'FUN_00401129', signature: 'void f()' },
        { entry_address: '00401153', entry_offset: '001153', size: 10, name: 'FUN_00401153', signature: 'void g()' },
      ],
      callgraph: [
        {
          from_addr: '0040115a',
          from_fn: 'FUN_00401153',
          from_fn_addr: '00401153',
          to_addr: '00401129',
          to_name: 'FUN_00401129',
          kind: 'call',
        },
        {
          from_addr: '00401160',
          from_fn: 'FUN_00401153',
          from_fn_addr: '00401153',
          to_addr: '00401129',
          to_name: 'FUN_00401129',
          kind: 'call',
        },
      ],
    });
    const s1 = makeSnapshot({
      id: 's1',
      label: 'Unstripped',
      functions: [
        { entry_address: '00401129', entry_offset: '001129', size: 10, name: 'mix', signature: 'void mix()' },
        {
          entry_address: '00401153',
          entry_offset: '001153',
          size: 10,
          name: 'transform',
          signature: 'void transform()',
        },
        { entry_address: '0040119a', entry_offset: '00119a', size: 10, name: 'main', signature: 'int main()' },
      ],
      callgraph: [
        {
          from_addr: '004011a7',
          from_fn: 'main',
          from_fn_addr: '0040119a',
          to_addr: '00401153',
          to_name: 'transform',
          kind: 'call',
        },
        {
          from_addr: '0040115a',
          from_fn: 'transform',
          from_fn_addr: '00401153',
          to_addr: '00401129',
          to_name: 'mix',
          kind: 'call',
        },
        {
          from_addr: '00401160',
          from_fn: 'transform',
          from_fn_addr: '00401153',
          to_addr: '00401129',
          to_name: 'mix',
          kind: 'call',
        },
        {
          from_addr: '0040112c',
          from_fn: 'mix',
          from_fn_addr: '00401129',
          to_addr: '00401153',
          to_name: 'transform',
          kind: 'call',
        },
      ],
    });

    const fnRows = alignFunctions([s0, s1], 0);
    const edgeRows = alignCallgraphEdges([s0, s1]);
    const layout = buildCallgraphLayout([s0, s1], edgeRows, fnRows, {
      baselineIndex: 0,
      includeData: true,
      onlyDiffers: false,
      focusNodeId: null,
      maxNodes: 20,
    });

    assert.equal(layout.nodes.length, 3);
    const mainNode = layout.nodes.find((n) => n.entryOffset === '00119a');
    const transformNode = layout.nodes.find((n) => n.entryOffset === '001153');
    assert.equal(mainNode?.status, 'added');
    assert.equal(transformNode?.status, 'renamed');
    assert.equal(
      layout.edges.some((e) => e.isBackEdge),
      true,
    );

    const stats = countSnapshotStats(s1);
    assert.equal(stats.functions, 3);
    assert.equal(stats.edges, 4);
  });

  it('computes unified diff with context hunks and handles large-input guard', () => {
    assert.equal(computeUnifiedDiff('a', 'b', 'x\ny', 'x\ny').identical, true);

    const res = computeUnifiedDiff('stripped', 'unstripped', 'int a = 1;\nreturn a;', 'int value = 1;\nreturn value;');
    assert.equal(res.identical, false);
    assert.equal(res.removed, 2);
    assert.equal(res.added, 2);
    assert.ok(res.diff.includes('--- stripped'));
    assert.ok(res.diff.includes('+++ unstripped'));
    assert.ok(res.diff.includes('-int a = 1;'));
    assert.ok(res.diff.includes('+int value = 1;'));

    const hugeA = Array.from({ length: 1600 }, (_, i) => `a${i}`).join('\n');
    const hugeB = Array.from({ length: 1600 }, (_, i) => `b${i}`).join('\n');
    const hugeDiff = computeUnifiedDiff('hugeA', 'hugeB', hugeA, hugeB);
    assert.equal(hugeDiff.identical, false);
    assert.equal(hugeDiff.removed, 1600);
    assert.equal(hugeDiff.added, 1600);
  });
});
