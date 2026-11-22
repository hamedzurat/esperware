import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ApiRequestError,
  buildFunctionTimeline,
  buildNavUrl,
  buildServerQuery,
  classifyEntryPoint,
  collectTouchedFunctions,
  findSegmentForAddress,
  formatDisassembly,
  formatRouteError,
  formatServerTag,
  isExternalSegmentAddress,
  isReadableAddress,
  isSegmentReadable,
  normalizeTarget,
  parseNavState,
  parseSseBlock,
  removeSavedServer,
  sameAddress,
  upsertSavedServer,
  type SavedServer,
  type SegmentInfo,
  type VersionDetail,
  type VersionSummary,
} from './ghidra-api.ts';

function summary(
  version: number,
  operation: string,
  functions: Array<{ addr: string; name: string }> = [],
): VersionSummary {
  return {
    version,
    parent_version: version === 0 ? null : version - 1,
    created_at: `2026-11-22T00:00:0${version}Z`,
    actor: 'agent',
    operation,
    reason: `step ${version}`,
    checkpoint_label: version === 2 ? 'clean-pass' : null,
    ops_count: functions.length,
    functions: functions.map((fn) => ({
      function_address: fn.addr,
      function_name: fn.name,
      decompile_status: 'complete',
    })),
  };
}

describe('normalizeTarget', () => {
  it('maps bare port numbers to loopback HTTP URLs', () => {
    assert.equal(normalizeTarget('8765'), 'http://127.0.0.1:8765');
    assert.equal(normalizeTarget(' 32100 '), 'http://127.0.0.1:32100');
  });

  it('strips MCP and API base suffixes from HTTP URLs', () => {
    assert.equal(normalizeTarget('http://127.0.0.1:9000/mcp/rw/'), 'http://127.0.0.1:9000');
    assert.equal(normalizeTarget('https://ghidra.local:8443/mcp/ro'), 'https://ghidra.local:8443');
    assert.equal(normalizeTarget('http://127.0.0.1:8765/api/v1/'), 'http://127.0.0.1:8765');
  });

  it('rejects out-of-range ports, invalid schemes, and credentialed URLs', () => {
    assert.throws(() => normalizeTarget(''));
    assert.throws(() => normalizeTarget('0'));
    assert.throws(() => normalizeTarget('70000'));
    assert.throws(() => normalizeTarget('ftp://127.0.0.1:8765'));
    assert.throws(() => normalizeTarget('http://user:pass@127.0.0.1:8765'));
    assert.throws(() => normalizeTarget('http://127.0.0.1:8765/?a=1'));
  });
});

describe('collectTouchedFunctions', () => {
  it('deduplicates addresses and keeps latest function name and version list', () => {
    const versions: VersionSummary[] = [
      summary(0, 'initial'),
      summary(1, 'apply_edits', [{ addr: '00401100', name: 'FUN_00401100' }]),
      summary(2, 'apply_edits', [
        { addr: '00401100', name: 'transform_fn' },
        { addr: '00401200', name: 'helper_fn' },
      ]),
    ];

    const touched = collectTouchedFunctions(versions);
    assert.equal(touched.length, 2);
    assert.deepEqual(touched[0], {
      address: '00401200',
      name: 'helper_fn',
      versions: [2],
      latestVersion: 2,
    });
    assert.deepEqual(touched[1], {
      address: '00401100',
      name: 'transform_fn',
      versions: [1, 2],
      latestVersion: 2,
    });
  });
});

describe('buildFunctionTimeline', () => {
  it('carries pseudocode across untouched versions and handles created functions', () => {
    const versions: VersionSummary[] = [
      summary(0, 'initial'),
      summary(1, 'define_type'),
      summary(2, 'apply_edits', [{ addr: '00401100', name: 'transform_fn' }]),
      summary(3, 'apply_edits', [{ addr: '00401100', name: 'transform_fn' }]),
      summary(4, 'apply_edits', [{ addr: '00401300', name: 'created_main' }]),
    ];
    const details = new Map<number, VersionDetail>([
      [
        2,
        {
          ...versions[2],
          ops: [{ op: 'rename_function' }],
          diffs: [
            {
              function_address: '00401100',
              function_name: 'transform_fn',
              before_c: 'void FUN_00401100(void) {}',
              after_c: 'void transform_fn(void) {}',
              diff: '...',
              decompile_status: 'complete',
            },
          ],
        },
      ],
      [
        3,
        {
          ...versions[3],
          ops: [{ op: 'set_comment' }],
          diffs: [
            {
              function_address: '00401100',
              function_name: 'transform_fn',
              before_c: 'void transform_fn(void) {}',
              after_c: '/* ok */\nvoid transform_fn(void) {}',
              diff: '...',
              decompile_status: 'complete',
            },
          ],
        },
      ],
      [
        4,
        {
          ...versions[4],
          ops: [{ op: 'create_function' }],
          diffs: [
            {
              function_address: '00401300',
              function_name: 'created_main',
              before_c: null,
              after_c: 'int created_main(void) { return 0; }',
              diff: '...',
              decompile_status: 'complete',
            },
          ],
        },
      ],
    ]);

    const transformSteps = buildFunctionTimeline('00401100', versions, details);
    assert.equal(transformSteps.length, 5);
    assert.equal(transformSteps[0].code, 'void FUN_00401100(void) {}');
    assert.equal(transformSteps[0].changed, false);
    assert.equal(transformSteps[1].code, 'void FUN_00401100(void) {}');
    assert.equal(transformSteps[2].code, 'void transform_fn(void) {}');
    assert.equal(transformSteps[2].changed, true);
    assert.equal(transformSteps[2].checkpointLabel, 'clean-pass');
    assert.equal(transformSteps[3].code, '/* ok */\nvoid transform_fn(void) {}');
    assert.equal(transformSteps[4].code, '/* ok */\nvoid transform_fn(void) {}');
    assert.equal(transformSteps[4].changed, false);

    const createdSteps = buildFunctionTimeline('00401300', versions, details);
    assert.equal(createdSteps[0].code, '/* Function created at v4 */');
    assert.equal(createdSteps[3].changed, false);
    assert.equal(createdSteps[4].code, 'int created_main(void) { return 0; }');
    assert.equal(createdSteps[4].changed, true);
  });

  it('uses fallback pseudocode when a function has no edits in history', () => {
    const versions = [summary(0, 'initial'), summary(1, 'define_type')];
    const steps = buildFunctionTimeline('00401000', versions, new Map(), 'void untouched(void) {}');
    assert.equal(steps.length, 2);
    assert.equal(steps[0].code, 'void untouched(void) {}');
    assert.equal(steps[1].code, 'void untouched(void) {}');
    assert.equal(steps[0].changed, false);
  });
});

describe('formatDisassembly', () => {
  it('formats aligned instructions with pre and eol comments', () => {
    const text = formatDisassembly([
      {
        address: '00401000',
        bytes: '55',
        mnemonic: 'PUSH',
        operands: 'RBP',
        pre_comment: 'entry',
        eol_comment: 'save frame',
      },
      {
        address: '00401001',
        bytes: 'c3',
        mnemonic: 'RET',
        operands: '',
      },
    ]);
    assert.equal(
      text,
      '; entry\n00401000    55                  PUSH RBP ; save frame\n00401001    c3                  RET',
    );
  });
});

describe('multi-server helpers', () => {
  it('builds compact per-tab query strings for loopback ports and remote URLs', () => {
    assert.equal(buildServerQuery('43299'), '?port=43299');
    assert.equal(buildServerQuery('http://127.0.0.1:43299/mcp/rw'), '?port=43299');
    assert.equal(
      buildServerQuery('https://ghidra.example.com:8443/api/v1'),
      '?api=https%3A%2F%2Fghidra.example.com%3A8443',
    );
  });

  it('formats concise server tags for loopback and non-loopback hosts', () => {
    assert.equal(formatServerTag('http://127.0.0.1:43299'), ':43299');
    assert.equal(formatServerTag('http://localhost:8765'), ':8765');
    assert.equal(formatServerTag('http://[::1]:9000'), ':9000');
    assert.equal(formatServerTag('https://ghidra.example.com:8443'), 'ghidra.example.com:8443');
  });

  it('deduplicates, updates labels, caps, and removes saved servers', () => {
    let list: SavedServer[] = [];
    list = upsertSavedServer(list, { raw: '43299', baseUrl: 'http://127.0.0.1:43299', label: 'bin-a' }, 2);
    list = upsertSavedServer(list, { raw: '43300', baseUrl: 'http://127.0.0.1:43300', label: 'bin-b' }, 2);
    // Re-upserting without label preserves existing label and moves to front.
    list = upsertSavedServer(list, { raw: 'http://127.0.0.1:43299', baseUrl: 'http://127.0.0.1:43299' }, 2);
    assert.equal(list.length, 2);
    assert.equal(list[0].label, 'bin-a');
    assert.equal(list[1].baseUrl, 'http://127.0.0.1:43300');

    // Cap at max = 2 drops oldest.
    list = upsertSavedServer(list, { raw: '43301', baseUrl: 'http://127.0.0.1:43301', label: 'bin-c' }, 2);
    assert.deepEqual(
      list.map((s) => s.baseUrl),
      ['http://127.0.0.1:43301', 'http://127.0.0.1:43299'],
    );

    list = removeSavedServer(list, 'http://127.0.0.1:43301');
    assert.deepEqual(
      list.map((s) => s.baseUrl),
      ['http://127.0.0.1:43299'],
    );
  });
});

describe('deep URL nav state', () => {
  it('round-trips scrubber snapshot and diff modes', () => {
    const snapQuery = buildNavUrl('43299', {
      tab: 'scrubber',
      scrubMode: 'snapshot',
      scrubFn: '0040116d',
      scrubVersion: 3,
    });
    assert.equal(snapQuery, '?port=43299&fn=0040116d&v=3');
    assert.deepEqual(parseNavState(snapQuery), {
      tab: 'scrubber',
      scrubFn: '0040116d',
      scrubVersion: 3,
      diffFrom: undefined,
      diffTo: undefined,
    });

    const diffQuery = buildNavUrl('43299', {
      tab: 'scrubber',
      scrubMode: 'diff',
      scrubFn: '0040116d',
      diffFrom: 1,
      diffTo: 4,
    });
    assert.equal(diffQuery, '?port=43299&fn=0040116d&mode=diff&from=1&to=4');
    assert.deepEqual(parseNavState(diffQuery), {
      tab: 'scrubber',
      scrubMode: 'diff',
      scrubFn: '0040116d',
      scrubVersion: undefined,
      diffFrom: 1,
      diffTo: 4,
    });
  });

  it('round-trips functions, explore, and binary tabs without inactive params', () => {
    const fnUrl = buildNavUrl('43299', {
      tab: 'functions',
      fnTarget: '00401129',
      fnView: 'disassembly',
      fnSort: 'size',
      fnFilter: 'mix',
      memAddr: '0xdeadbeef',
    });
    assert.equal(fnUrl, '?port=43299&tab=functions&fn=00401129&view=disassembly&sort=size&q=mix');
    assert.deepEqual(parseNavState(fnUrl), {
      tab: 'functions',
      fnTarget: '00401129',
      fnView: 'disassembly',
      fnSort: 'size',
      fnFilter: 'mix',
    });

    const memUrl = buildNavUrl('43299', {
      tab: 'explore',
      exploreSub: 'memory',
      memAddr: '00404020',
      memSize: 128,
      memFormat: 'u64',
    });
    assert.equal(memUrl, '?port=43299&tab=explore&sub=memory&addr=00404020&size=128&fmt=u64');
    assert.deepEqual(parseNavState(memUrl), {
      tab: 'explore',
      exploreSub: 'memory',
      memAddr: '00404020',
      memSize: 128,
      memFormat: 'u64',
    });

    const binUrl = buildNavUrl('43299', { tab: 'binary' });
    assert.equal(binUrl, '?port=43299&tab=binary');
    assert.deepEqual(parseNavState(binUrl), { tab: 'binary' });
  });

  it('ignores invalid enum and numeric query parameters safely', () => {
    const parsed = parseNavState('?port=43299&tab=bogus&v=-5&mode=other&from=abc');
    assert.deepEqual(parsed, {
      tab: 'scrubber',
      scrubVersion: undefined,
      diffFrom: undefined,
      diffTo: undefined,
    });
  });
});

describe('address classification, timeline renames, and SSE framing', () => {
  const fixtureSegments: SegmentInfo[] = [
    { name: '.text', start: '00401020', end: '004011af', size: 400, read: true, write: false, execute: true },
    { name: '.rodata', start: '00402000', end: '00402003', size: 4, read: true, write: false, execute: false },
    { name: '.data', start: '00404000', end: '0040400f', size: 16, read: true, write: true, execute: false },
    { name: '.bss', start: '00404010', end: '0040401f', size: 16, read: true, write: true, execute: false },
    { name: 'EXTERNAL', start: '00405000', end: '0040501f', size: 32, read: true, write: true, execute: false },
    {
      name: '.comment',
      start: '.comment::00000000',
      end: '.comment::0000001a',
      size: 27,
      read: false,
      write: false,
      execute: false,
      initialized: true,
      overlay: true,
    },
  ];

  it('distinguishes readable segments, uninitialized .bss/EXTERNAL, and overlay addresses', () => {
    assert.equal(isSegmentReadable(fixtureSegments[0]), true);
    assert.equal(isSegmentReadable(fixtureSegments[3]), false);
    assert.equal(isSegmentReadable(fixtureSegments[4]), false);
    assert.equal(isSegmentReadable(fixtureSegments[5]), true);

    assert.equal(findSegmentForAddress('0x00401129', fixtureSegments)?.name, '.text');
    assert.equal(findSegmentForAddress('.comment::00000000', fixtureSegments)?.name, '.comment');
    assert.equal(findSegmentForAddress('00404020', fixtureSegments), null);

    assert.equal(isReadableAddress('00401129', fixtureSegments), true);
    assert.equal(isReadableAddress('00402000', fixtureSegments), true);
    assert.equal(isReadableAddress('.comment::00000000', fixtureSegments), true);
    assert.equal(isReadableAddress('00404018', fixtureSegments), false);
    assert.equal(isReadableAddress('EXTERNAL:00000001', fixtureSegments), false);
    assert.equal(isReadableAddress('Stack[-0x10]', fixtureSegments), false);
    assert.equal(isReadableAddress('NO ADDRESS', fixtureSegments), false);
    assert.equal(isReadableAddress('Entry Point', fixtureSegments), false);

    assert.equal(isExternalSegmentAddress('00405000', fixtureSegments), true);
    assert.equal(isExternalSegmentAddress('EXTERNAL:00000001', fixtureSegments), true);
    assert.equal(isExternalSegmentAddress('00401129', fixtureSegments), false);
  });

  it('classifies entry points as function, data, or unreadable without throwing on .bss', () => {
    assert.equal(classifyEntryPoint('0040119a', fixtureSegments), 'function');
    assert.equal(classifyEntryPoint('00402000', fixtureSegments), 'data');
    assert.equal(classifyEntryPoint('00404018', fixtureSegments), 'unreadable');
    assert.equal(classifyEntryPoint('00404020', fixtureSegments), 'unreadable');
  });

  it('derives pre-rename function name for v0 and handles type-only, rename, and revert steps', () => {
    const versions: VersionSummary[] = [
      summary(0, 'initial'),
      summary(1, 'define_type'),
      summary(2, 'apply_edits', [{ addr: '00401129', name: 'mix_banana_audit' }]),
      summary(3, 'revert'),
    ];
    const details = new Map<number, VersionDetail>([
      [1, { ...versions[1], ops: [{ op: 'define_type' }], diffs: [] }],
      [
        2,
        {
          ...versions[2],
          ops: [{ op: 'rename_function', target: '00401129', new_name: 'mix_banana_audit' }],
          diffs: [
            {
              function_address: '00401129',
              function_name: 'mix_banana_audit',
              before_c: '\nuint32_t mix(uint32_t value,uint32_t salt)\n{\n  return value + salt;\n}\n',
              after_c: '\nuint32_t mix_banana_audit(uint32_t value,uint32_t salt)\n{\n  return value + salt;\n}\n',
              diff: '...',
              decompile_status: 'complete',
            },
          ],
        },
      ],
    ]);

    const steps = buildFunctionTimeline('0x401129', versions, details);
    assert.equal(steps.length, 4);
    assert.equal(steps[0].name, 'mix');
    assert.equal(steps[1].name, 'mix');
    assert.equal(steps[2].name, 'mix_banana_audit');
    assert.equal(steps[3].changed, false);
    assert.equal(sameAddress('0x401129', '00401129'), true);
  });

  it('parses SSE blocks and formats route 404 hints vs structured domain errors', () => {
    const frame = parseSseBlock('event: version_created\ndata: {"version":3}\n');
    assert.deepEqual(frame, { event: 'version_created', data: { version: 3 } });
    assert.equal(parseSseBlock(': keepalive'), null);

    assert.match(formatRouteError('/api/v1/symbols', new ApiRequestError('Not found', 404)), /rebuild ghidraMCP/i);
    assert.equal(
      formatRouteError('/api/v1/memory', new ApiRequestError('Unmapped memory', 404, 'NOT_FOUND')),
      'Unmapped memory',
    );
  });
});
