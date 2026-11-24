import { neoretroColors, type Color } from '#lib/utils.ts';

export const SNAPSHOT_PALETTE = [
  { color: 'cyan', cssVar: neoretroColors.cyan },
  { color: 'green', cssVar: neoretroColors.green },
  { color: 'yellow', cssVar: neoretroColors.yellow },
  { color: 'magenta', cssVar: neoretroColors.magenta },
  { color: 'blue', cssVar: neoretroColors.blue },
  { color: 'red', cssVar: neoretroColors.red },
] as const satisfies ReadonlyArray<{ color: Color; cssVar: string }>;

export function getSnapshotPaletteEntry(index: number) {
  return SNAPSHOT_PALETTE[((index % SNAPSHOT_PALETTE.length) + SNAPSHOT_PALETTE.length) % SNAPSHOT_PALETTE.length];
}

export type SnapshotCounts = {
  functions: number;
  decompiled: number;
  failed: number;
  types: number;
  globals: number;
  strings: number;
  edges: number;
  source_files: number;
};

export type SnapshotSegment = {
  name: string;
  start?: string;
  end?: string;
  size?: number;
  read?: boolean;
  write?: boolean;
  execute?: boolean;
  initialized?: boolean;
  external?: boolean;
};

export type SnapshotManifest = {
  version?: number;
  binary_name: string;
  binary_sha256?: string;
  ghidra_version?: string;
  format?: string;
  language?: string;
  compiler?: string;
  endian?: string;
  function_count?: number;
  type_count?: number;
  entry_points?: string[];
  segments?: SnapshotSegment[];
  export_layout_version?: number;
  counts?: Partial<SnapshotCounts>;
  files: string[];
};

export type SnapshotVariable = {
  name: string;
  data_type: string;
  data_type_path?: string;
  storage?: string;
  kind?: string;
  comment?: string;
  source?: string;
};

export type SnapshotSourceLine = {
  file?: string;
  line?: number;
  start?: string;
  end?: string;
};

export type SnapshotFunction = {
  entry_address: string;
  entry_offset?: string;
  body_ranges?: Array<{ start: string; end: string }>;
  size: number;
  name: string;
  namespace?: string;
  signature: string;
  calling_convention?: string;
  is_thunk?: boolean;
  comment?: string;
  src_file?: string;
  decompile_status?: string;
  decompile_error?: string;
  variables?: SnapshotVariable[];
  lines?: SnapshotSourceLine[];
};

export type SymbolGlobalItem = {
  name: string;
  full_name?: string;
  address: string;
  type?: string;
  source?: string;
  data_type?: string;
  size?: number;
};

export type SymbolStringItem = {
  address: string;
  value: string;
  length?: number;
  data_type?: string;
};

export type SymbolNamedAddrItem = {
  name: string;
  full_name?: string;
  address: string;
  type?: string;
  source?: string;
};

export type SymbolNamespaceItem = {
  name: string;
  full_name: string;
  id?: number;
};

export type SnapshotSymbols = {
  globals: SymbolGlobalItem[];
  strings: SymbolStringItem[];
  imports: SymbolNamedAddrItem[];
  exports: SymbolNamedAddrItem[];
  classes: SymbolNamespaceItem[];
  namespaces: SymbolNamespaceItem[];
};

export type SymbolCategory = keyof SnapshotSymbols;

export const SYMBOL_CATEGORIES: readonly SymbolCategory[] = [
  'globals',
  'strings',
  'imports',
  'exports',
  'classes',
  'namespaces',
];

export type SnapshotCallEdge = {
  from_addr: string;
  from_fn: string;
  from_fn_addr: string;
  to_addr: string;
  to_name: string;
  kind: 'call' | 'data' | 'string' | string;
};

export type LoadedSnapshot = {
  id: string;
  label: string;
  sourceKind: 'path' | 'folder';
  dirPath: string;
  manifest: SnapshotManifest;
  functions: SnapshotFunction[];
  symbols: SnapshotSymbols;
  callgraph: SnapshotCallEdge[];
  typesHeader: string;
  sources: Record<string, string>;
  sourcesComplete: boolean;
  loadSource: (relPath: string) => Promise<string | null>;
};

export type SnapshotSlotConfig = {
  id: string;
  label: string;
  path: string;
  status: 'idle' | 'loading' | 'ready' | 'error';
  error: string | null;
  snapshot: LoadedSnapshot | null;
};

const EMPTY_SYMBOLS: SnapshotSymbols = {
  globals: [],
  strings: [],
  imports: [],
  exports: [],
  classes: [],
  namespaces: [],
};

export function parseJsonl<T>(text: string): T[] {
  if (!text) return [];
  const items: T[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    items.push(JSON.parse(line) as T);
  }
  return items;
}

export function parseSymbolsJson(text: string): SnapshotSymbols {
  if (!text.trim()) {
    return {
      globals: [],
      strings: [],
      imports: [],
      exports: [],
      classes: [],
      namespaces: [],
    };
  }
  const parsed = JSON.parse(text) as Partial<SnapshotSymbols>;
  return {
    globals: Array.isArray(parsed.globals) ? parsed.globals : [],
    strings: Array.isArray(parsed.strings) ? parsed.strings : [],
    imports: Array.isArray(parsed.imports) ? parsed.imports : [],
    exports: Array.isArray(parsed.exports) ? parsed.exports : [],
    classes: Array.isArray(parsed.classes) ? parsed.classes : [],
    namespaces: Array.isArray(parsed.namespaces) ? parsed.namespaces : [],
  };
}

export function normalizeSnapshotAddr(raw: string | undefined | null): string {
  if (!raw) return '';
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return '';
  const colonIdx = trimmed.indexOf(':');
  if (colonIdx >= 0) {
    const space = trimmed.slice(0, colonIdx);
    const offset = trimmed
      .slice(colonIdx + 1)
      .replace(/^0x/, '')
      .replace(/^0+(?=.)/, '');
    return `${space}:${offset}`;
  }
  if (/^(0x)?[0-9a-f]+$/.test(trimmed)) {
    return trimmed.replace(/^0x/, '').replace(/^0+(?=.)/, '');
  }
  return trimmed;
}

export function functionMatchKey(fn: Pick<SnapshotFunction, 'entry_offset' | 'entry_address'>): string {
  const off = fn.entry_offset?.trim().toLowerCase();
  if (off) return off;
  return normalizeSnapshotAddr(fn.entry_address);
}

function compareHexKeys(a: string, b: string): number {
  const cleanA = a.replace(/^0x/i, '');
  const cleanB = b.replace(/^0x/i, '');
  if (/^[0-9a-f]+$/i.test(cleanA) && /^[0-9a-f]+$/i.test(cleanB)) {
    const diff = BigInt(`0x${cleanA}`) - BigInt(`0x${cleanB}`);
    if (diff < 0n) return -1;
    if (diff > 0n) return 1;
    return 0;
  }
  return a.localeCompare(b);
}

export type SnapshotBundleWire = {
  dir: string;
  manifest: SnapshotManifest;
  functionsText: string;
  symbolsText: string;
  callgraphText: string;
  typesText: string;
  sources: Record<string, string>;
  sourcesComplete: boolean;
};

export async function loadSnapshotFromPath(
  dir: string,
  label: string,
  id: string,
  signal?: AbortSignal,
): Promise<LoadedSnapshot> {
  const trimmedDir = dir.trim();
  if (!trimmedDir) {
    throw new Error('Snapshot directory path is empty.');
  }

  const query = new URLSearchParams({ dir: trimmedDir, mode: 'bundle' });
  const response = await fetch(`/__local-snapshot?${query.toString()}`, { signal });
  if (!response.ok) {
    let message = `Failed to load snapshot (${response.status})`;
    try {
      const errBody = (await response.json()) as { error?: string };
      if (errBody?.error) message = errBody.error;
    } catch {
      // Keep default status error message.
    }
    throw new Error(message);
  }

  const bundle = (await response.json()) as SnapshotBundleWire;
  const cachedSources: Record<string, string> = { ...(bundle.sources ?? {}) };

  return {
    id,
    label: label.trim() || bundle.manifest.binary_name || trimmedDir,
    sourceKind: 'path',
    dirPath: bundle.dir || trimmedDir,
    manifest: bundle.manifest,
    functions: parseJsonl<SnapshotFunction>(bundle.functionsText),
    symbols: bundle.symbolsText ? parseSymbolsJson(bundle.symbolsText) : { ...EMPTY_SYMBOLS },
    callgraph: parseJsonl<SnapshotCallEdge>(bundle.callgraphText),
    typesHeader: bundle.typesText ?? '',
    sources: cachedSources,
    sourcesComplete: Boolean(bundle.sourcesComplete),
    loadSource: async (relPath: string) => {
      if (Object.hasOwn(cachedSources, relPath)) {
        return cachedSources[relPath];
      }
      const fileQuery = new URLSearchParams({ dir: bundle.dir || trimmedDir, file: relPath });
      const fileRes = await fetch(`/__local-snapshot?${fileQuery.toString()}`);
      if (!fileRes.ok) return null;
      const content = await fileRes.text();
      cachedSources[relPath] = content;
      return content;
    },
  };
}

function normalizeUploadedRelPath(file: File): string {
  const raw = file.webkitRelativePath || file.name;
  const slashIdx = raw.indexOf('/');
  return slashIdx >= 0 ? raw.slice(slashIdx + 1) : raw;
}

export async function loadSnapshotFromFiles(
  fileList: FileList | File[],
  label: string,
  id: string,
): Promise<LoadedSnapshot> {
  const files = Array.from(fileList);
  if (files.length === 0) {
    throw new Error('Selected folder contains no files.');
  }

  const fileMap = new Map<string, File>();
  let inferredRoot = '';
  for (const f of files) {
    if (!inferredRoot && f.webkitRelativePath) {
      inferredRoot = f.webkitRelativePath.split('/')[0] ?? '';
    }
    fileMap.set(normalizeUploadedRelPath(f), f);
  }

  const manifestFile = fileMap.get('manifest.json');
  if (!manifestFile) {
    throw new Error('Selected folder is missing manifest.json.');
  }

  const manifest = JSON.parse(await manifestFile.text()) as SnapshotManifest;
  const readText = async (name: string) => {
    const f = fileMap.get(name);
    return f ? f.text() : '';
  };

  const [functionsText, symbolsText, callgraphText, typesText] = await Promise.all([
    readText('functions.jsonl'),
    readText('symbols.json'),
    readText('callgraph.jsonl'),
    readText('types.h'),
  ]);

  const srcNames = [...fileMap.keys()]
    .filter((rel) => rel.startsWith('src/') && rel.endsWith('.c'))
    .sort((a, b) => a.localeCompare(b));
  const sources: Record<string, string> = {};
  const sourcesComplete = srcNames.length <= 150;
  if (sourcesComplete) {
    await Promise.all(
      srcNames.map(async (rel) => {
        const f = fileMap.get(rel);
        if (f) sources[rel] = await f.text();
      }),
    );
  }

  return {
    id,
    label: label.trim() || inferredRoot || manifest.binary_name || 'Folder snapshot',
    sourceKind: 'folder',
    dirPath: inferredRoot || label,
    manifest,
    functions: parseJsonl<SnapshotFunction>(functionsText),
    symbols: symbolsText ? parseSymbolsJson(symbolsText) : { ...EMPTY_SYMBOLS },
    callgraph: parseJsonl<SnapshotCallEdge>(callgraphText),
    typesHeader: typesText,
    sources,
    sourcesComplete,
    loadSource: async (relPath: string) => {
      if (Object.hasOwn(sources, relPath)) return sources[relPath];
      const f = fileMap.get(relPath);
      if (!f) return null;
      const text = await f.text();
      sources[relPath] = text;
      return text;
    },
  };
}

export type ParsedCompareUrl = {
  entries: Array<{ dir: string; label?: string }>;
  baselineIndex: number;
};

export function parseCompareUrl(search: string): ParsedCompareUrl {
  const params = new URLSearchParams(search);
  const dirs = params.getAll('dir').map((d) => d.trim());
  const labels = params.getAll('label').map((l) => l.trim());

  const entries: Array<{ dir: string; label?: string }> = [];
  for (let i = 0; i < dirs.length; i++) {
    if (!dirs[i]) continue;
    entries.push({
      dir: dirs[i],
      label: labels[i] || undefined,
    });
  }

  const rawBase = Number.parseInt(params.get('base') ?? '0', 10);
  const baselineIndex = Number.isFinite(rawBase) && rawBase >= 0 ? rawBase : 0;
  return { entries, baselineIndex };
}

export function buildCompareUrl(slots: ReadonlyArray<{ path: string; label: string }>, baselineIndex: number): string {
  const params = new URLSearchParams();
  let count = 0;
  for (const slot of slots) {
    const dir = slot.path.trim();
    if (!dir) continue;
    params.append('dir', dir);
    params.append('label', slot.label.trim());
    count++;
  }
  if (count === 0) return '';
  if (baselineIndex > 0 && baselineIndex < slots.length) {
    params.set('base', String(baselineIndex));
  }
  return `?${params.toString()}`;
}

export function countSnapshotStats(snap: LoadedSnapshot): SnapshotCounts {
  const counts = snap.manifest.counts ?? {};
  const completeDecompiles = snap.functions.filter((f) => f.decompile_status === 'complete').length;
  const failedDecompiles = snap.functions.filter((f) => f.decompile_status && f.decompile_status !== 'complete').length;
  return {
    functions: counts.functions ?? snap.manifest.function_count ?? snap.functions.length,
    decompiled: counts.decompiled ?? completeDecompiles,
    failed: counts.failed ?? failedDecompiles,
    types: counts.types ?? snap.manifest.type_count ?? 0,
    globals: counts.globals ?? snap.symbols.globals.length,
    strings: counts.strings ?? snap.symbols.strings.length,
    edges: counts.edges ?? snap.callgraph.length,
    source_files: counts.source_files ?? Object.keys(snap.sources).length,
  };
}

export type FunctionCompareStatus = 'identical' | 'differs' | 'missing';
export type FunctionFilter = 'all' | 'shared' | 'missing' | 'identical';
export type FunctionDiffReason = 'missing' | 'name' | 'signature' | 'size' | 'vars' | 'code' | 'dwarf';

export type FunctionCompareRow = {
  key: string;
  entries: Array<SnapshotFunction | null>;
  status: FunctionCompareStatus;
  diffReasons: FunctionDiffReason[];
  displayName: string;
  maxSize: number;
  lineCounts: Array<number | null>;
};

export type VariableCompareRow = {
  key: string;
  kind: string;
  storage: string;
  entries: Array<SnapshotVariable | null>;
  status: 'identical' | 'differs' | 'missing';
};

export function alignVariables(entries: ReadonlyArray<SnapshotFunction | null>): VariableCompareRow[] {
  const maps = entries.map((fn) => {
    const m = new Map<string, SnapshotVariable>();
    for (const v of fn?.variables ?? []) {
      const storagePart = v.storage?.trim() || v.name;
      const baseKey = `${v.kind ?? 'var'}:${storagePart}`;
      const key = m.has(baseKey) ? `${baseKey}:${v.name}` : baseKey;
      m.set(key, v);
    }
    return m;
  });

  const orderedKeys: string[] = [];
  const seen = new Set<string>();
  for (const m of maps) {
    for (const k of m.keys()) {
      if (!seen.has(k)) {
        seen.add(k);
        orderedKeys.push(k);
      }
    }
  }

  return orderedKeys.map((key) => {
    const rowEntries = maps.map((m) => m.get(key) ?? null);
    const present = rowEntries.filter((v): v is SnapshotVariable => v !== null);
    const first = present[0];
    let status: 'identical' | 'differs' | 'missing' = 'identical';
    if (present.length < entries.length) {
      status = 'missing';
    } else if (
      present.some(
        (v) =>
          v.name !== first.name ||
          v.data_type !== first.data_type ||
          (v.storage ?? '') !== (first.storage ?? '') ||
          (v.source ?? '') !== (first.source ?? ''),
      )
    ) {
      status = 'differs';
    }
    return {
      key,
      kind: first?.kind ?? 'local',
      storage: first?.storage ?? '-',
      entries: rowEntries,
      status,
    };
  });
}

function stableDwarfKey(fn: SnapshotFunction): string {
  const lines = fn.lines ?? [];
  if (lines.length === 0) return '';
  return lines.map((l) => `${l.file ?? ''}:${l.line ?? 0}`).join('|');
}

function stableVarsSignature(fn: SnapshotFunction): string {
  const vars = fn.variables ?? [];
  return vars.map((v) => `${v.kind ?? ''}:${v.storage ?? ''}:${v.name}:${v.data_type}`).join('|');
}

function formatDistinctNameChain(names: string[]): string {
  const unique: string[] = [];
  for (const name of names) {
    if (name && !unique.includes(name)) unique.push(name);
  }
  if (unique.length === 0) return 'unknown';
  if (unique.length === 1) return unique[0];
  if (unique.length === 2) return `${unique[0]} → ${unique[1]}`;
  return `${unique[0]} … ${unique[unique.length - 1]} (${unique.length})`;
}

export function alignFunctions(snapshots: LoadedSnapshot[], baselineIndex = 0): FunctionCompareRow[] {
  if (snapshots.length === 0) return [];
  const fnMaps = snapshots.map((snap) => {
    const m = new Map<string, SnapshotFunction>();
    for (const fn of snap.functions) {
      const k = functionMatchKey(fn);
      if (!m.has(k)) m.set(k, fn);
    }
    return m;
  });

  const allKeys = new Set<string>();
  for (const m of fnMaps) {
    for (const k of m.keys()) allKeys.add(k);
  }

  const sortedKeys = [...allKeys].sort(compareHexKeys);
  const safeBaseIdx = baselineIndex >= 0 && baselineIndex < snapshots.length ? baselineIndex : 0;

  return sortedKeys.map((key) => {
    const entries = fnMaps.map((m) => m.get(key) ?? null);
    const present = entries.filter((fn): fn is SnapshotFunction => fn !== null);
    const refFn = entries[safeBaseIdx] ?? present[0];
    const diffReasons: FunctionDiffReason[] = [];

    if (present.length < snapshots.length) {
      diffReasons.push('missing');
    }

    if (present.some((fn) => fn.name !== refFn.name)) diffReasons.push('name');
    if (present.some((fn) => fn.signature !== refFn.signature)) diffReasons.push('signature');
    if (present.some((fn) => fn.size !== refFn.size)) diffReasons.push('size');
    if (present.some((fn) => stableVarsSignature(fn) !== stableVarsSignature(refFn))) diffReasons.push('vars');
    if (present.some((fn) => stableDwarfKey(fn) !== stableDwarfKey(refFn))) diffReasons.push('dwarf');

    const lineCounts = entries.map((fn, idx) => {
      if (!fn?.src_file) return null;
      const code = snapshots[idx]?.sources[fn.src_file];
      if (code === undefined) return null;
      return code.split(/\r?\n/).length;
    });

    const bundledCodes = entries
      .map((fn, idx) => (fn?.src_file ? snapshots[idx]?.sources[fn.src_file] : undefined))
      .filter((c): c is string => c !== undefined);
    if (bundledCodes.length === present.length && bundledCodes.length > 1) {
      const firstCode = bundledCodes[0].trim();
      if (bundledCodes.some((c) => c.trim() !== firstCode)) {
        diffReasons.push('code');
      }
    }

    const status: FunctionCompareStatus =
      present.length < snapshots.length ? 'missing' : diffReasons.length > 0 ? 'differs' : 'identical';

    const namesInOrder = entries.filter((e): e is SnapshotFunction => e !== null).map((e) => e.name);

    return {
      key,
      entries,
      status,
      diffReasons,
      displayName: formatDistinctNameChain(namesInOrder),
      maxSize: Math.max(...present.map((fn) => fn.size ?? 0), 0),
      lineCounts,
    };
  });
}

export type SymbolDisplayItem = {
  primaryName: string;
  secondaryType: string;
  meta: string;
  addressOrId: string;
};

export type SymbolCompareRow = {
  key: string;
  addressOrId: string;
  items: Array<SymbolDisplayItem | null>;
  status: 'identical' | 'differs' | 'missing';
};

function toSymbolDisplay(
  category: SymbolCategory,
  raw: Record<string, unknown>,
): { key: string; display: SymbolDisplayItem } {
  if (category === 'strings') {
    const addr = String(raw.address ?? '');
    const value = String(raw.value ?? '');
    const length = typeof raw.length === 'number' ? `${raw.length} B` : '';
    const dataType = String(raw.data_type ?? 'string');
    return {
      key: normalizeSnapshotAddr(addr) || value,
      display: {
        primaryName: value,
        secondaryType: dataType,
        meta: length || '-',
        addressOrId: addr,
      },
    };
  }
  if (category === 'classes' || category === 'namespaces') {
    const fullName = String(raw.full_name ?? raw.name ?? '');
    const id = raw.id !== undefined ? `id:${String(raw.id)}` : '-';
    return {
      key: fullName,
      display: {
        primaryName: fullName,
        secondaryType: category === 'classes' ? 'Class' : 'Namespace',
        meta: id,
        addressOrId: id,
      },
    };
  }
  const addr = String(raw.address ?? '');
  const name = String(raw.full_name ?? raw.name ?? '');
  const dataType = String(raw.data_type ?? raw.type ?? '-');
  const size = typeof raw.size === 'number' ? `${raw.size} B` : '';
  const source = String(raw.source ?? '');
  return {
    key: normalizeSnapshotAddr(addr) || name,
    display: {
      primaryName: name,
      secondaryType: dataType,
      meta: [size, source].filter(Boolean).join(' · ') || '-',
      addressOrId: addr,
    },
  };
}

export function alignSymbols(snapshots: LoadedSnapshot[], category: SymbolCategory): SymbolCompareRow[] {
  if (snapshots.length === 0) return [];
  const maps = snapshots.map((snap) => {
    const m = new Map<string, SymbolDisplayItem>();
    const list = snap.symbols[category] as unknown as Array<Record<string, unknown>>;
    for (const raw of list) {
      const { key, display } = toSymbolDisplay(category, raw);
      if (!m.has(key)) m.set(key, display);
    }
    return m;
  });

  const keys = new Set<string>();
  for (const m of maps) {
    for (const k of m.keys()) keys.add(k);
  }

  return [...keys].sort(compareHexKeys).map((key) => {
    const items = maps.map((m) => m.get(key) ?? null);
    const present = items.filter((item): item is SymbolDisplayItem => item !== null);
    const first = present[0];
    let status: 'identical' | 'differs' | 'missing' = 'identical';
    if (present.length < snapshots.length) {
      status = 'missing';
    } else if (
      present.some(
        (item) =>
          item.primaryName !== first.primaryName ||
          item.secondaryType !== first.secondaryType ||
          item.meta !== first.meta,
      )
    ) {
      status = 'differs';
    }

    return {
      key,
      addressOrId: first?.addressOrId || key,
      items,
      status,
    };
  });
}

export type CallgraphEdgeSlotInfo = {
  fromName: string;
  toName: string;
  fromFnAddr: string;
  toAddr: string;
  count: number;
  sampleFromAddrs: string[];
};

export type CallgraphEdgeCompareRow = {
  key: string;
  fromKey: string;
  toKey: string;
  kind: string;
  slots: Array<CallgraphEdgeSlotInfo | null>;
  status: 'identical' | 'differs' | 'missing';
};

function buildSnapshotAddrToOffsetLookup(snapshots: LoadedSnapshot[]): Array<Map<string, string>> {
  return snapshots.map((snap) => {
    const m = new Map<string, string>();
    for (const fn of snap.functions) {
      m.set(normalizeSnapshotAddr(fn.entry_address), functionMatchKey(fn));
    }
    return m;
  });
}

export function alignCallgraphEdges(snapshots: LoadedSnapshot[]): CallgraphEdgeCompareRow[] {
  if (snapshots.length === 0) return [];
  const addrToKeyMaps = buildSnapshotAddrToOffsetLookup(snapshots);
  const slotMaps = snapshots.map((snap, idx) => {
    const addrToKey = addrToKeyMaps[idx];
    const m = new Map<string, CallgraphEdgeSlotInfo>();
    for (const edge of snap.callgraph) {
      const normFrom = normalizeSnapshotAddr(edge.from_fn_addr);
      const normTo = normalizeSnapshotAddr(edge.to_addr);
      const fromKey = addrToKey.get(normFrom) ?? normFrom;
      const toKey = addrToKey.get(normTo) ?? normTo;
      const key = `${fromKey}->${toKey}:${edge.kind}`;
      const existing = m.get(key);
      if (existing) {
        existing.count++;
        if (existing.sampleFromAddrs.length < 3) existing.sampleFromAddrs.push(edge.from_addr);
      } else {
        m.set(key, {
          fromName: edge.from_fn,
          toName: edge.to_name,
          fromFnAddr: edge.from_fn_addr,
          toAddr: edge.to_addr,
          count: 1,
          sampleFromAddrs: [edge.from_addr],
        });
      }
    }
    return m;
  });

  const allKeys = new Set<string>();
  for (const m of slotMaps) {
    for (const k of m.keys()) allKeys.add(k);
  }

  return [...allKeys]
    .sort((a, b) => a.localeCompare(b))
    .map((key) => {
      const arrowIdx = key.indexOf('->');
      const lastColon = key.lastIndexOf(':');
      const fromKey = key.slice(0, arrowIdx);
      const toKey = key.slice(arrowIdx + 2, lastColon);
      const kind = key.slice(lastColon + 1);

      const slots = slotMaps.map((m) => m.get(key) ?? null);
      const present = slots.filter((s): s is CallgraphEdgeSlotInfo => s !== null);
      const first = present[0];
      let status: 'identical' | 'differs' | 'missing' = 'identical';
      if (present.length < snapshots.length) {
        status = 'missing';
      } else if (
        present.some((s) => s.fromName !== first.fromName || s.toName !== first.toName || s.count !== first.count)
      ) {
        status = 'differs';
      }

      return {
        key,
        fromKey,
        toKey,
        kind,
        slots,
        status,
      };
    });
}

export type UnifiedDiffResult = {
  diff: string;
  added: number;
  removed: number;
  identical: boolean;
};

type DiffOp = {
  type: ' ' | '-' | '+';
  line: string;
  leftLine: number;
  rightLine: number;
};

export function computeUnifiedDiff(
  leftLabel: string,
  rightLabel: string,
  leftText: string,
  rightText: string,
  contextLines = 3,
): UnifiedDiffResult {
  if (leftText === rightText) {
    return { diff: '', added: 0, removed: 0, identical: true };
  }

  const leftLines = leftText === '' ? [] : leftText.replace(/\r\n/g, '\n').split('\n');
  const rightLines = rightText === '' ? [] : rightText.replace(/\r\n/g, '\n').split('\n');

  let prefix = 0;
  const minLen = Math.min(leftLines.length, rightLines.length);
  while (prefix < minLen && leftLines[prefix] === rightLines[prefix]) {
    prefix++;
  }

  let suffix = 0;
  while (
    suffix < minLen - prefix &&
    leftLines[leftLines.length - 1 - suffix] === rightLines[rightLines.length - 1 - suffix]
  ) {
    suffix++;
  }

  const midLeft = leftLines.slice(prefix, leftLines.length - suffix);
  const midRight = rightLines.slice(prefix, rightLines.length - suffix);

  const ops: DiffOp[] = [];
  for (let i = 0; i < prefix; i++) {
    ops.push({ type: ' ', line: leftLines[i], leftLine: i + 1, rightLine: i + 1 });
  }

  const midProduct = midLeft.length * midRight.length;
  if (midProduct > 2_000_000) {
    for (let i = 0; i < midLeft.length; i++) {
      ops.push({ type: '-', line: midLeft[i], leftLine: prefix + i + 1, rightLine: prefix + 1 });
    }
    for (let j = 0; j < midRight.length; j++) {
      ops.push({
        type: '+',
        line: midRight[j],
        leftLine: prefix + midLeft.length + 1,
        rightLine: prefix + j + 1,
      });
    }
  } else {
    const m = midLeft.length;
    const n = midRight.length;
    const cols = n + 1;
    const dp = new Int32Array((m + 1) * cols);

    for (let i = m - 1; i >= 0; i--) {
      for (let j = n - 1; j >= 0; j--) {
        if (midLeft[i] === midRight[j]) {
          dp[i * cols + j] = dp[(i + 1) * cols + (j + 1)] + 1;
        } else {
          const down = dp[(i + 1) * cols + j];
          const right = dp[i * cols + (j + 1)];
          dp[i * cols + j] = down >= right ? down : right;
        }
      }
    }

    let i = 0;
    let j = 0;
    while (i < m && j < n) {
      if (midLeft[i] === midRight[j]) {
        ops.push({ type: ' ', line: midLeft[i], leftLine: prefix + i + 1, rightLine: prefix + j + 1 });
        i++;
        j++;
      } else if (dp[(i + 1) * cols + j] >= dp[i * cols + (j + 1)]) {
        ops.push({ type: '-', line: midLeft[i], leftLine: prefix + i + 1, rightLine: prefix + j + 1 });
        i++;
      } else {
        ops.push({ type: '+', line: midRight[j], leftLine: prefix + i + 1, rightLine: prefix + j + 1 });
        j++;
      }
    }
    while (i < m) {
      ops.push({ type: '-', line: midLeft[i], leftLine: prefix + i + 1, rightLine: prefix + j + 1 });
      i++;
    }
    while (j < n) {
      ops.push({ type: '+', line: midRight[j], leftLine: prefix + i + 1, rightLine: prefix + j + 1 });
      j++;
    }
  }

  for (let k = 0; k < suffix; k++) {
    const li = leftLines.length - suffix + k;
    const ri = rightLines.length - suffix + k;
    ops.push({ type: ' ', line: leftLines[li], leftLine: li + 1, rightLine: ri + 1 });
  }

  let added = 0;
  let removed = 0;
  const changeIndices: number[] = [];
  for (let idx = 0; idx < ops.length; idx++) {
    if (ops[idx].type === '+') added++;
    if (ops[idx].type === '-') removed++;
    if (ops[idx].type !== ' ') changeIndices.push(idx);
  }

  if (changeIndices.length === 0) {
    return { diff: '', added: 0, removed: 0, identical: true };
  }

  const hunks: Array<[number, number]> = [];
  let hunkStart = Math.max(0, changeIndices[0] - contextLines);
  let hunkEnd = Math.min(ops.length - 1, changeIndices[0] + contextLines);

  for (let c = 1; c < changeIndices.length; c++) {
    const nextStart = Math.max(0, changeIndices[c] - contextLines);
    const nextEnd = Math.min(ops.length - 1, changeIndices[c] + contextLines);
    if (nextStart <= hunkEnd + 1) {
      hunkEnd = nextEnd;
    } else {
      hunks.push([hunkStart, hunkEnd]);
      hunkStart = nextStart;
      hunkEnd = nextEnd;
    }
  }
  hunks.push([hunkStart, hunkEnd]);

  const out: string[] = [`--- ${leftLabel}`, `+++ ${rightLabel}`];
  for (const [start, end] of hunks) {
    let oldCount = 0;
    let newCount = 0;
    let firstOld = -1;
    let firstNew = -1;

    for (let k = start; k <= end; k++) {
      const op = ops[k];
      if (op.type !== '+') {
        if (firstOld < 0) firstOld = op.leftLine;
        oldCount++;
      }
      if (op.type !== '-') {
        if (firstNew < 0) firstNew = op.rightLine;
        newCount++;
      }
    }
    const headerOldStart = firstOld < 0 ? Math.max(0, ops[start].leftLine - 1) : firstOld;
    const headerNewStart = firstNew < 0 ? Math.max(0, ops[start].rightLine - 1) : firstNew;
    out.push(`@@ -${headerOldStart},${oldCount} +${headerNewStart},${newCount} @@`);
    for (let k = start; k <= end; k++) {
      out.push(`${ops[k].type}${ops[k].line}`);
    }
  }

  return {
    diff: out.join('\n'),
    added,
    removed,
    identical: false,
  };
}

export type CallgraphNodeStatus = 'same' | 'renamed' | 'added' | 'removed';
export type CallgraphEdgeStatus = 'same' | 'added' | 'removed';

export type CallgraphGraphNode = {
  id: string;
  label: string;
  sublabel: string;
  entryOffset: string | null;
  names: Array<string | null>;
  status: CallgraphNodeStatus;
  kind: 'function' | 'external' | 'data' | 'string';
  layer: number;
  x: number;
  y: number;
  width: number;
  height: number;
  degree: number;
};

export type CallgraphGraphEdge = {
  key: string;
  fromId: string;
  toId: string;
  kind: string;
  status: CallgraphEdgeStatus;
  totalCount: number;
  counts: Array<number | null>;
  fromNames: Array<string | null>;
  toNames: Array<string | null>;
  isBackEdge: boolean;
  path: string;
  labelX: number;
  labelY: number;
};

export type CallgraphLayoutResult = {
  nodes: CallgraphGraphNode[];
  edges: CallgraphGraphEdge[];
  width: number;
  height: number;
  totalNodes: number;
  truncated: boolean;
};

export type CallgraphLayoutOptions = {
  baselineIndex: number;
  includeData: boolean;
  onlyDiffers?: boolean;
  onlyMissing?: boolean;
  focusNodeId: string | null;
  maxNodes?: number;
};

export function buildCallgraphLayout(
  snapshots: LoadedSnapshot[],
  edgeRows: CallgraphEdgeCompareRow[],
  fnRows: FunctionCompareRow[],
  options: CallgraphLayoutOptions,
): CallgraphLayoutResult {
  const maxNodes = options.maxNodes ?? 48;
  const safeBase = options.baselineIndex >= 0 && options.baselineIndex < snapshots.length ? options.baselineIndex : 0;

  const fnRowMap = new Map<string, FunctionCompareRow>();
  for (const r of fnRows) fnRowMap.set(r.key, r);

  const visibleEdges = edgeRows.filter((row) => {
    if (!options.includeData && row.kind !== 'call') return false;
    if (options.onlyMissing && row.status !== 'missing') return false;
    if (options.onlyDiffers && row.status === 'identical') return false;
    return true;
  });

  if (visibleEdges.length === 0) {
    return { nodes: [], edges: [], width: 600, height: 180, totalNodes: 0, truncated: false };
  }

  let scopedEdges = visibleEdges;
  if (options.focusNodeId) {
    const focused = visibleEdges.filter((e) => e.fromKey === options.focusNodeId || e.toKey === options.focusNodeId);
    if (focused.length > 0) scopedEdges = focused;
  }

  type NodeDraft = {
    id: string;
    names: Array<string | null>;
    present: boolean[];
    entryOffset: string | null;
    kind: 'function' | 'external' | 'data' | 'string';
    degree: number;
  };

  const nodeDrafts = new Map<string, NodeDraft>();
  const ensureNode = (
    id: string,
    snapCount: number,
    hintKind: 'function' | 'external' | 'data' | 'string',
  ): NodeDraft => {
    let draft = nodeDrafts.get(id);
    if (!draft) {
      const fnRow = fnRowMap.get(id);
      draft = {
        id,
        names: Array.from({ length: snapCount }, (_, idx) => fnRow?.entries[idx]?.name ?? null),
        present: Array.from({ length: snapCount }, (_, idx) => Boolean(fnRow?.entries[idx])),
        entryOffset: fnRow ? id : null,
        kind: fnRow ? 'function' : hintKind,
        degree: 0,
      };
      nodeDrafts.set(id, draft);
    }
    return draft;
  };

  for (const edge of scopedEdges) {
    const toHintKind =
      edge.kind === 'data'
        ? 'data'
        : edge.kind === 'string'
          ? 'string'
          : edge.toKey.startsWith('external:')
            ? 'external'
            : 'function';
    const fromNode = ensureNode(edge.fromKey, snapshots.length, 'function');
    const toNode = ensureNode(edge.toKey, snapshots.length, toHintKind);
    fromNode.degree++;
    toNode.degree++;

    edge.slots.forEach((slot, idx) => {
      if (!slot) return;
      if (!fromNode.names[idx]) fromNode.names[idx] = slot.fromName;
      fromNode.present[idx] = true;
      if (!toNode.names[idx]) toNode.names[idx] = slot.toName;
      toNode.present[idx] = true;
    });
  }

  const classifyNodeStatus = (draft: NodeDraft): CallgraphNodeStatus => {
    const inBase = draft.present[safeBase] ?? false;
    const inOthers = draft.present.some((p, idx) => idx !== safeBase && p);
    if (!inBase && inOthers) return 'added';
    if (inBase && draft.present.some((p, idx) => idx !== safeBase && !p)) return 'removed';
    const distinctNames = new Set(draft.names.filter((n): n is string => Boolean(n)));
    return distinctNames.size > 1 ? 'renamed' : 'same';
  };

  const allDrafts = [...nodeDrafts.values()];
  const totalNodes = allDrafts.length;
  let keptNodeIds = new Set(allDrafts.map((d) => d.id));
  let truncated = false;

  if (allDrafts.length > maxNodes) {
    truncated = true;
    const statusWeight = (s: CallgraphNodeStatus) => (s === 'added' || s === 'removed' ? 3 : s === 'renamed' ? 2 : 0);
    allDrafts.sort((a, b) => {
      if (a.id === options.focusNodeId) return -1;
      if (b.id === options.focusNodeId) return 1;
      const diff = statusWeight(classifyNodeStatus(b)) - statusWeight(classifyNodeStatus(a));
      if (diff !== 0) return diff;
      if (b.degree !== a.degree) return b.degree - a.degree;
      return a.id.localeCompare(b.id);
    });
    keptNodeIds = new Set(allDrafts.slice(0, maxNodes).map((d) => d.id));
  }

  const keptEdges = scopedEdges.filter((e) => keptNodeIds.has(e.fromKey) && keptNodeIds.has(e.toKey));
  const activeDrafts = allDrafts.filter((d) => keptNodeIds.has(d.id));

  // Cycle breaking via DFS active stack + topological longest-path layering
  const outAdj = new Map<string, string[]>();
  for (const d of activeDrafts) outAdj.set(d.id, []);
  for (const e of keptEdges) {
    if (e.fromKey !== e.toKey) outAdj.get(e.fromKey)?.push(e.toKey);
  }

  const visitState = new Map<string, 0 | 1 | 2>();
  const backEdgePairs = new Set<string>();
  function dfs(u: string) {
    visitState.set(u, 1);
    for (const v of outAdj.get(u) ?? []) {
      const state = visitState.get(v) ?? 0;
      if (state === 1) {
        backEdgePairs.add(`${u}->${v}`);
      } else if (state === 0) {
        dfs(v);
      }
    }
    visitState.set(u, 2);
  }
  for (const d of activeDrafts) {
    if ((visitState.get(d.id) ?? 0) === 0) dfs(d.id);
  }

  const dagOut = new Map<string, string[]>();
  const inDeg = new Map<string, number>();
  for (const d of activeDrafts) {
    dagOut.set(d.id, []);
    inDeg.set(d.id, 0);
  }
  const seenPairs = new Set<string>();
  for (const e of keptEdges) {
    const pair = `${e.fromKey}->${e.toKey}`;
    if (e.fromKey === e.toKey || backEdgePairs.has(pair) || seenPairs.has(pair)) continue;
    seenPairs.add(pair);
    dagOut.get(e.fromKey)?.push(e.toKey);
    inDeg.set(e.toKey, (inDeg.get(e.toKey) ?? 0) + 1);
  }

  const layerMap = new Map<string, number>();
  const queue: string[] = [];
  for (const d of activeDrafts) {
    if ((inDeg.get(d.id) ?? 0) === 0) {
      queue.push(d.id);
      layerMap.set(d.id, 0);
    }
  }

  while (queue.length > 0) {
    const u = queue.shift()!;
    const uLayer = layerMap.get(u) ?? 0;
    for (const v of dagOut.get(u) ?? []) {
      const nextLayer = Math.max(layerMap.get(v) ?? 0, uLayer + 1);
      layerMap.set(v, nextLayer);
      const nextDeg = (inDeg.get(v) ?? 1) - 1;
      inDeg.set(v, nextDeg);
      if (nextDeg <= 0) queue.push(v);
    }
  }

  const layers = new Map<number, NodeDraft[]>();
  for (const d of activeDrafts) {
    const l = layerMap.get(d.id) ?? 0;
    const list = layers.get(l) ?? [];
    list.push(d);
    layers.set(l, list);
  }

  const NODE_W = 216;
  const NODE_H = 56;
  const COL_GAP = 84;
  const ROW_GAP = 22;
  const PAD_X = 28;
  const PAD_Y = 28;

  const sortedLayerNums = [...layers.keys()].sort((a, b) => a - b);
  let maxLayerRows = 1;
  for (const l of sortedLayerNums) {
    const row = layers.get(l) ?? [];
    row.sort((a, b) => b.degree - a.degree || a.id.localeCompare(b.id));
    maxLayerRows = Math.max(maxLayerRows, row.length);
  }

  const maxLayerHeight = maxLayerRows * NODE_H + Math.max(0, maxLayerRows - 1) * ROW_GAP;
  const builtNodes: CallgraphGraphNode[] = [];
  const nodePosMap = new Map<string, CallgraphGraphNode>();

  for (const l of sortedLayerNums) {
    const group = layers.get(l) ?? [];
    const groupHeight = group.length * NODE_H + Math.max(0, group.length - 1) * ROW_GAP;
    const startY = PAD_Y + Math.max(0, (maxLayerHeight - groupHeight) / 2);

    group.forEach((draft, rowIdx) => {
      const status = classifyNodeStatus(draft);
      const nonNullNames = draft.names.filter((n): n is string => Boolean(n));
      const label = formatDistinctNameChain(nonNullNames);
      const sublabel = draft.entryOffset
        ? `@${draft.entryOffset}`
        : draft.kind === 'data'
          ? 'data'
          : draft.kind === 'string'
            ? 'string'
            : draft.id;

      const node: CallgraphGraphNode = {
        id: draft.id,
        label,
        sublabel,
        entryOffset: draft.entryOffset,
        names: draft.names,
        status,
        kind: draft.kind,
        layer: l,
        x: PAD_X + l * (NODE_W + COL_GAP),
        y: startY + rowIdx * (NODE_H + ROW_GAP),
        width: NODE_W,
        height: NODE_H,
        degree: draft.degree,
      };
      builtNodes.push(node);
      nodePosMap.set(node.id, node);
    });
  }

  const builtEdges: CallgraphGraphEdge[] = [];
  let maxExtraBottom = 0;

  for (const row of keptEdges) {
    const src = nodePosMap.get(row.fromKey);
    const dst = nodePosMap.get(row.toKey);
    if (!src || !dst) continue;

    const counts = row.slots.map((s) => (s ? s.count : null));
    const inBase = counts[safeBase] !== null;
    const inOthers = counts.some((c, idx) => idx !== safeBase && c !== null);
    let edgeStatus: CallgraphEdgeStatus = 'same';
    if (!inBase && inOthers) edgeStatus = 'added';
    else if (inBase && counts.some((c, idx) => idx !== safeBase && c === null)) edgeStatus = 'removed';

    const isSelf = src.id === dst.id;
    const isBack = isSelf || backEdgePairs.has(`${src.id}->${dst.id}`) || src.x >= dst.x;

    let pathStr: string;
    let labelX: number;
    let labelY: number;

    if (isSelf) {
      const sx = src.x + src.width / 2;
      const sy = src.y;
      pathStr = `M ${sx - 18} ${sy} C ${sx - 28} ${sy - 40}, ${sx + 28} ${sy - 40}, ${sx + 18} ${sy}`;
      labelX = sx;
      labelY = sy - 34;
    } else if (isBack) {
      const sx = src.x + src.width / 2;
      const sy = src.y + src.height;
      const dx = dst.x + dst.width / 2;
      const dy = dst.y + dst.height;
      const drop = Math.max(sy, dy) + 38;
      maxExtraBottom = Math.max(maxExtraBottom, drop - (PAD_Y + maxLayerHeight));
      pathStr = `M ${sx} ${sy} C ${sx} ${drop}, ${dx} ${drop}, ${dx} ${dy}`;
      labelX = (sx + dx) / 2;
      labelY = drop - 10;
    } else {
      const sx = src.x + src.width;
      const sy = src.y + src.height / 2 + (row.kind === 'data' || row.kind === 'string' ? 8 : 0);
      const dx = dst.x;
      const dy = dst.y + dst.height / 2 + (row.kind === 'data' || row.kind === 'string' ? 8 : 0);
      const midX = (sx + dx) / 2;
      pathStr = `M ${sx} ${sy} C ${midX} ${sy}, ${midX} ${dy}, ${dx} ${dy}`;
      labelX = midX;
      labelY = (sy + dy) / 2;
    }

    const validCounts = counts.filter((c): c is number => c !== null);
    builtEdges.push({
      key: row.key,
      fromId: src.id,
      toId: dst.id,
      kind: row.kind,
      status: edgeStatus,
      totalCount: Math.max(...validCounts, 1),
      counts,
      fromNames: row.slots.map((s) => s?.fromName ?? null),
      toNames: row.slots.map((s) => s?.toName ?? null),
      isBackEdge: isBack,
      path: pathStr,
      labelX,
      labelY,
    });
  }

  const colCount = Math.max(sortedLayerNums.length, 1);
  const width = PAD_X * 2 + colCount * NODE_W + Math.max(0, colCount - 1) * COL_GAP;
  const height = PAD_Y * 2 + maxLayerHeight + Math.max(16, maxExtraBottom);

  return {
    nodes: builtNodes,
    edges: builtEdges,
    width,
    height,
    totalNodes,
    truncated,
  };
}
