import type { CodeBlockShikiConfig } from '#lib/components/ui/code-block/index.js';

export const TARGET_STORAGE_KEY = 'esperware.target';
export const SERVERS_STORAGE_KEY = 'esperware.servers';

export type SavedServer = {
  raw: string;
  baseUrl: string;
  label?: string;
};

export type WorkspaceTab = 'scrubber' | 'functions' | 'explore' | 'binary';
export type FunctionSubView = 'pseudocode' | 'disassembly' | 'xrefs';
export type ExploreSubTab = 'symbols' | 'types' | 'search' | 'memory';

export type UrlNavState = {
  tab: WorkspaceTab;
  scrubMode?: 'snapshot' | 'diff';
  scrubFn?: string;
  scrubVersion?: number;
  diffFrom?: number;
  diffTo?: number;
  fnTarget?: string;
  fnView?: FunctionSubView;
  fnSort?: 'address' | 'name' | 'size';
  fnFilter?: string;
  exploreSub?: ExploreSubTab;
  symbolKind?: SymbolKind;
  symbolFilter?: string;
  typeQuery?: string;
  typeExact?: boolean;
  searchScope?: SearchScope;
  searchQuery?: string;
  memAddr?: string;
  memSize?: number;
  memFormat?: MemoryFormat;
};

export const SHIKI_CONFIG: CodeBlockShikiConfig = {
  themes: ['github-dark', 'github-light'],
  langs: ['c', 'diff', 'json', 'asm'],
  darkTheme: 'github-dark',
  lightTheme: 'github-light',
};

export type HealthResponse = {
  ok: boolean;
  status: 'analyzing' | 'ready' | 'error' | 'recovery_required' | string;
  error?: string;
};

export type SegmentInfo = {
  name: string;
  start: string;
  end: string;
  size: number;
  read: boolean;
  write: boolean;
  execute: boolean;
  initialized?: boolean;
  overlay?: boolean;
  external?: boolean;
};

export type StatusResponse = {
  ok: boolean;
  state: string;
  version: number;
  binary_name: string;
  binary_sha256: string;
  ghidra_version: string;
  format: string;
  language: string;
  compiler: string;
  endian: string;
  function_count: number;
  type_count: number;
  entry_points: string[];
  segments: SegmentInfo[];
  mcp_rw_url: string;
  mcp_ro_url: string;
  uptime_ms: number;
};

export type VersionFunctionRef = {
  function_address: string;
  function_name: string;
  decompile_status: string;
};

export type VersionSummary = {
  version: number;
  parent_version: number | null;
  created_at: string;
  actor: string;
  operation: string;
  reason: string | null;
  checkpoint_label: string | null;
  ops_count: number;
  functions: VersionFunctionRef[];
};

export type VersionsResponse = {
  ok: boolean;
  current_version: number;
  versions: VersionSummary[];
};

export type FunctionDiff = {
  function_address: string;
  function_name: string;
  before_c: string | null;
  after_c: string | null;
  diff: string;
  decompile_status: string;
};

export type VersionDetail = {
  version: number;
  parent_version: number | null;
  created_at: string;
  actor: string;
  operation: string;
  reason: string | null;
  checkpoint_label: string | null;
  ops: Array<Record<string, unknown>>;
  diffs: FunctionDiff[];
};

export type VersionDetailResponse = {
  ok: boolean;
  version: VersionDetail;
};

export type RangeDiffResponse = {
  ok: boolean;
  from: number;
  to: number;
  diffs: FunctionDiff[];
};

export type FunctionRow = {
  address: string;
  name: string;
  size: number;
  external: boolean;
  signature: string;
};

export type FunctionsResponse = {
  ok: boolean;
  version: number;
  total: number;
  functions: FunctionRow[];
  next_cursor?: string;
};

export type VariableInfo = {
  name: string;
  data_type: string;
  data_type_path: string;
  storage: string;
  kind: 'parameter' | 'local' | string;
  comment: string;
  source: 'db' | 'high' | string;
};

export type GlobalInfo = {
  name: string;
  address: string;
  data_type: string;
  data_type_path: string;
  size: number;
  comment: string;
};

export type DisasmInstruction = {
  address: string;
  bytes: string;
  mnemonic: string;
  operands: string;
  pre_comment?: string;
  eol_comment?: string;
};

export type DisassemblyResult = {
  ok: boolean;
  version: number;
  scope: string;
  instructions: DisasmInstruction[];
  next_cursor?: string;
};

export type FunctionDetailResponse = {
  ok: boolean;
  version: number;
  function: {
    address: string;
    name: string;
    signature: string;
    comment: string;
  };
  decompile_status: string;
  decompile_error?: string;
  pseudocode: string;
  truncated: boolean;
  next_offset?: number;
  variables?: VariableInfo[];
  globals?: GlobalInfo[];
  disassembly?: DisassemblyResult;
};

export type SymbolKind = 'imports' | 'exports' | 'globals' | 'strings' | 'classes' | 'namespaces';

export type SymbolRow = {
  name?: string;
  full_name?: string;
  address?: string;
  type?: string;
  source?: string;
  data_type?: string;
  size?: number;
  value?: string;
  length?: number;
  id?: number;
};

export type SymbolsResponse = {
  ok: boolean;
  version: number;
  kind: SymbolKind;
  total: number;
  items: SymbolRow[];
  next_cursor?: string;
};

export type XrefKind = 'all' | 'callers' | 'callees' | 'to' | 'from';

export type XrefRow = {
  kind: string;
  address?: string;
  name?: string;
  from_address?: string;
  to_address?: string;
  ref_type?: string;
  from_function?: string;
  from_function_address?: string;
  to_symbol?: string;
  to_is_function?: boolean;
  to_function_address?: string;
};

export type XrefsResponse = {
  ok: boolean;
  version: number;
  target: string;
  total: number;
  xrefs: XrefRow[];
  next_cursor?: string;
};

export type MemoryFormat = 'hex' | 'utf8' | 'u32' | 'u64';

export type MemoryResponse = {
  ok: boolean;
  version: number;
  address: string;
  size: number;
  format: MemoryFormat;
  hex: string;
  utf8?: string;
  values?: string[];
};

export type SearchScope = 'pseudocode' | 'disassembly' | 'bytes';

export type SearchMatch = {
  address: string;
  function?: string;
  instruction?: string;
  name?: string;
  excerpt?: string;
};

export type SearchResponse = {
  ok: boolean;
  version: number;
  scope: SearchScope;
  scanned?: number;
  scanned_functions?: number;
  matches: SearchMatch[];
  next_cursor?: string;
};

export type TypeField = {
  ordinal: number;
  offset: number;
  name: string;
  type: string;
  path: string;
  size: number;
  comment?: string;
};

export type TypeEnumValue = {
  name: string;
  value: number;
};

export type TypeInfo = {
  name: string;
  path: string;
  kind: string;
  size: number;
  description: string;
  fields?: TypeField[];
  fields_truncated?: boolean;
  values?: TypeEnumValue[];
  values_truncated?: boolean;
  base_type?: string;
  base_path?: string;
  points_to?: string;
  points_to_path?: string;
  element_type?: string;
  element_count?: number;
};

export type TypesResponse = {
  ok: boolean;
  version: number;
  total: number;
  types: TypeInfo[];
  next_cursor?: string;
};

export type ExportResponse = {
  ok: boolean;
  version: number;
  dir: string;
  counts: Record<string, number>;
  files: string[];
};

export type SseFrame = {
  event: string;
  data: Record<string, unknown>;
};

export type SseConnectionState = 'connecting' | 'connected' | 'reconnecting' | 'auth_error' | 'disconnected';

export type TouchedFunction = {
  address: string;
  name: string;
  versions: number[];
  latestVersion: number;
};

export type FunctionTimelineStep = {
  version: number;
  operation: string;
  actor: string;
  reason: string | null;
  checkpointLabel: string | null;
  changed: boolean;
  name: string;
  code: string;
  diff: string;
  decompileStatus: string;
};

export class ApiRequestError extends Error {
  status?: number;
  code?: string;

  constructor(message: string, status?: number, code?: string) {
    super(message);
    this.name = 'ApiRequestError';
    this.status = status;
    this.code = code;
  }
}

/** Normalizes a bare port number or full server/MCP/API URL into the server origin base URL. */
export function normalizeTarget(raw: string): string {
  const s = (raw || '').trim();
  if (!s) throw new Error('Enter a server port or HTTP URL.');
  if (/^\d+$/.test(s)) {
    const port = Number.parseInt(s, 10);
    if (port < 1 || port > 65535) {
      throw new Error('Port must be between 1 and 65535.');
    }
    return `http://127.0.0.1:${port}`;
  }
  let url: URL;
  try {
    url = new URL(s);
  } catch {
    throw new Error('Enter a valid port number or http(s) server URL.');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error('Enter a plain http(s) URL without credentials, query, or hash.');
  }
  url.pathname = url.pathname.replace(/(?:\/mcp\/(?:ro|rw)|\/api\/v1)\/?$/, '');
  return url.href.replace(/\/+$/, '');
}

function buildQuery(params: Record<string, string | number | boolean | undefined | null>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      query.set(key, String(value));
    }
  }
  const str = query.toString();
  return str ? `?${str}` : '';
}

function networkFailureMessage(baseUrl: string): string {
  const origin = typeof window !== 'undefined' ? window.location.origin : '';
  if (origin && origin !== 'null') {
    return `Cannot reach ${baseUrl}. Confirm ghidraMCP is running and start it with GHIDRA_MCP_CORS_ORIGIN=${origin}.`;
  }
  return `Cannot reach ${baseUrl}. Confirm ghidraMCP is running and allows this browser origin.`;
}

async function parseErrorResponse(response: Response): Promise<ApiRequestError> {
  if (response.status === 401) {
    return new ApiRequestError('Unauthorized — enter a valid read or write token.', 401, 'UNAUTHORIZED');
  }
  if (response.status === 403) {
    return new ApiRequestError('Forbidden — verify server --cors-origin allows this viewer origin.', 403, 'FORBIDDEN');
  }
  let message = `HTTP ${response.status}`;
  let code: string | undefined;
  const contentType = response.headers.get('Content-Type') ?? '';
  if (contentType.includes('application/json')) {
    try {
      const body = (await response.json()) as { error?: string; code?: string };
      if (body.error) message = body.error;
      if (body.code) code = body.code;
    } catch {
      // Ignore malformed JSON error payloads.
    }
  }
  return new ApiRequestError(message, response.status, code);
}

export function parseSseBlock(block: string): SseFrame | null {
  let event = 'message';
  const dataLines: string[] = [];
  for (const rawLine of block.split(/\r?\n/)) {
    if (!rawLine || rawLine.startsWith(':')) continue;
    if (rawLine.startsWith('event:')) {
      event = rawLine.slice(6).trim();
    } else if (rawLine.startsWith('data:')) {
      dataLines.push(rawLine.slice(5).trimStart());
    }
  }
  if (!dataLines.length) return null;
  const joined = dataLines.join('\n');
  try {
    return { event, data: JSON.parse(joined) as Record<string, unknown> };
  } catch {
    return { event, data: { raw: joined } };
  }
}

export function normalizeAddress(addr: string): string {
  return (addr || '').trim().replace(/^0x/i, '').toLowerCase();
}

function stripLeadingHexZeros(hex: string): string {
  return hex.replace(/^0+(?=.)/, '');
}

export function sameAddress(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) return false;
  const na = normalizeAddress(a);
  const nb = normalizeAddress(b);
  if (na === nb) return true;
  if (/^[0-9a-f]+$/.test(na) && /^[0-9a-f]+$/.test(nb)) {
    return stripLeadingHexZeros(na) === stripLeadingHexZeros(nb);
  }
  return false;
}

function parseHexBigInt(raw: string): bigint | null {
  const m = /^(?:0x)?([0-9a-f]+)$/i.exec(raw.trim());
  if (!m) return null;
  try {
    return BigInt(`0x${m[1]}`);
  } catch {
    return null;
  }
}

export function isSegmentReadable(seg: SegmentInfo): boolean {
  if (seg.initialized !== undefined) return seg.initialized;
  return !seg.external && !['.bss', '.tbss', 'EXTERNAL'].includes(seg.name);
}

export function findSegmentForAddress(address: string, segments: SegmentInfo[]): SegmentInfo | null {
  const addr = (address || '').trim();
  if (
    !addr ||
    /\s/.test(addr) ||
    /^(?:NO ADDRESS|Entry Point)$/i.test(addr) ||
    /^EXTERNAL:/i.test(addr) ||
    /^Stack\[/i.test(addr)
  ) {
    return null;
  }

  const overlaySep = addr.indexOf('::');
  if (overlaySep > 0) {
    const segName = addr.slice(0, overlaySep);
    const offsetVal = parseHexBigInt(addr.slice(overlaySep + 2));
    if (offsetVal === null) return null;
    for (const seg of segments) {
      if (seg.name !== segName) continue;
      const startPart = seg.start.includes('::') ? seg.start.slice(seg.start.indexOf('::') + 2) : seg.start;
      const endPart = seg.end.includes('::') ? seg.end.slice(seg.end.indexOf('::') + 2) : seg.end;
      const startVal = parseHexBigInt(startPart);
      const endVal = parseHexBigInt(endPart);
      if (startVal !== null && endVal !== null && offsetVal >= startVal && offsetVal <= endVal) {
        return seg;
      }
    }
    return null;
  }

  const target = parseHexBigInt(addr);
  if (target === null) return null;
  for (const seg of segments) {
    if (seg.overlay || seg.start.includes('::')) continue;
    const startVal = parseHexBigInt(seg.start);
    const endVal = parseHexBigInt(seg.end);
    if (startVal !== null && endVal !== null && target >= startVal && target <= endVal) {
      return seg;
    }
  }
  return null;
}

export function isReadableAddress(address: string | undefined | null, segments: SegmentInfo[]): boolean {
  const addr = (address || '').trim();
  if (
    !addr ||
    /\s/.test(addr) ||
    /^(?:NO ADDRESS|Entry Point)$/i.test(addr) ||
    /^EXTERNAL:/i.test(addr) ||
    /^Stack\[/i.test(addr)
  ) {
    return false;
  }
  if (segments.length === 0) {
    const overlaySep = addr.indexOf('::');
    if (overlaySep > 0) return parseHexBigInt(addr.slice(overlaySep + 2)) !== null;
    return parseHexBigInt(addr) !== null;
  }
  const seg = findSegmentForAddress(addr, segments);
  return seg !== null && isSegmentReadable(seg);
}

export function isExternalSegmentAddress(address: string, segments: SegmentInfo[]): boolean {
  const addr = (address || '').trim();
  if (/^EXTERNAL:/i.test(addr)) return true;
  const seg = findSegmentForAddress(addr, segments);
  return Boolean(seg && (seg.external || seg.name === 'EXTERNAL'));
}

export function classifyEntryPoint(ep: string, segments: SegmentInfo[]): 'function' | 'data' | 'unreadable' {
  const seg = findSegmentForAddress(ep, segments);
  if (!seg || !isSegmentReadable(seg)) return 'unreadable';
  if (seg.execute && !seg.external && seg.name !== 'EXTERNAL') return 'function';
  return 'data';
}

export function formatRouteError(route: string, err: unknown): string {
  if (err instanceof ApiRequestError && err.status === 404 && !err.code) {
    return `GET ${route} returned 404 — rebuild ghidraMCP (\`just build\` / \`just image\`) for this route.`;
  }
  return err instanceof Error ? err.message : 'Request failed.';
}

export function createGhidraClient(baseUrl: string, token = '') {
  const trimmedToken = token.trim();

  async function requestRaw(path: string, opts?: { method?: 'GET' | 'POST'; signal?: AbortSignal }): Promise<Response> {
    const headers: Record<string, string> = trimmedToken ? { Authorization: `Bearer ${trimmedToken}` } : {};
    let response: Response;
    try {
      response = await fetch(baseUrl + path, {
        method: opts?.method ?? 'GET',
        headers,
        signal: opts?.signal,
        redirect: 'error',
      });
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      throw new ApiRequestError(networkFailureMessage(baseUrl));
    }
    if (!response.ok) {
      throw await parseErrorResponse(response);
    }
    return response;
  }

  async function requestJson<T>(path: string, opts?: { method?: 'GET' | 'POST'; signal?: AbortSignal }): Promise<T> {
    const response = await requestRaw(path, opts);
    return (await response.json()) as T;
  }

  return {
    baseUrl,
    hasToken: trimmedToken.length > 0,

    health(signal?: AbortSignal) {
      return requestJson<HealthResponse>('/api/v1/health', { signal });
    },

    status(signal?: AbortSignal) {
      return requestJson<StatusResponse>('/api/v1/status', { signal });
    },

    versions(signal?: AbortSignal) {
      return requestJson<VersionsResponse>('/api/v1/versions', { signal });
    },

    version(v: number, signal?: AbortSignal) {
      return requestJson<VersionDetailResponse>(`/api/v1/versions/${v}`, { signal });
    },

    diff(from: number, to: number, fn?: string, signal?: AbortSignal) {
      return requestJson<RangeDiffResponse>(`/api/v1/diff${buildQuery({ from, to, function: fn })}`, { signal });
    },

    functions(
      params: { filter?: string; sort?: 'address' | 'name' | 'size'; cursor?: string; limit?: number },
      signal?: AbortSignal,
    ) {
      return requestJson<FunctionsResponse>(`/api/v1/functions${buildQuery(params)}`, { signal });
    },

    functionDetail(
      target: string,
      opts?: { offset?: number; disasm?: boolean; disasmCursor?: string; maxInstructions?: number },
      signal?: AbortSignal,
    ) {
      const qs = buildQuery({
        offset: opts?.offset,
        disasm: opts?.disasm ? 'true' : undefined,
        disasm_cursor: opts?.disasmCursor,
        max_instructions: opts?.maxInstructions,
      });
      return requestJson<FunctionDetailResponse>(`/api/v1/functions/${encodeURIComponent(target)}${qs}`, { signal });
    },

    symbols(params: { kind: SymbolKind; filter?: string; cursor?: string; limit?: number }, signal?: AbortSignal) {
      return requestJson<SymbolsResponse>(`/api/v1/symbols${buildQuery(params)}`, { signal });
    },

    xrefs(params: { target: string; kind?: XrefKind; cursor?: string; limit?: number }, signal?: AbortSignal) {
      return requestJson<XrefsResponse>(`/api/v1/xrefs${buildQuery(params)}`, { signal });
    },

    memory(params: { address: string; size?: number; format?: MemoryFormat }, signal?: AbortSignal) {
      return requestJson<MemoryResponse>(`/api/v1/memory${buildQuery(params)}`, { signal });
    },

    search(params: { query: string; scope: SearchScope; cursor?: string; limit?: number }, signal?: AbortSignal) {
      return requestJson<SearchResponse>(`/api/v1/search${buildQuery(params)}`, { signal });
    },

    types(params: { query: string; exact?: boolean; cursor?: string; limit?: number }, signal?: AbortSignal) {
      return requestJson<TypesResponse>(
        `/api/v1/types${buildQuery({ ...params, exact: params.exact ? 'true' : undefined })}`,
        { signal },
      );
    },

    exportSnapshot(signal?: AbortSignal) {
      return requestJson<ExportResponse>('/api/v1/export', { method: 'POST', signal });
    },

    shutdown(signal?: AbortSignal) {
      return requestJson<{ ok: boolean; shutting_down: boolean }>('/api/v1/shutdown', { method: 'POST', signal });
    },

    async subscribeEvents(
      onFrame: (frame: SseFrame) => void,
      onState: (state: SseConnectionState, detail?: string) => void,
      signal: AbortSignal,
    ) {
      let retryMs = 2000;
      while (!signal.aborted) {
        let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
        let stopRetry = false;
        try {
          onState('connecting');
          const response = await requestRaw('/api/v1/events', { signal });
          if (!response.body) {
            throw new ApiRequestError('Event stream body unavailable.');
          }
          onState('connected');
          retryMs = 2000;
          const decoder = new TextDecoder();
          reader = response.body.getReader();
          let buffer = '';
          while (!signal.aborted) {
            const { value, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const blocks = buffer.split(/\r?\n\r?\n/);
            buffer = blocks.pop() ?? '';
            for (const block of blocks) {
              const frame = parseSseBlock(block);
              if (frame) onFrame(frame);
            }
          }
        } catch (error) {
          if (signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) {
            return;
          }
          if (error instanceof ApiRequestError && (error.status === 401 || error.status === 403)) {
            stopRetry = true;
            onState('auth_error', error.message);
          }
        } finally {
          if (reader) {
            await reader.cancel().catch(() => {});
          }
        }
        if (signal.aborted || stopRetry) return;
        onState('reconnecting');
        const jitter = Math.floor(Math.random() * 400);
        const waitMs = retryMs + jitter;
        retryMs = Math.min(30_000, retryMs * 2);
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, waitMs);
          signal.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              resolve();
            },
            { once: true },
          );
        });
      }
    },
  };
}

export type GhidraClient = ReturnType<typeof createGhidraClient>;

/** Collects every function modified in version history, preserving its latest observed name. */
export function collectTouchedFunctions(versions: VersionSummary[]): TouchedFunction[] {
  const byAddr = new Map<string, TouchedFunction>();
  const ordered = [...versions].sort((a, b) => a.version - b.version);
  for (const v of ordered) {
    for (const fn of v.functions) {
      const key = fn.function_address.toLowerCase();
      const existing = byAddr.get(key);
      if (existing) {
        existing.name = fn.function_name;
        if (!existing.versions.includes(v.version)) existing.versions.push(v.version);
        existing.latestVersion = v.version;
      } else {
        byAddr.set(key, {
          address: fn.function_address,
          name: fn.function_name,
          versions: [v.version],
          latestVersion: v.version,
        });
      }
    }
  }
  return [...byAddr.values()].sort((a, b) => b.latestVersion - a.latestVersion || a.name.localeCompare(b.name));
}

function extractSignatureFunctionName(code: string | null | undefined): string | null {
  if (!code) return null;
  const noComments = code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  const parenIdx = noComments.indexOf('(');
  if (parenIdx <= 0) return null;
  const head = noComments.slice(0, parenIdx).trimEnd();
  const match = /\b([A-Za-z_][A-Za-z0-9_]*)$/.exec(head);
  return match ? match[1] : null;
}

/** Reconstructs per-version C snapshots for one function so sliders can scrub v0..vN cleanly. */
export function buildFunctionTimeline(
  address: string,
  versions: VersionSummary[],
  details: ReadonlyMap<number, VersionDetail>,
  fallbackCode?: string,
): FunctionTimelineStep[] {
  const ordered = [...versions].sort((a, b) => a.version - b.version);

  let earliestDiff: FunctionDiff | undefined;
  let earliestVersion: number | undefined;
  for (const v of ordered) {
    const match = details.get(v.version)?.diffs.find((d) => sameAddress(d.function_address, address));
    if (match) {
      earliestDiff = match;
      earliestVersion = v.version;
      break;
    }
  }

  const initialNameFromBefore = earliestDiff
    ? extractSignatureFunctionName(earliestDiff.before_c)
    : extractSignatureFunctionName(fallbackCode);
  let runningCode = earliestDiff
    ? earliestDiff.before_c && earliestDiff.before_c.length > 0
      ? earliestDiff.before_c
      : `/* Function created at v${earliestVersion} */`
    : fallbackCode && fallbackCode.length > 0
      ? fallbackCode
      : '/* No pseudocode available */';
  let runningName = initialNameFromBefore ?? earliestDiff?.function_name ?? address;
  let runningStatus = earliestDiff ? 'baseline' : 'unchanged';

  return ordered.map((summary) => {
    const diff = details.get(summary.version)?.diffs.find((d) => sameAddress(d.function_address, address));
    if (diff) {
      runningName = diff.function_name;
      runningStatus = diff.decompile_status;
      if (diff.after_c && diff.after_c.length > 0) {
        runningCode = diff.after_c;
      } else if (diff.decompile_status !== 'complete') {
        runningCode = `/* decompile ${diff.decompile_status} at v${summary.version} */`;
      }
    }
    return {
      version: summary.version,
      operation: summary.operation,
      actor: summary.actor,
      reason: summary.reason,
      checkpointLabel: summary.checkpoint_label,
      changed: Boolean(diff),
      name: runningName,
      code: runningCode,
      diff: diff?.diff ?? '',
      decompileStatus: diff ? diff.decompile_status : runningStatus,
    };
  });
}

export function formatDisassembly(instructions: DisasmInstruction[]): string {
  if (!instructions.length) return '; (no instructions)';
  return instructions
    .map((ins) => {
      const addr = ins.address.padEnd(10, ' ');
      const bytes = ins.bytes.padEnd(18, ' ');
      const opText = ins.operands ? `${ins.mnemonic} ${ins.operands}` : ins.mnemonic;
      const pre = ins.pre_comment ? `; ${ins.pre_comment.replace(/\s+/g, ' ')}\n` : '';
      const eol = ins.eol_comment ? ` ; ${ins.eol_comment.replace(/\s+/g, ' ')}` : '';
      return `${pre}${addr}  ${bytes}  ${opText}${eol}`;
    })
    .join('\n');
}

export function formatUptime(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const hrs = Math.floor(totalSec / 3600);
  const mins = Math.floor((totalSec % 3600) / 60);
  const secs = totalSec % 60;
  if (hrs > 0) return `${hrs}h ${mins}m ${secs}s`;
  if (mins > 0) return `${mins}m ${secs}s`;
  return `${secs}s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '-';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

/** Builds a clean `?port=` or `?api=` query string for per-tab server URLs. */
export function buildServerQuery(raw: string): string {
  const normalized = normalizeTarget(raw);
  const trimmed = raw.trim();
  if (/^\d+$/.test(trimmed)) {
    return `?port=${Number.parseInt(trimmed, 10)}`;
  }
  const loopbackMatch = /^http:\/\/127\.0\.0\.1:(\d+)$/.exec(normalized);
  if (loopbackMatch) {
    return `?port=${loopbackMatch[1]}`;
  }
  return `?api=${encodeURIComponent(normalized)}`;
}

export function formatServerTag(baseUrl: string): string {
  try {
    const url = new URL(baseUrl);
    const host = url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if ((host === '127.0.0.1' || host === 'localhost' || host === '::1') && url.port) {
      return `:${url.port}`;
    }
    return url.host;
  } catch {
    return baseUrl;
  }
}

export function upsertSavedServer(list: SavedServer[], entry: SavedServer, max = 8): SavedServer[] {
  const existing = list.find((item) => item.baseUrl === entry.baseUrl);
  const merged: SavedServer = {
    raw: entry.raw,
    baseUrl: entry.baseUrl,
    label: entry.label ?? existing?.label,
  };
  return [merged, ...list.filter((item) => item.baseUrl !== entry.baseUrl)].slice(0, max);
}

export function removeSavedServer(list: SavedServer[], baseUrl: string): SavedServer[] {
  return list.filter((item) => item.baseUrl !== baseUrl);
}

const WORKSPACE_TABS: readonly WorkspaceTab[] = ['scrubber', 'functions', 'explore', 'binary'];
const FN_SUB_VIEWS: readonly FunctionSubView[] = ['pseudocode', 'disassembly', 'xrefs'];
const FN_SORTS: readonly ('address' | 'name' | 'size')[] = ['address', 'name', 'size'];
const EXPLORE_SUB_TABS: readonly ExploreSubTab[] = ['symbols', 'types', 'search', 'memory'];
const SYMBOL_KINDS: readonly SymbolKind[] = ['imports', 'exports', 'globals', 'strings', 'classes', 'namespaces'];
const SEARCH_SCOPES: readonly SearchScope[] = ['pseudocode', 'disassembly', 'bytes'];
const MEMORY_FORMATS: readonly MemoryFormat[] = ['hex', 'utf8', 'u32', 'u64'];

function pickEnum<T extends string>(raw: string | null, allowed: readonly T[]): T | undefined {
  return raw && (allowed as readonly string[]).includes(raw) ? (raw as T) : undefined;
}

function parseNonNegInt(raw: string | null): number | undefined {
  if (!raw || !/^\d+$/.test(raw.trim())) return undefined;
  const n = Number.parseInt(raw.trim(), 10);
  return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
}

/** Restores deep workspace navigation state from URL search params. */
export function parseNavState(search: string): UrlNavState {
  const params = new URLSearchParams(search);
  const tab = pickEnum(params.get('tab'), WORKSPACE_TABS) ?? 'scrubber';
  const nav: UrlNavState = { tab };

  if (tab === 'scrubber') {
    const mode = params.get('mode');
    if (mode === 'snapshot' || mode === 'diff') nav.scrubMode = mode;
    const fn = params.get('fn')?.trim();
    if (fn) nav.scrubFn = fn;
    nav.scrubVersion = parseNonNegInt(params.get('v'));
    nav.diffFrom = parseNonNegInt(params.get('from'));
    nav.diffTo = parseNonNegInt(params.get('to'));
  } else if (tab === 'functions') {
    const fn = params.get('fn')?.trim();
    if (fn) nav.fnTarget = fn;
    nav.fnView = pickEnum(params.get('view'), FN_SUB_VIEWS);
    nav.fnSort = pickEnum(params.get('sort'), FN_SORTS);
    const q = params.get('q');
    if (q) nav.fnFilter = q;
  } else if (tab === 'explore') {
    const sub = pickEnum(params.get('sub'), EXPLORE_SUB_TABS) ?? 'symbols';
    nav.exploreSub = sub;
    if (sub === 'symbols') {
      nav.symbolKind = pickEnum(params.get('kind'), SYMBOL_KINDS);
      const q = params.get('q');
      if (q) nav.symbolFilter = q;
    } else if (sub === 'types') {
      const q = params.get('q');
      if (q) nav.typeQuery = q;
      if (params.get('exact') === '1' || params.get('exact') === 'true') nav.typeExact = true;
    } else if (sub === 'search') {
      nav.searchScope = pickEnum(params.get('scope'), SEARCH_SCOPES);
      const q = params.get('q');
      if (q) nav.searchQuery = q;
    } else if (sub === 'memory') {
      const addr = params.get('addr')?.trim();
      if (addr) nav.memAddr = addr;
      const size = parseNonNegInt(params.get('size'));
      if (size !== undefined && size >= 1 && size <= 4096) nav.memSize = size;
      nav.memFormat = pickEnum(params.get('fmt'), MEMORY_FORMATS);
    }
  }
  return nav;
}

/** Serializes server target plus active tab navigation into a compact URL query string. */
export function buildNavUrl(rawTarget: string, nav: UrlNavState): string {
  const baseQuery = buildServerQuery(rawTarget);
  const params = new URLSearchParams(baseQuery);

  if (nav.tab !== 'scrubber') {
    params.set('tab', nav.tab);
  }

  if (nav.tab === 'scrubber') {
    if (nav.scrubFn) params.set('fn', nav.scrubFn);
    if (nav.scrubMode === 'diff') {
      params.set('mode', 'diff');
      if (nav.diffFrom !== undefined) params.set('from', String(nav.diffFrom));
      if (nav.diffTo !== undefined) params.set('to', String(nav.diffTo));
    } else if (nav.scrubVersion !== undefined) {
      params.set('v', String(nav.scrubVersion));
    }
  } else if (nav.tab === 'functions') {
    if (nav.fnTarget) params.set('fn', nav.fnTarget);
    if (nav.fnView && nav.fnView !== 'pseudocode') params.set('view', nav.fnView);
    if (nav.fnSort && nav.fnSort !== 'address') params.set('sort', nav.fnSort);
    if (nav.fnFilter) params.set('q', nav.fnFilter);
  } else if (nav.tab === 'explore') {
    const sub = nav.exploreSub ?? 'symbols';
    if (sub !== 'symbols') params.set('sub', sub);
    if (sub === 'symbols') {
      if (nav.symbolKind && nav.symbolKind !== 'strings') params.set('kind', nav.symbolKind);
      if (nav.symbolFilter) params.set('q', nav.symbolFilter);
    } else if (sub === 'types') {
      if (nav.typeQuery) params.set('q', nav.typeQuery);
      if (nav.typeExact) params.set('exact', '1');
    } else if (sub === 'search') {
      if (nav.searchScope && nav.searchScope !== 'pseudocode') params.set('scope', nav.searchScope);
      if (nav.searchQuery) params.set('q', nav.searchQuery);
    } else if (sub === 'memory') {
      if (nav.memAddr) params.set('addr', nav.memAddr);
      if (nav.memSize !== undefined && nav.memSize !== 64) params.set('size', String(nav.memSize));
      if (nav.memFormat && nav.memFormat !== 'hex') params.set('fmt', nav.memFormat);
    }
  }

  return `?${params.toString()}`;
}
