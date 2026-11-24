import fs from 'node:fs/promises';
import type { IncomingMessage, ServerResponse } from 'node:http';
import path from 'node:path';
import type { Plugin } from 'vite';

const LOCAL_SNAPSHOT_ENDPOINT = '/__local-snapshot';
const MAX_BUNDLE_SOURCE_FILES = 150;
const MAX_BUNDLE_SOURCE_BYTES = 16 * 1024 * 1024;
const LOOPBACK_IPS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);

export class LocalSnapshotError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'LocalSnapshotError';
    this.status = status;
  }
}

export type SnapshotBundlePayload = {
  dir: string;
  manifest: Record<string, unknown>;
  functionsText: string;
  symbolsText: string;
  callgraphText: string;
  typesText: string;
  sources: Record<string, string>;
  sourcesComplete: boolean;
};

export function isLoopbackAddress(remoteAddress?: string | null): boolean {
  if (!remoteAddress) return false;
  return LOOPBACK_IPS.has(remoteAddress.trim());
}

export function isSafeRelativePath(relPath: string): boolean {
  if (!relPath || relPath.includes('\0') || relPath.includes('\\') || relPath.startsWith('/')) {
    return false;
  }
  const segments = relPath.split('/');
  return segments.every((seg) => seg.length > 0 && seg !== '.' && seg !== '..');
}

function isInsideDir(realDir: string, realTarget: string): boolean {
  return realTarget === realDir || realTarget.startsWith(realDir + path.sep);
}

export async function resolveSnapshotDir(rawDir: string, cwd = process.cwd()): Promise<string> {
  if (typeof rawDir !== 'string' || rawDir.includes('\0')) {
    throw new LocalSnapshotError(400, 'Invalid snapshot directory parameter.');
  }
  const trimmed = rawDir.trim();
  if (!trimmed) {
    throw new LocalSnapshotError(400, 'Missing snapshot directory path.');
  }

  const candidates = path.isAbsolute(trimmed)
    ? [path.resolve(trimmed)]
    : [path.resolve(cwd, trimmed), path.resolve(cwd, '..', trimmed)];

  for (const candidate of candidates) {
    let realDir: string;
    try {
      realDir = await fs.realpath(candidate);
    } catch {
      continue;
    }

    let dirStat;
    try {
      dirStat = await fs.stat(realDir);
    } catch {
      continue;
    }
    if (!dirStat.isDirectory()) {
      throw new LocalSnapshotError(400, `Path is not a directory: ${trimmed}`);
    }

    const manifestCandidate = path.resolve(realDir, 'manifest.json');
    try {
      const realManifest = await fs.realpath(manifestCandidate);
      if (!realManifest.startsWith(realDir + path.sep)) {
        throw new LocalSnapshotError(403, 'manifest.json escapes snapshot directory.');
      }
      const manifestStat = await fs.stat(realManifest);
      if (manifestStat.isFile()) {
        return realDir;
      }
    } catch (err) {
      if (err instanceof LocalSnapshotError) throw err;
      throw new LocalSnapshotError(404, `Missing manifest.json in snapshot directory: ${realDir}`);
    }
  }

  throw new LocalSnapshotError(404, `Snapshot directory not found: ${trimmed}`);
}

export async function readValidatedManifest(realDir: string): Promise<{
  manifest: Record<string, unknown>;
  allowlist: Set<string>;
  rawText: string;
}> {
  const manifestPath = path.resolve(realDir, 'manifest.json');
  let realManifest: string;
  try {
    realManifest = await fs.realpath(manifestPath);
  } catch {
    throw new LocalSnapshotError(404, 'Missing manifest.json.');
  }
  if (!isInsideDir(realDir, realManifest) || realManifest === realDir) {
    throw new LocalSnapshotError(403, 'manifest.json escapes snapshot directory.');
  }

  const manifestStat = await fs.stat(realManifest);
  if (!manifestStat.isFile()) {
    throw new LocalSnapshotError(404, 'manifest.json is not a regular file.');
  }

  const rawText = await fs.readFile(realManifest, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    throw new LocalSnapshotError(400, 'manifest.json contains invalid JSON.');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new LocalSnapshotError(400, 'manifest.json root must be a JSON object.');
  }

  const manifest = parsed as Record<string, unknown>;
  if (typeof manifest.binary_name !== 'string' || !Array.isArray(manifest.files)) {
    throw new LocalSnapshotError(400, 'manifest.json must include string binary_name and files array.');
  }

  const allowlist = new Set<string>(['manifest.json']);
  for (const entry of manifest.files) {
    if (typeof entry !== 'string' || !isSafeRelativePath(entry)) {
      throw new LocalSnapshotError(400, `Unsafe path listed in manifest files: ${String(entry)}`);
    }
    allowlist.add(entry);
  }

  return { manifest, allowlist, rawText };
}

export async function readAllowedSnapshotFile(
  realDir: string,
  allowlist: Set<string>,
  relPath: string,
): Promise<string> {
  if (typeof relPath !== 'string') {
    throw new LocalSnapshotError(400, 'Invalid file parameter.');
  }
  const trimmed = relPath.trim();
  if (!isSafeRelativePath(trimmed)) {
    throw new LocalSnapshotError(403, `Forbidden relative file path: ${relPath}`);
  }
  if (!allowlist.has(trimmed)) {
    throw new LocalSnapshotError(403, `File is not listed in snapshot manifest allowlist: ${trimmed}`);
  }

  const candidate = path.resolve(realDir, trimmed);
  let realFile: string;
  try {
    realFile = await fs.realpath(candidate);
  } catch {
    throw new LocalSnapshotError(404, `Snapshot file not found: ${trimmed}`);
  }
  if (!isInsideDir(realDir, realFile) || realFile === realDir) {
    throw new LocalSnapshotError(403, `Symlink escapes snapshot directory: ${trimmed}`);
  }

  const fileStat = await fs.stat(realFile);
  if (!fileStat.isFile()) {
    throw new LocalSnapshotError(404, `Snapshot entry is not a regular file: ${trimmed}`);
  }

  return fs.readFile(realFile, 'utf8');
}

async function readOptionalAllowed(realDir: string, allowlist: Set<string>, relPath: string): Promise<string> {
  if (!allowlist.has(relPath)) return '';
  return readAllowedSnapshotFile(realDir, allowlist, relPath);
}

export async function readSnapshotBundle(rawDir: string, cwd = process.cwd()): Promise<SnapshotBundlePayload> {
  const realDir = await resolveSnapshotDir(rawDir, cwd);
  const { manifest, allowlist } = await readValidatedManifest(realDir);

  const [functionsText, symbolsText, callgraphText, typesText] = await Promise.all([
    readOptionalAllowed(realDir, allowlist, 'functions.jsonl'),
    readOptionalAllowed(realDir, allowlist, 'symbols.json'),
    readOptionalAllowed(realDir, allowlist, 'callgraph.jsonl'),
    readOptionalAllowed(realDir, allowlist, 'types.h'),
  ]);

  const srcFiles = [...allowlist]
    .filter((entry) => entry.startsWith('src/') && entry.endsWith('.c'))
    .sort((a, b) => a.localeCompare(b));

  const sources: Record<string, string> = {};
  let sourcesComplete = srcFiles.length <= MAX_BUNDLE_SOURCE_FILES;
  if (sourcesComplete) {
    let totalBytes = 0;
    for (const relPath of srcFiles) {
      const content = await readAllowedSnapshotFile(realDir, allowlist, relPath);
      const nextBytes = Buffer.byteLength(content, 'utf8');
      if (totalBytes + nextBytes > MAX_BUNDLE_SOURCE_BYTES) {
        sourcesComplete = false;
        break;
      }
      totalBytes += nextBytes;
      sources[relPath] = content;
    }
  }

  return {
    dir: realDir,
    manifest,
    functionsText,
    symbolsText,
    callgraphText,
    typesText,
    sources,
    sourcesComplete,
  };
}

function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

export function createLocalSnapshotMiddleware(cwd = process.cwd()) {
  return async (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => {
    const rawUrl = req.url ?? '/';
    const url = new URL(rawUrl, 'http://127.0.0.1');
    if (url.pathname !== LOCAL_SNAPSHOT_ENDPOINT) {
      next();
      return;
    }

    if (req.method !== 'GET') {
      sendJson(res, 405, { error: 'Only GET requests are supported.' });
      return;
    }

    if (!isLoopbackAddress(req.socket?.remoteAddress)) {
      sendJson(res, 403, { error: 'Local snapshot reader is restricted to loopback clients.' });
      return;
    }

    const dir = url.searchParams.get('dir') ?? '';
    const mode = url.searchParams.get('mode') ?? '';
    const file = url.searchParams.get('file') ?? '';

    try {
      if (mode === 'bundle') {
        const bundle = await readSnapshotBundle(dir, cwd);
        sendJson(res, 200, bundle);
        return;
      }

      if (!file) {
        sendJson(res, 400, { error: 'Specify mode=bundle or file=<allowlisted-path>.' });
        return;
      }

      const realDir = await resolveSnapshotDir(dir, cwd);
      const { allowlist } = await readValidatedManifest(realDir);
      const text = await readAllowedSnapshotFile(realDir, allowlist, file);
      res.statusCode = 200;
      res.setHeader(
        'Content-Type',
        file.endsWith('.json') ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
      );
      res.setHeader('Cache-Control', 'no-store');
      res.end(text);
    } catch (err) {
      if (err instanceof LocalSnapshotError) {
        sendJson(res, err.status, { error: err.message });
        return;
      }
      sendJson(res, 500, { error: err instanceof Error ? err.message : 'Failed to read local snapshot.' });
    }
  };
}

export function createLocalSnapshotPlugin(): Plugin {
  const middleware = createLocalSnapshotMiddleware();
  return {
    name: 'esperware-local-snapshot',
    configureServer(server) {
      server.middlewares.use(middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use(middleware);
    },
  };
}
