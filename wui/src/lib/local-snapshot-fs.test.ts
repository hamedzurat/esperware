import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  isLoopbackAddress,
  isSafeRelativePath,
  LocalSnapshotError,
  readAllowedSnapshotFile,
  readSnapshotBundle,
  readValidatedManifest,
  resolveSnapshotDir,
} from './local-snapshot-fs.ts';

let tmpRoot = '';
let validSnapDir = '';
let outsideFile = '';

before(async () => {
  tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'esperware-snap-test-'));
  validSnapDir = path.join(tmpRoot, 'snap');
  await fs.mkdir(path.join(validSnapDir, 'src'), { recursive: true });

  outsideFile = path.join(tmpRoot, 'secret.txt');
  await fs.writeFile(outsideFile, 'top-secret\n', 'utf8');
  await fs.writeFile(path.join(validSnapDir, 'unlisted.txt'), 'not-in-manifest\n', 'utf8');
  await fs.symlink(outsideFile, path.join(validSnapDir, 'src', 'escape.c'));

  await fs.writeFile(
    path.join(validSnapDir, 'manifest.json'),
    JSON.stringify({
      version: 0,
      binary_name: 'demo.elf',
      export_layout_version: 2,
      counts: { functions: 1 },
      files: ['functions.jsonl', 'types.h', 'src/001000.c', 'src/escape.c'],
    }),
    'utf8',
  );
  await fs.writeFile(
    path.join(validSnapDir, 'functions.jsonl'),
    '{"entry_address":"00401000","entry_offset":"001000","size":16,"name":"demo","signature":"void demo(void)","src_file":"src/001000.c"}\n',
    'utf8',
  );
  await fs.writeFile(path.join(validSnapDir, 'types.h'), 'typedef unsigned int u32;\n', 'utf8');
  await fs.writeFile(path.join(validSnapDir, 'src', '001000.c'), 'void demo(void) {}\n', 'utf8');
});

after(async () => {
  if (tmpRoot) {
    await fs.rm(tmpRoot, { recursive: true, force: true });
  }
});

describe('local-snapshot-fs security and allowlist checks', () => {
  it('accepts only loopback remote addresses', () => {
    assert.equal(isLoopbackAddress('127.0.0.1'), true);
    assert.equal(isLoopbackAddress('::1'), true);
    assert.equal(isLoopbackAddress('::ffff:127.0.0.1'), true);
    assert.equal(isLoopbackAddress('192.168.1.50'), false);
    assert.equal(isLoopbackAddress('0.0.0.0'), false);
    assert.equal(isLoopbackAddress(undefined), false);
  });

  it('rejects unsafe relative paths', () => {
    assert.equal(isSafeRelativePath('src/001000.c'), true);
    assert.equal(isSafeRelativePath('manifest.json'), true);
    assert.equal(isSafeRelativePath('../etc/passwd'), false);
    assert.equal(isSafeRelativePath('/etc/passwd'), false);
    assert.equal(isSafeRelativePath('src\\001000.c'), false);
    assert.equal(isSafeRelativePath('src/../secret.txt'), false);
    assert.equal(isSafeRelativePath('a\0b'), false);
  });

  it('reads allowlisted files and blocks unlisted, traversal, and escaping symlinks', async () => {
    const realDir = await resolveSnapshotDir(validSnapDir);
    const { allowlist } = await readValidatedManifest(realDir);

    assert.equal(await readAllowedSnapshotFile(realDir, allowlist, 'src/001000.c'), 'void demo(void) {}\n');

    await assert.rejects(
      () => readAllowedSnapshotFile(realDir, allowlist, '../secret.txt'),
      (err: unknown) => err instanceof LocalSnapshotError && err.status === 403,
    );
    await assert.rejects(
      () => readAllowedSnapshotFile(realDir, allowlist, 'unlisted.txt'),
      (err: unknown) => err instanceof LocalSnapshotError && err.status === 403,
    );
    await assert.rejects(
      () => readAllowedSnapshotFile(realDir, allowlist, 'src/escape.c'),
      (err: unknown) => err instanceof LocalSnapshotError && err.status === 403,
    );
  });

  it('rejects directories without a valid manifest.json', async () => {
    const noManifestDir = path.join(tmpRoot, 'empty-dir');
    await fs.mkdir(noManifestDir, { recursive: true });
    await assert.rejects(
      () => resolveSnapshotDir(noManifestDir),
      (err: unknown) => err instanceof LocalSnapshotError && err.status === 404,
    );
  });

  it('loads repo .tmp/stripped and .tmp/unstripped bundles when present', async () => {
    const repoTmp = fileURLToPath(new URL('../../../.tmp', import.meta.url));
    const strippedDir = path.join(repoTmp, 'stripped');
    const unstrippedDir = path.join(repoTmp, 'unstripped');
    const strippedExists = await fs
      .stat(path.join(strippedDir, 'manifest.json'))
      .then(() => true)
      .catch(() => false);
    if (!strippedExists) return;

    const strippedBundle = await readSnapshotBundle(strippedDir);
    const unstrippedBundle = await readSnapshotBundle(unstrippedDir);
    assert.equal((strippedBundle.manifest.counts as { functions: number }).functions, 9);
    assert.equal((unstrippedBundle.manifest.counts as { functions: number }).functions, 12);
    assert.equal(strippedBundle.sourcesComplete, true);
    assert.equal(Object.hasOwn(strippedBundle.sources, 'src/001129.c'), true);
    assert.equal(unstrippedBundle.sources['src/00119a.c']?.includes('main'), true);
  });
});
