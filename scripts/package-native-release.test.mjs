import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { gunzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { BINARIES, HELPERS, MAX_BINARY_BYTES, packageNativeRelease } from './package-native-release.mjs';
import { validateArtifact } from './release-channels.mjs';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const manifestName = 'heteronetwork-release-artifact.json';
const base = { schema_version: 1, component: 'heteronetwork', version: 'v1.2.3-rc.1',
  commit: 'a'.repeat(40), image: `ghcr.io/ipa-cyberlab/heteronetwork@sha256:${'b'.repeat(64)}` };
const asset = 'heteronetwork-1.2.3-rc.1-linux-amd64.tar.gz';

// Deliberately non-runnable synthetic ELF headers, not compiled release binaries.
function elf() {
  const bytes = Buffer.alloc(128);
  Buffer.from([127, 69, 76, 70, 2, 1, 1]).copy(bytes);
  bytes.writeUInt16LE(3, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeUInt16LE(64, 52);
  return bytes;
}

async function fixture(run) {
  const root = await fs.mkdtemp(path.join(tmpdir(), 'native-package-test-'));
  const bin = path.join(root, 'binaries');
  const artifact = path.join(root, 'base.json');
  const out = path.join(root, 'out');
  try {
    await fs.mkdir(bin);
    for (const name of BINARIES) await fs.writeFile(path.join(bin, name), elf(), { mode: 0o600 });
    await fs.writeFile(artifact, JSON.stringify(base));
    await run({ root, bin, artifact, out });
  } finally { await fs.rm(root, { recursive: true, force: true }); }
}

function members(gzip) {
  const tar = gunzipSync(gzip);
  const result = [];
  let position = 0;
  const text = bytes => bytes.toString('ascii').replace(/\0.*$/s, '').trim();
  const octal = bytes => Number.parseInt(text(bytes), 8);
  while (position + 512 <= tar.length) {
    const header = tar.subarray(position, position + 512);
    if (header.every(byte => byte === 0)) {
      assert.ok(tar.subarray(position).every(byte => byte === 0));
      break;
    }
    const size = octal(header.subarray(124, 136));
    result.push({ name: text(header.subarray(0, 100)), mode: octal(header.subarray(100, 108)),
      uid: octal(header.subarray(108, 116)), gid: octal(header.subarray(116, 124)),
      mtime: octal(header.subarray(136, 148)), type: header[156],
      link: text(header.subarray(157, 257)), data: tar.subarray(position + 512, position + 512 + size) });
    position += 512 + Math.ceil(size / 512) * 512;
  }
  return result;
}

test('synthetic ELF package matches parent schema, exact files, bytes and deterministic tar metadata', async () => {
  await fixture(async ({ artifact, bin, out, root }) => {
    await fs.writeFile(path.join(bin, 'unreviewed.sh'), 'not included');
    const result = await packageNativeRelease(artifact, bin, out);
    assert.deepEqual(validateArtifact(result), result);
    for (const key of Object.keys(base)) assert.equal(result[key], base[key]);
    const archive = await fs.readFile(path.join(out, asset));
    const bundle = result.native['linux-amd64'];
    assert.equal(bundle.asset, asset);
    assert.equal(bundle.sha256, digest(archive));
    assert.deepEqual(JSON.parse(await fs.readFile(path.join(out, manifestName), 'utf8')), result);
    const entries = members(archive);
    const expected = [...BINARIES.map(name => `bin/${name}`), ...HELPERS.map(name => `libexec/${name}`)].sort();
    assert.deepEqual(entries.map(entry => entry.name), expected);
    assert.deepEqual(Object.keys(bundle.files), expected);
    for (const entry of entries) {
      assert.equal(entry.mode, 0o755);
      assert.equal(entry.uid, 0);
      assert.equal(entry.gid, 0);
      assert.equal(entry.mtime, 0);
      assert.equal(entry.type, 48);
      assert.equal(entry.link, '');
      const source = path.join(entry.name.startsWith('bin/') ? bin : scriptDir, path.basename(entry.name));
      assert.deepEqual(entry.data, await fs.readFile(source));
      assert.equal(bundle.files[entry.name], digest(entry.data));
    }
    assert.deepEqual((await fs.readdir(out)).sort(), [manifestName, asset].sort());
    for (const name of BINARIES) {
      await fs.chmod(path.join(bin, name), 0o700);
      await fs.utimes(path.join(bin, name), 1234, 5678);
    }
    const second = path.join(root, 'second');
    await packageNativeRelease(artifact, bin, second);
    assert.deepEqual(await fs.readFile(path.join(second, asset)), archive);
  });
});

test('CLI accepts exactly the CI inputs and creates its output directory', async () => {
  await fixture(async ({ artifact, bin, out }) => {
    const stdout = execFileSync(process.execPath, [path.join(scriptDir, 'package-native-release.mjs'), artifact, bin, out], { encoding: 'utf8' });
    assert.equal(stdout.trim(), asset);
    assert.ok((await fs.stat(path.join(out, manifestName))).isFile());
  });
});

test('either existing output including dangling symlinks denies without replacing contents', async () => {
  for (const name of [asset, manifestName]) {
    for (const symlink of [false, true]) await fixture(async ({ artifact, bin, out }) => {
      await fs.mkdir(out);
      const target = path.join(out, name);
      if (symlink) await fs.symlink('missing-target', target);
      else await fs.writeFile(target, 'preserve');
      await assert.rejects(packageNativeRelease(artifact, bin, out));
      if (symlink) assert.equal(await fs.readlink(target), 'missing-target');
      else assert.equal(await fs.readFile(target, 'utf8'), 'preserve');
      assert.deepEqual(await fs.readdir(out), [name]);
    });
  }
});

test('rejects missing, linked, nonregular, oversized and wrong-architecture binaries', async () => {
  const changes = [
    async filename => fs.unlink(filename),
    async filename => { await fs.unlink(filename); await fs.symlink('iparsd', filename); },
    async filename => fs.link(filename, `${filename}-hardlink`),
    async filename => { await fs.unlink(filename); await fs.mkdir(filename); },
    async filename => { await fs.unlink(filename); execFileSync('mkfifo', [filename]); },
    async filename => fs.truncate(filename, MAX_BINARY_BYTES + 1),
    async filename => fs.writeFile(filename, Buffer.alloc(63)),
    ...[[4, 1], [5, 2], [18, 183], [16, 1], [52, 32]].map(([offset, value]) => async filename => {
      const bytes = elf(); bytes[offset] = value; await fs.writeFile(filename, bytes);
    }),
  ];
  for (const change of changes) await fixture(async ({ artifact, bin, out }) => {
    await change(path.join(bin, 'ipars'));
    await assert.rejects(packageNativeRelease(artifact, bin, out));
    assert.deepEqual(await fs.readdir(out), []);
  });
});

test('rejects symlinked input directories, artifacts and output directories', async () => {
  await fixture(async ({ artifact, bin, out, root }) => {
    const link = path.join(root, 'linked');
    await fs.symlink(bin, link);
    await assert.rejects(packageNativeRelease(artifact, link, out));
    await fs.unlink(link);
    await fs.symlink(artifact, link);
    await assert.rejects(packageNativeRelease(link, bin, out));
    await fs.unlink(link);
    await fs.symlink(root, link);
    await assert.rejects(packageNativeRelease(artifact, bin, path.join(link, 'out')));
    await fs.mkdir(out);
    await fs.symlink(out, path.join(root, 'linked-out'));
    await assert.rejects(packageNativeRelease(artifact, bin, path.join(root, 'linked-out')));
  });
});

test('invalid component, mutable image, extended input and traversal version fail closed', async () => {
  for (const change of [{ component: 'flow' }, { image: 'ghcr.io/ipa-cyberlab/heteronetwork:latest' },
    { image: `ghcr.io/ipa-cyberlab/other@sha256:${'b'.repeat(64)}` }, { native: {} },
    { commit: 'abcd' }, { version: '../../escape' }]) {
    await fixture(async ({ artifact, bin, out }) => {
      await fs.writeFile(artifact, JSON.stringify({ ...base, ...change }));
      await assert.rejects(packageNativeRelease(artifact, bin, out));
    });
  }
});

test('competing publishers have one winner without replacing the archive', async () => {
  await fixture(async ({ artifact, bin, out }) => {
    const results = await Promise.allSettled([
      packageNativeRelease(artifact, bin, out), packageNativeRelease(artifact, bin, out),
    ]);
    assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
    const manifest = JSON.parse(await fs.readFile(path.join(out, manifestName), 'utf8'));
    assert.equal(manifest.native['linux-amd64'].sha256, digest(await fs.readFile(path.join(out, asset))));
    assert.deepEqual((await fs.readdir(out)).sort(), [manifestName, asset].sort());
  });
});

test('missing tar fails without publishing or leaving temporary files and locks', async () => {
  await fixture(async ({ artifact, bin, out, root }) => {
    const original = process.env.PATH;
    try {
      process.env.PATH = root;
      await assert.rejects(packageNativeRelease(artifact, bin, out));
    } finally {
      if (original === undefined) delete process.env.PATH;
      else process.env.PATH = original;
    }
    assert.deepEqual(await fs.readdir(out), []);
  });
});
