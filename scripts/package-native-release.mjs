#!/usr/bin/env node
import fs, { constants } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateArtifact } from './release-channels.mjs';

export const BINARIES = ['ipars', 'iparsd', 'ipars-k8s-controller'];
export const HELPERS = [
  'public-services-bootstrap.sh', 'public-services-autopilot.sh',
  'postgres-ha-node.sh', 'postgres-ha-autopilot.sh',
  'keycloak-ha-node.sh', 'keycloak-autopilot.sh',
  'kubeadm-ha-node.sh', 'kubeadm-ha-autopilot.sh',
  'reconcile-owner-console-auth.sh',
];
export const MAX_BINARY_BYTES = 256 * 1024 * 1024;
const MAX_HELPER_BYTES = 2 * 1024 * 1024;
const MAX_ARCHIVE_BYTES = 512 * 1024 * 1024;
const MAX_TOTAL_BYTES = 768 * 1024 * 1024;
const MANIFEST_NAME = 'heteronetwork-release-artifact.json';
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const readFlags = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
const fdPath = handle => `/proc/${process.pid}/fd/${handle.fd}`;

// Pin each ancestor without following symlinks. Child tar can also access these
// parent-process descriptors, even though Node marks descriptors close-on-exec.
async function openDirectory(filename) {
  let handle = await fs.open('/', readFlags | constants.O_DIRECTORY);
  try {
    for (const part of path.resolve(filename).split('/').filter(Boolean)) {
      const next = await fs.open(`${fdPath(handle)}/${part}`, readFlags | constants.O_DIRECTORY);
      await handle.close();
      handle = next;
    }
    return handle;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function regularSource(filename, maximum) {
  const handle = await fs.open(filename, readFlags);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.nlink !== 1 || info.size === 0 || info.size > maximum) {
      throw new Error('Source must be a nonempty bounded regular file with one link');
    }
    return { handle, info };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

function validateElf(header) {
  if (header.length < 64 || !header.subarray(0, 7).equals(Buffer.from([127, 69, 76, 70, 2, 1, 1])) ||
      ![2, 3].includes(header.readUInt16LE(16)) || header.readUInt16LE(18) !== 62 ||
      header.readUInt32LE(20) !== 1 || header.readUInt16LE(52) !== 64) {
    throw new Error('Binary must be an ELF64 little-endian x86_64 executable');
  }
}

async function copySource(source, destination, binary) {
  const maximum = binary ? MAX_BINARY_BYTES : MAX_HELPER_BYTES;
  const { handle, info } = await regularSource(source, maximum);
  let output;
  try {
    output = await fs.open(destination, 'wx', 0o600);
    const digest = createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    let total = 0;
    let header = Buffer.alloc(0);
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.length, maximum + 1 - total), null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maximum) throw new Error('Source grew beyond its size limit');
      const bytes = buffer.subarray(0, bytesRead);
      if (header.length < 64) header = Buffer.concat([header, bytes.subarray(0, 64 - header.length)]);
      digest.update(bytes);
      await output.writeFile(bytes);
    }
    const after = await handle.stat();
    if (total !== info.size || after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs) {
      throw new Error('Source changed during packaging');
    }
    if (binary) validateElf(header);
    await output.chmod(0o755);
    await output.sync();
    return { sha256: digest.digest('hex'), size: total };
  } finally {
    await output?.close();
    await handle.close();
  }
}

async function archiveFiles(stage, names, archive) {
  const output = await fs.open(archive, 'wx', 0o600);
  const digest = createHash('sha256');
  let size = 0;
  const tar = spawn('tar', [
    '--format=ustar', '--sort=name', '--mtime=@0', '--owner=0', '--group=0',
    '--numeric-owner', '--mode=0755', '--no-recursion', '-cf', '-', '--', ...names,
  ], { cwd: stage, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, TAR_OPTIONS: '', LC_ALL: 'C' } });
  tar.stderr.resume();
  const completion = new Promise((resolve, reject) => {
    tar.once('error', reject);
    tar.once('close', code => code === 0 ? resolve() : reject(new Error('Native tar creation failed')));
  });
  // Always observe child failure while the stream pipeline is running.
  completion.catch(() => {});
  try {
    await pipeline(tar.stdout, createGzip({ level: 9 }), async function (chunks) {
      for await (const bytes of chunks) {
        size += bytes.length;
        if (size > MAX_ARCHIVE_BYTES) throw new Error('Native archive exceeds size limit');
        digest.update(bytes);
        await output.writeFile(bytes);
      }
    });
    await completion;
    await output.chmod(0o644);
    await output.sync();
    return digest.digest('hex');
  } finally {
    if (tar.exitCode === null) tar.kill('SIGTERM');
    await completion.catch(() => {});
    await output.close();
  }
}

// BIN_DIR is copied from /usr/local/bin of a stopped, just-built image by CI.
// OUT_DIR is created under an existing parent. Nothing runs a packaged program.
export async function packageNativeRelease(artifactPath, binDir, outDir) {
  if (process.platform !== 'linux') throw new Error('Native packaging requires Linux and GNU tar');
  const handles = [];
  let lock;
  let stage;
  let outputRoot;
  const published = [];
  try {
    const open = async directory => {
      const handle = await openDirectory(directory);
      handles.push(handle);
      return fdPath(handle);
    };
    const artifactRoot = await open(path.dirname(path.resolve(artifactPath)));
    const { handle: input } = await regularSource(`${artifactRoot}/${path.basename(artifactPath)}`, MAX_HELPER_BYTES);
    let raw;
    try {
      const bytes = Buffer.alloc(MAX_HELPER_BYTES + 1);
      let length = 0;
      for (;;) {
        const { bytesRead } = await input.read(bytes, length, bytes.length - length, null);
        if (!bytesRead) break;
        length += bytesRead;
        if (length > MAX_HELPER_BYTES) throw new Error('Release artifact too large');
      }
      raw = JSON.parse(bytes.subarray(0, length).toString('utf8'));
    } finally { await input.close(); }
    const artifact = validateArtifact(raw);
    if (artifact.component !== 'heteronetwork' || artifact.native !== undefined || artifact.version.length > 128 ||
        !/^ghcr\.io\/ipa-cyberlab\/heteronetwork@sha256:[a-f0-9]{64}$/.test(artifact.image)) {
      throw new Error('Expected an unextended heteronetwork image release artifact');
    }
    const asset = `heteronetwork-${artifact.version.replace(/^v/, '')}-linux-amd64.tar.gz`;
    const binaries = await open(binDir);
    const helpers = await open(scriptDir);
    const outputParent = await open(path.dirname(path.resolve(outDir)));
    const outputName = `${outputParent}/${path.basename(path.resolve(outDir))}`;
    try { await fs.mkdir(outputName, { mode: 0o755 }); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    const outputDirectory = await fs.open(outputName, readFlags | constants.O_DIRECTORY);
    handles.push(outputDirectory);
    outputRoot = fdPath(outputDirectory);
    lock = await fs.open(`${outputRoot}/.native-release.lock`, 'wx', 0o600);
    for (const name of [asset, MANIFEST_NAME]) {
      try {
        await fs.lstat(`${outputRoot}/${name}`);
        throw new Error('Refusing to overwrite existing native release output');
      } catch (error) { if (error.code !== 'ENOENT') throw error; }
    }
    stage = await fs.mkdtemp(`${outputRoot}/.native-release-`);
    await fs.mkdir(`${stage}/bin`);
    await fs.mkdir(`${stage}/libexec`);
    const sources = [
      ...BINARIES.map(name => [`bin/${name}`, `${binaries}/${name}`, true]),
      ...HELPERS.map(name => [`libexec/${name}`, `${helpers}/${name}`, false]),
    ].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
    if (sources.length > 64) throw new Error('Too many native release files');
    const files = {};
    let total = 0;
    for (const [name, source, binary] of sources) {
      if (!/^(bin\/(ipars|iparsd|ipars-k8s-controller)|libexec\/[a-z][a-z0-9-]*\.sh)$/.test(name)) {
        throw new Error('Unreviewed native release path');
      }
      const copied = await copySource(source, `${stage}/${name}`, binary);
      total += copied.size;
      if (total > MAX_TOTAL_BYTES) throw new Error('Native release exceeds total size limit');
      files[name] = copied.sha256;
    }
    const sha256 = await archiveFiles(stage, Object.keys(files), `${stage}/${asset}`);
    const result = validateArtifact({ ...artifact, native: { 'linux-amd64': { asset, sha256, files } } });
    const manifestOutput = await fs.open(`${stage}/${MANIFEST_NAME}`, 'wx', 0o644);
    try {
      await manifestOutput.writeFile(`${JSON.stringify(result, null, 2)}\n`);
      await manifestOutput.sync();
    } finally { await manifestOutput.close(); }
    // Exclusive hard-link publication cannot replace an existing file or symlink.
    // Publish the manifest last, so it never advertises an absent archive.
    for (const name of [asset, MANIFEST_NAME]) {
      await fs.link(`${stage}/${name}`, `${outputRoot}/${name}`);
      published.push(name);
    }
    await outputDirectory.sync();
    return result;
  } catch (error) {
    for (const name of published.reverse()) await fs.unlink(`${outputRoot}/${name}`);
    throw error;
  } finally {
    if (stage) await fs.rm(stage, { recursive: true, force: true });
    if (lock) {
      await lock.close();
      await fs.unlink(`${outputRoot}/.native-release.lock`);
    }
    for (const handle of handles.reverse()) await handle.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const args = process.argv.slice(2);
  if (args.length !== 3) {
    console.error('Usage: node scripts/package-native-release.mjs RELEASE_ARTIFACT.json BIN_DIR OUT_DIR');
    process.exitCode = 1;
  } else {
    packageNativeRelease(...args).then(result => console.log(result.native['linux-amd64'].asset))
      .catch(error => { console.error(`Native packaging: ${error.message}`); process.exitCode = 1; });
  }
}
