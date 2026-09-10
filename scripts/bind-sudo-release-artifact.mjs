#!/usr/bin/env node
import fs, { constants } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { validateArtifact } from './release-channels.mjs';

const tool = fileURLToPath(new URL('./sudo-quorum-v2-artifact.py', import.meta.url));
async function readBounded(filename, maximum) {
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size <= 0 || before.size > maximum) {
      throw new Error('Expected bounded single-link regular artifact input');
    }
    const bytes = Buffer.alloc(before.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const {bytesRead} = await handle.read(bytes, length, bytes.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    const after = await handle.stat();
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error('Artifact input changed');
    }
    return bytes.subarray(0, length);
  } finally { await handle.close(); }
}

export function bindContract(base, record) {
  const artifact = validateArtifact(base);
  if (artifact.component !== 'heteronetwork' || artifact.sudo_native !== undefined) {
    throw new Error('Expected HeteroNetwork artifact without existing sudo binding');
  }
  return validateArtifact({...artifact, sudo_native: {'linux-amd64': record}});
}

function verifySudo(artifact, archive) {
  const record = artifact.sudo_native?.['linux-amd64'];
  if (!record || path.basename(archive) !== record.asset) throw new Error('Missing/misnamed sudo archive');
  // Reuse the bounded archive/ELF/manifest validator; never extract or execute payloads.
  const actual = JSON.parse(execFileSync('python3', ['-B', '-c', `
import importlib.util,json,sys
s=importlib.util.spec_from_file_location('sudo_artifact',sys.argv[1])
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
data=m.regular(sys.argv[2],m.MAX_TOTAL)
print(json.dumps(m.release_contract(data,sys.argv[3],sys.argv[4])))
`, tool, archive, artifact.commit, artifact.version], {encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024}));
  if (!isDeepStrictEqual(record, actual)) throw new Error('Sudo archive does not match catalog binding');
}

export async function bindFiles(baseFile, contractFile, archive, output) {
  const base = JSON.parse(await readBounded(baseFile, 1024 * 1024));
  const record = JSON.parse(await readBounded(contractFile, 65536));
  const artifact = bindContract(base, record);
  verifySudo(artifact, archive);
  await fs.writeFile(output, `${JSON.stringify(artifact, null, 2)}\n`, {flag: 'wx', mode: 0o644});
  return artifact;
}

export async function verifyFiles(catalog, sudoArchive, nativeArchive) {
  const artifact = validateArtifact(JSON.parse(await readBounded(catalog, 1024 * 1024)));
  verifySudo(artifact, sudoArchive);
  const native = artifact.native?.['linux-amd64'];
  if (!native || path.basename(nativeArchive) !== native.asset) throw new Error('Missing/misnamed native archive');
  const bytes = await readBounded(nativeArchive, 512 * 1024 * 1024);
  if (createHash('sha256').update(bytes).digest('hex') !== native.sha256) throw new Error('Native archive digest mismatch');
  return artifact;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const [command, ...args] = process.argv.slice(2);
  const operation = command === 'bind' && args.length === 4 ? bindFiles(...args)
    : command === 'verify' && args.length === 3 ? verifyFiles(...args)
    : Promise.reject(new Error('Usage: bind BASE.json CONTRACT.json SUDO_ARCHIVE OUTPUT.json | verify CATALOG.json SUDO_ARCHIVE NATIVE_ARCHIVE'));
  operation.then(() => console.log('Validated release binding; no publication or activation.'))
    .catch(error => { console.error(error.message); process.exitCode = 1; });
}
