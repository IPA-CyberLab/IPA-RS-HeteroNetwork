import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { bindContract, bindFiles, verifyFiles } from './bind-sudo-release-artifact.mjs';
import { validateArtifact } from './release-channels.mjs';
import { packageNativeRelease, BINARIES } from './package-native-release.mjs';

const tool = fileURLToPath(new URL('./sudo-quorum-v2-artifact.py', import.meta.url));
const base = {schema_version: 1, component: 'heteronetwork', version: '1.2.3-dev.1',
  commit: 'a'.repeat(40), image: `ghcr.io/ipa-cyberlab/heteronetwork@sha256:${'b'.repeat(64)}`};
const fixture = `
import importlib.util,json,pathlib,struct,sys
s=importlib.util.spec_from_file_location('artifact',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
elf=bytearray(64);elf[:7]=b'\\x7fELF\\x02\\x01\\x01';struct.pack_into('<HHI',elf,16,3,62,1);struct.pack_into('<H',elf,52,64)
p={'bin/local-sudo-v2':bytes(elf),'lib/quorum_v2_gate.so':bytes(elf),'NOT_ENABLED.txt':m.NOTE}
manifest=m.manifest_for(p,{'source_commit':'a'*40,'source_dirty':False,'profile':'release','ack_regression':'passed'},'linux-amd64')
archive=m.encode_archive(p,manifest);record=m.release_contract(archive,'a'*40,sys.argv[3])
out=pathlib.Path(sys.argv[2]);(out/record['asset']).write_bytes(archive);(out/'contract.json').write_text(json.dumps(record))
(out/'elf-fixture').write_bytes(elf)
`;

test('actual emitter contract binds, survives native metadata, verifies bytes and refuses overwrite', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sudo-binding-test-'));
  try {
    // Synthetic ELF fixture is never executed; all archive/payload digests are computed.
    execFileSync('python3', ['-B', '-c', fixture, tool, dir, 'v1.2.3-dev.1']);
    const record = JSON.parse(await fs.readFile(path.join(dir, 'contract.json'), 'utf8'));
    const archive = path.join(dir, record.asset);
    const input = path.join(dir, 'base.json');
    const output = path.join(dir, 'bound.json');
    await fs.writeFile(input, JSON.stringify(base));
    const bound = await bindFiles(input, path.join(dir, 'contract.json'), archive, output);
    assert.deepEqual(validateArtifact(bound).sudo_native['linux-amd64'], record);
    await assert.rejects(bindFiles(input, path.join(dir, 'contract.json'), archive, output), /EEXIST/);
    const binDir = path.join(dir, 'bins');
    await fs.mkdir(binDir);
    for (const binary of BINARIES) await fs.copyFile(path.join(dir, 'elf-fixture'), path.join(binDir, binary));
    const nativeDir = path.join(dir, 'native');
    const final = await packageNativeRelease(output, binDir, nativeDir);
    assert.deepEqual(final.sudo_native, bound.sudo_native);
    const nativeArchive = path.join(nativeDir, final.native['linux-amd64'].asset);
    const catalog = path.join(nativeDir, 'heteronetwork-release-artifact.json');
    await verifyFiles(catalog, archive, nativeArchive);
    await fs.appendFile(nativeArchive, 'tamper');
    await assert.rejects(verifyFiles(catalog, archive, nativeArchive), /digest mismatch/);
    for (const change of [{source_commit: 'c'.repeat(40)}, {profile: 'dev'}, {extra: 1},
      {asset: '../bad'}, {plugin_header_sha256: '0'.repeat(64)}]) {
      assert.throws(() => bindContract(base, {...record, ...change}));
    }
    assert.throws(() => bindContract(bound, record), /existing sudo/);
    assert.throws(() => bindContract({...base, component: 'flash'}, record));
    const wrong = {...record, sha256: '0'.repeat(64)};
    await fs.writeFile(path.join(dir, 'wrong.json'), JSON.stringify(wrong));
    await assert.rejects(bindFiles(input, path.join(dir, 'wrong.json'), archive, path.join(dir, 'bad.json')), /does not match/);
    await assert.rejects(fs.stat(path.join(dir, 'bad.json')), /ENOENT/);
    await fs.symlink(input, path.join(dir, 'link.json'));
    await assert.rejects(bindFiles(path.join(dir, 'link.json'), path.join(dir, 'contract.json'), archive, output));
  } finally { await fs.rm(dir, {recursive: true, force: true}); }
});

test('emitter rejects build metadata before emitting catalog-incompatible contract', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sudo-version-test-'));
  try {
    assert.throws(() => execFileSync('python3', ['-B', '-c', fixture, tool, dir, '1.2.3+build.1'], {stdio: 'pipe'}));
    assert.deepEqual(await fs.readdir(dir), []);
  } finally { await fs.rm(dir, {recursive: true, force: true}); }
});
