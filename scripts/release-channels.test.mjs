import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {transition, updateChannels, validateArtifact, SUDO_PLUGIN_HEADER_SHA256} from './release-channels.mjs';

const artifact = {schema_version: 1, component: 'heteronetwork', version: '1.2.3',
  commit: 'a'.repeat(40), image: `ghcr.io/ipa-cyberlab/heteronetwork@sha256:${'b'.repeat(64)}`};
const empty = () => ({schema_version: 1, revision: 0, dev: {}, prod: {}, history: []});

// Synthetic bytes are used only for contract tests, never deployment selections.
const sudoBundle = () => ({'linux-amd64': {
  asset: 'heteronetwork-1.2.3-sudo-v2-linux-amd64.tar.gz', sha256: 'c'.repeat(64),
  source_commit: artifact.commit, profile: 'release', plugin_header_sha256: SUDO_PLUGIN_HEADER_SHA256,
  files: {
    'bin/local-sudo-v2': {sha256: 'd'.repeat(64), size: 1024, mode: 0o755},
    'lib/quorum_v2_gate.so': {sha256: 'e'.repeat(64), size: 512, mode: 0o644},
    'NOT_ENABLED.txt': {sha256: 'f'.repeat(64), size: 128, mode: 0o644},
  },
}});

test('sudo archive and payload identity are retained across stage, promotion and rollback', () => {
  const release = {...artifact, sudo_native: sudoBundle()};
  let state = transition(empty(), 'stage', release, 0);
  assert.deepEqual(state.dev.heteronetwork.sudo_native, release.sudo_native);
  assert.throws(() => transition(state, 'promote', artifact, 1));
  for (const field of ['archive', 'size']) {
    const invalid = structuredClone(release);
    const bundle = invalid.sudo_native['linux-amd64'];
    if (field === 'archive') bundle.sha256 = 'a'.repeat(64);
    else bundle.files['bin/local-sudo-v2'].size++;
    assert.throws(() => transition(state, 'promote', invalid, 1));
  }
  const changed = structuredClone(release);
  changed.sudo_native['linux-amd64'].files['lib/quorum_v2_gate.so'].sha256 = 'a'.repeat(64);
  assert.throws(() => transition(state, 'promote', changed, 1));
  state = transition(state, 'promote', release, 1);
  assert.throws(() => transition(state, 'rollback', changed, 2));
  state = transition(state, 'stage', changed, 2);
  state = transition(state, 'promote', changed, 3);
  state = transition(state, 'rollback', release, 4);
  assert.deepEqual(state.prod.heteronetwork.sudo_native, release.sudo_native);
  const tampered = structuredClone(state);
  tampered.history[0].after.sudo_native = changed.sudo_native;
  assert.throws(() => transition(tampered, 'stage', changed, 5));
});

test('sudo bindings reject development builds, unrelated commits, ABI drift and unsafe metadata', () => {
  const release = {...artifact, sudo_native: sudoBundle()};
  for (const patch of [{profile: 'dev'}, {source_commit: 'b'.repeat(40)},
    {plugin_header_sha256: 'b'.repeat(64)}, {asset: '../sudo.tar.gz'}, {sha256: 'latest'},
    {enabled: true}, {files: {}}, {files: []}]) {
    const invalid = structuredClone(release);
    Object.assign(invalid.sudo_native['linux-amd64'], patch);
    assert.throws(() => validateArtifact(invalid));
  }
  for (const patch of [{size: 0}, {size: 1.5}, {size: 300 * 1024 * 1024},
    {sha256: 'bad'}, {mode: 0o4755}, {unknown: true}]) {
    const invalid = structuredClone(release);
    Object.assign(invalid.sudo_native['linux-amd64'].files['bin/local-sudo-v2'], patch);
    assert.throws(() => validateArtifact(invalid));
  }
  assert.throws(() => validateArtifact({...release, component: 'flash'}));
  assert.throws(() => validateArtifact({...release, image: artifact.image.replace('heteronetwork@', 'unrelated@')}));
  assert.throws(() => validateArtifact({...release, sudo_native: {...sudoBundle(), 'linux-arm64': {}}}));
  const noNotice = structuredClone(release);
  delete noNotice.sudo_native['linux-amd64'].files['NOT_ENABLED.txt'];
  assert.throws(() => validateArtifact(noNotice));
});

test('Flow promotion and rollback bind the LiveKit companion as well as the primary image', () => {
  const flow = {...artifact, component: 'flow',
    image: `ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow@sha256:${'b'.repeat(64)}`,
    companions: {livekit: {image: `ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flow-livekit@sha256:${'c'.repeat(64)}`}}};
  let state = transition(empty(), 'stage', flow, 0);
  assert.deepEqual(state.dev.flow.companions, flow.companions);
  const changed = structuredClone(flow);
  changed.companions.livekit.image = changed.companions.livekit.image.replace(/c{64}$/, 'd'.repeat(64));
  assert.throws(() => transition(state, 'promote', changed, 1));
  state = transition(state, 'promote', flow, 1);
  assert.throws(() => transition(state, 'rollback', changed, 2));
  state = transition(state, 'stage', changed, 2);
  assert.deepEqual(state.prod.flow.companions, flow.companions);
  state = transition(state, 'promote', changed, 3);
  state = transition(state, 'rollback', flow, 4);
  assert.deepEqual(state.prod.flow.companions, flow.companions);
  assert.deepEqual(state.dev.flow.companions, changed.companions);
  const tampered = structuredClone(state);
  tampered.history[0].after.companions = changed.companions;
  assert.throws(() => transition(tampered, 'stage', changed, 5));
  for (const companions of [undefined, {}, [], {livekit: {image: 'latest'}},
    {livekit: {image: flow.image}}, {...flow.companions, unknown: {}},
    {livekit: {...flow.companions.livekit, version: 'other'}}]) {
    assert.throws(() => validateArtifact({...flow, companions}));
  }
  assert.throws(() => validateArtifact({...artifact, companions: flow.companions}));
});

test('production accepts only exact staged artifact; staging does not affect production', () => {
  assert.throws(() => transition(empty(), 'promote', artifact, 0));
  const dev = transition(empty(), 'stage', artifact, 0);
  assert.deepEqual(dev.prod, {});
  assert.throws(() => transition(dev, 'promote', {...artifact, commit: 'c'.repeat(40)}, 1));
  const prod = transition(dev, 'promote', artifact, 1);
  assert.deepEqual(prod.prod.heteronetwork, artifact);
  assert.equal(transition(prod, 'promote', artifact, 2), prod);
  assert.throws(() => transition(prod, 'stage', artifact, 0));
});

test('rollback is restricted to previously promoted artifacts', () => {
  let state = transition(empty(), 'stage', artifact, 0);
  assert.throws(() => transition(state, 'rollback', artifact, 1));
  state = transition(state, 'promote', artifact, 1);
  const newer = {...artifact, version: '1.2.4',
    image: `ghcr.io/ipa-cyberlab/heteronetwork@sha256:${'c'.repeat(64)}`};
  state = transition(state, 'stage', newer, 2);
  state = transition(state, 'promote', newer, 3);
  state = transition(state, 'rollback', artifact, 4);
  assert.deepEqual(state.prod.heteronetwork, artifact);
  assert.deepEqual(state.dev.heteronetwork, newer);
});

test('mutable image references and invalid fields fail closed', () => {
  for (const change of [{image: 'ghcr.io/ipa-cyberlab/heteronetwork:latest'},
    {commit: '1234567'}, {component: '__proto__'}, {version: '../prod'}]) {
    assert.throws(() => validateArtifact({...artifact, ...change}));
  }
});

test('malformed maps and contradictory histories fail closed', () => {
  assert.throws(() => transition({...empty(), dev: []}, 'stage', artifact, 0));
  const state = transition(transition(empty(), 'stage', artifact, 0), 'promote', artifact, 1);
  for (const patch of [{command: 'stage'}, {revision: 9}, {component: 'flow'}, {before: artifact}]) {
    const broken = structuredClone(state);
    Object.assign(broken.history[1], patch);
    assert.throws(() => transition(broken, 'rollback', artifact, 2));
  }
  const missing = structuredClone(state);
  delete missing.prod.heteronetwork;
  assert.throws(() => transition(missing, 'rollback', artifact, 2));
});

test('native checksums are retained and bound to promotion', () => {
  const native = {'linux-amd64': {asset: 'heteronetwork-1.2.3-linux-amd64.tar.gz',
    sha256: 'c'.repeat(64), files: {'bin/ipars': 'd'.repeat(64), 'bin/iparsd': 'e'.repeat(64),
      'bin/ipars-k8s-controller': 'f'.repeat(64)}}};
  const release = {...artifact, native};
  const state = transition(empty(), 'stage', release, 0);
  assert.deepEqual(state.dev.heteronetwork.native, native);
  const changed = structuredClone(release);
  changed.native['linux-amd64'].sha256 = 'a'.repeat(64);
  assert.throws(() => transition(state, 'promote', changed, 1));
  assert.throws(() => transition(state, 'promote', artifact, 1));
  assert.deepEqual(transition(state, 'promote', release, 1).prod.heteronetwork.native, native);
  assert.throws(() => validateArtifact({...release,
    image: `ghcr.io/ipa-cyberlab/unrelated@sha256:${'a'.repeat(64)}`}));
  changed.native['linux-amd64'].files['../outside'] = 'a'.repeat(64);
  assert.throws(() => validateArtifact(changed));
});

test('file update is idempotent and rejects competing lock or symlink', async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'release-channels-'));
  try {
    const filename = path.join(root, 'channels.json');
    await updateChannels(filename, 'stage', artifact, 0);
    await updateChannels(filename, 'stage', artifact, 1);
    assert.equal(JSON.parse(await fs.readFile(filename, 'utf8')).revision, 1);
    await fs.writeFile(`${filename}.lock`, '');
    await assert.rejects(updateChannels(filename, 'promote', artifact, 1));
    await fs.unlink(`${filename}.lock`);
    const link = path.join(root, 'link.json');
    await fs.symlink(filename, link);
    await assert.rejects(updateChannels(link, 'promote', artifact, 1));
  } finally { await fs.rm(root, {recursive: true, force: true}); }
});
