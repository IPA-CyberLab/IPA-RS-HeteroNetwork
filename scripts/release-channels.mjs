#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const components = new Set(['heteronetwork', 'heterocloud', 'flow', 'flash', 'syouyu']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;
const same = (a, b) => a && b && JSON.stringify(validateArtifact(a)) === JSON.stringify(validateArtifact(b));
export function validateArtifact(value) {
  if (!value || value.schema_version !== 1 || !components.has(value.component) ||
      typeof value.version !== 'string' || !/^v?\d+\.\d+\.\d+(?:[.-][A-Za-z0-9._-]+)?$/.test(value.version) ||
      typeof value.commit !== 'string' || !/^[a-f0-9]{40}$/.test(value.commit) ||
      typeof value.image !== 'string' ||
      !/^ghcr\.io\/ipa-cyberlab\/[a-z0-9._/-]+@sha256:[a-f0-9]{64}$/.test(value.image)) {
    throw new Error('Invalid immutable release artifact');
  }
  const artifact = Object.fromEntries(['schema_version', 'component', 'version', 'commit', 'image'].map(k => [k, value[k]]));
  if (value.native !== undefined) {
    if (value.component !== 'heteronetwork' ||
        !/^ghcr\.io\/ipa-cyberlab\/heteronetwork@sha256:[a-f0-9]{64}$/.test(value.image) ||
        !object(value.native) ||
        Object.keys(value.native).length !== 1 || !object(value.native['linux-amd64'])) {
      throw new Error('Unsupported native artifact platform');
    }
    const bundle = value.native['linux-amd64'];
    const expectedAsset = `heteronetwork-${value.version.replace(/^v/, '')}-linux-amd64.tar.gz`;
    if (bundle.asset !== expectedAsset || !/^[a-f0-9]{64}$/.test(bundle.sha256 ?? '') ||
        !object(bundle.files) || Object.keys(bundle.files).length > 64 ||
        ['bin/ipars', 'bin/iparsd', 'bin/ipars-k8s-controller'].some(name => !Object.hasOwn(bundle.files, name))) {
      throw new Error('Invalid native artifact manifest');
    }
    const files = {};
    for (const name of Object.keys(bundle.files).sort()) {
      if (!/^(bin\/(ipars|iparsd|ipars-k8s-controller)|libexec\/[a-z][a-z0-9-]*\.sh)$/.test(name) ||
          typeof bundle.files[name] !== 'string' || !/^[a-f0-9]{64}$/.test(bundle.files[name])) {
        throw new Error('Invalid native artifact file');
      }
      files[name] = bundle.files[name];
    }
    artifact.native = {'linux-amd64': {asset: expectedAsset, sha256: bundle.sha256, files}};
  }
  return artifact;
}

export function transition(state, command, artifact, expectedRevision) {
  if (!object(state) || state.schema_version !== 1 || !Number.isSafeInteger(state.revision) || state.revision < 0 ||
      !object(state.dev) || !object(state.prod) || !Array.isArray(state.history) || state.history.length !== state.revision) {
    throw new Error('Invalid release channel state');
  }
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision !== state.revision) {
    throw new Error('Release revision changed; inspect the current state before retrying');
  }
  for (const channel of ['dev', 'prod']) {
    for (const [component, current] of Object.entries(state[channel])) {
      if (validateArtifact(current).component !== component) throw new Error('Invalid component mapping');
    }
  }
  const replay = {dev: {}, prod: {}};
  const promoted = [];
  for (const [index, entry] of state.history.entries()) {
    if (!object(entry) || entry.revision !== index + 1 ||
        !['stage', 'promote', 'rollback'].includes(entry.command) ||
        entry.channel !== (entry.command === 'stage' ? 'dev' : 'prod') ||
        typeof entry.at !== 'string' || !Number.isFinite(Date.parse(entry.at))) {
      throw new Error('Invalid release history');
    }
    const after = validateArtifact(entry.after);
    if (entry.component !== after.component) throw new Error('Invalid history component');
    const before = replay[entry.channel][entry.component] ?? null;
    if (before === null ? entry.before !== null : !same(before, entry.before)) {
      throw new Error('Broken release history chain');
    }
    if (entry.command === 'promote' && !same(replay.dev[entry.component], after)) {
      throw new Error('History contains an unstaged promotion');
    }
    if (entry.command === 'rollback' && !promoted.some(previous => same(previous, after))) {
      throw new Error('History contains an unknown rollback');
    }
    replay[entry.channel][entry.component] = after;
    if (entry.command === 'promote') promoted.push(after);
  }
  for (const channel of ['dev', 'prod']) {
    if (Object.keys(replay[channel]).length !== Object.keys(state[channel]).length ||
        Object.entries(replay[channel]).some(([component, value]) => !same(value, state[channel][component]))) {
      throw new Error('Release selections do not match their history');
    }
  }
  if (!['stage', 'promote', 'rollback'].includes(command)) throw new Error('Unknown release command');
  const selected = validateArtifact(artifact);
  const component = selected.component;
  const channel = command === 'stage' ? 'dev' : 'prod';
  if (command === 'promote' && !same(state.dev[component], selected)) {
    throw new Error('Production must use the exact artifact currently staged in dev');
  }
  if (command === 'rollback' && !promoted.some(previous => same(previous, selected))) {
    throw new Error('Rollback target has never been promoted to production');
  }
  if (same(state[channel][component], selected)) return state;
  const next = structuredClone(state);
  next.revision++;
  next[channel][component] = selected;
  next.history.push({revision: next.revision, command, channel, component,
    before: state[channel][component] ?? null, after: selected, at: new Date().toISOString()});
  return next;
}

export async function updateChannels(filename, command, artifact, revision) {
  const target = path.resolve(filename);
  // The lock covers reading and renaming, so concurrent writers cannot both pass the revision check.
  const lockPath = `${target}.lock`;
  const lock = await fs.open(lockPath, 'wx', 0o600);
  const temporary = `${target}.${process.pid}.tmp`;
  let created = false;
  try {
    let state;
    try {
      const info = await fs.lstat(target);
      if (!info.isFile() || info.size > 16 * 1024 * 1024) throw new Error('Invalid channel file');
      state = JSON.parse(await fs.readFile(target, 'utf8'));
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      state = {schema_version: 1, revision: 0, dev: {}, prod: {}, history: []};
    }
    const next = transition(state, command, artifact, revision);
    if (next === state) return next;
    const output = await fs.open(temporary, 'wx', 0o644);
    created = true;
    try { await output.writeFile(`${JSON.stringify(next, null, 2)}\n`); await output.sync(); }
    finally { await output.close(); }
    await fs.rename(temporary, target);
    return next;
  } finally {
    if (created) await fs.rm(temporary, {force: true});
    await lock.close();
    await fs.unlink(lockPath);
  }
}

async function main() {
  const [command, filename, artifactPath, rawRevision, ...extra] = process.argv.slice(2);
  if (!['stage', 'promote', 'rollback'].includes(command) || !filename || !artifactPath ||
      !/^(0|[1-9][0-9]*)$/.test(rawRevision ?? '') || extra.length) {
    throw new Error('Usage: node scripts/release-channels.mjs stage|promote|rollback CHANNELS.json ARTIFACT.json EXPECTED_REVISION');
  }
  const artifact = JSON.parse(await fs.readFile(artifactPath, 'utf8'));
  const state = await updateChannels(filename, command, artifact, Number(rawRevision));
  console.log(`Release channels revision ${state.revision}; no deployment performed.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}
