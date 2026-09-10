import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const commitPattern = /^[0-9a-f]{40}$/;
const tagPattern = /^v?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9._-]+)?$/;

export function validateRelease({ tag, commit, head, tagCommit }) {
  if (typeof tag !== 'string' || tag.length > 128 || !tagPattern.test(tag)) {
    throw new Error('Unsupported release tag');
  }
  if (![commit, head, tagCommit].every(value => typeof value === 'string' && commitPattern.test(value))) {
    throw new Error('Release commits must be full lowercase 40-character SHA values');
  }
  if (commit !== head || commit !== tagCommit) {
    throw new Error('Release event, checked-out HEAD, and exact release tag must match');
  }
  return tag.replace(/^v/, '');
}

export function createManifest(release, repository, repoDigests) {
  const version = validateRelease(release);
  if (typeof repository !== 'string' || !/^[a-z0-9.-]+(?::[0-9]+)?\/[a-z0-9._/-]+$/.test(repository)) {
    throw new Error('Expected an untagged image repository');
  }
  if (!Array.isArray(repoDigests) || !repoDigests.every(value => typeof value === 'string')) {
    throw new Error('RepoDigests must be a JSON array of strings');
  }
  const candidates = [...new Set(repoDigests.filter(value => value.startsWith(`${repository}@`)))];
  if (candidates.length !== 1 || !/^sha256:[0-9a-f]{64}$/.test(candidates[0].slice(repository.length + 1))) {
    throw new Error('Expected exactly one pushed sha256 RepoDigest for the image repository');
  }
  return { schema_version: 1, component: 'heteronetwork', version, commit: release.commit, image: candidates[0] };
}

export function checkedOutRelease(env = process.env, cwd = process.cwd()) {
  // Validate before constructing the fully qualified ref passed to git.
  validateRelease({ tag: env.RELEASE_TAG, commit: env.GITHUB_SHA, head: env.GITHUB_SHA, tagCommit: env.GITHUB_SHA });
  const rev = ref => execFileSync('git', ['rev-parse', '--verify', ref], { cwd, encoding: 'utf8' }).trim();
  const release = {
    tag: env.RELEASE_TAG,
    commit: env.GITHUB_SHA,
    head: rev('HEAD^{commit}'),
    tagCommit: rev(`refs/tags/${env.RELEASE_TAG}^{commit}`),
  };
  validateRelease(release);
  return release;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const command = process.argv[2];
    if (process.argv.length !== 3 || !['validate', 'generate'].includes(command)) {
      throw new Error('Usage: node scripts/release-artifact-manifest.mjs validate|generate');
    }
    const release = checkedOutRelease();
    if (command === 'generate') {
      const digests = JSON.parse(readFileSync(process.env.REPO_DIGESTS_FILE, 'utf8'));
      process.stdout.write(`${JSON.stringify(createManifest(release, process.env.IMAGE, digests), null, 2)}\n`);
    }
  } catch (error) {
    console.error(`Release artifact: ${error.message}`);
    process.exitCode = 1;
  }
}
