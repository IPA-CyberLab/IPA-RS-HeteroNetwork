import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { checkedOutRelease, createManifest, validateRelease } from './release-artifact-manifest.mjs';

const commit = 'a'.repeat(40);
const release = { tag: 'v1.2.3-rc.1', commit, head: commit, tagCommit: commit };
const repository = 'ghcr.io/ipa-cyberlab/heteronetwork';
const image = `${repository}@sha256:${'b'.repeat(64)}`;

test('stable and prerelease artifacts share the same environment-neutral schema', () => {
  for (const tag of ['v1.2.3-rc.1', 'v1.2.3', '1.2.3']) {
    assert.deepEqual(createManifest({ ...release, tag }, repository, [image]), {
      schema_version: 1, component: 'heteronetwork', version: tag.replace(/^v/, ''), commit, image,
    });
  }
});

test('rejects malformed tags and abbreviated or mismatched commits', () => {
  for (const tag of ['latest', '--help', 'v1.2.3\n', 'v1.2.3;echo', 'v1.2.3/' , `v1.2.3-${'x'.repeat(128)}`]) {
    assert.throws(() => validateRelease({ ...release, tag }));
  }
  for (const field of ['commit', 'head', 'tagCommit']) {
    for (const value of ['a'.repeat(7), 'b'.repeat(40), undefined]) {
      assert.throws(() => validateRelease({ ...release, [field]: value }));
    }
  }
});

test('requires an unambiguous sha256 digest for the expected repository', () => {
  for (const digests of [null, {}, [], [42], [`${repository}:latest`], ['other/image@sha256:' + 'b'.repeat(64)],
    [`${repository}@sha256:abc`], [image, `${repository}@sha256:${'c'.repeat(64)}`]]) {
    assert.throws(() => createManifest(release, repository, digests));
  }
  assert.throws(() => createManifest(release, `${repository}:latest`, [image]));
  assert.equal(createManifest(release, repository, [image, image]).image, image);
});

test('resolves exact lightweight and annotated tags and rejects a moved HEAD', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'release-artifact-test-'));
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  try {
    git('init');
    git('config', 'user.name', 'Release Test');
    git('config', 'user.email', 'release-test@users.noreply.github.com');
    git('-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-m', 'fixture');
    const sha = git('rev-parse', 'HEAD');
    git('tag', 'v1.2.3');
    git('-c', 'tag.gpgsign=false', 'tag', '-a', 'v1.2.4', '-m', 'annotated');
    for (const tag of ['v1.2.3', 'v1.2.4']) {
      assert.equal(checkedOutRelease({ RELEASE_TAG: tag, GITHUB_SHA: sha }, cwd).tagCommit, sha);
    }
    const digestsPath = join(cwd, 'digests.json');
    writeFileSync(digestsPath, JSON.stringify([image]));
    const output = execFileSync(process.execPath, [fileURLToPath(new URL('./release-artifact-manifest.mjs', import.meta.url)), 'generate'], {
      cwd, encoding: 'utf8', env: { ...process.env, RELEASE_TAG: 'v1.2.4', GITHUB_SHA: sha, IMAGE: repository, REPO_DIGESTS_FILE: digestsPath },
    });
    assert.deepEqual(JSON.parse(output), {
      schema_version: 1, component: 'heteronetwork', version: '1.2.4', commit: sha, image,
    });
    git('-c', 'commit.gpgsign=false', 'commit', '--allow-empty', '-m', 'different commit');
    assert.throws(() => checkedOutRelease({ RELEASE_TAG: 'v1.2.3', GITHUB_SHA: sha }, cwd));
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
