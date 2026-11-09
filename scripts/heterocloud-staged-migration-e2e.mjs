// Disposable database and credentials only. This does not connect to production.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const image = process.env.HC_TEST_IMAGE;
const source = process.env.HC_TEST_SOURCE;
const temporary = process.env.RUNNER_TEMP;
assert.match(image ?? '', /^ghcr\.io\/ipa-cyberlab\/ipa-rs-heterocloud@sha256:[a-f0-9]{64}$/);
assert.ok(source && temporary);
const migration = readFileSync(join(source, 'migrations', '0036_flash_cost_budgets.sql'), 'utf8');
const checksum = createHash('sha384').update(migration).digest('hex');
const secrets = join(temporary, 'hc-stage-secrets');
mkdirSync(secrets, { mode: 0o755 });
chmodSync(secrets, 0o755); // The unprivileged container reads these disposable fixture files.
const write = (name, content) => writeFileSync(join(secrets, name), content, { mode: 0o644 });
write('database-url', 'postgres://hc_test:fixture-only@127.0.0.1:5432/heterocloud_test_stage');
write('csrf', 'fixture-csrf-key-with-more-than-32-bytes');
write('flow', 'fixture-flow-key-with-more-than-32-bytes');
write('syouyu', 'fixture-syouyu-key-with-more-than-32-bytes');
write('password', 'fixture-only-password');
execFileSync('openssl', ['genpkey', '-algorithm', 'ED25519', '-out', join(secrets, 'provider.pem')]);
chmodSync(join(secrets, 'provider.pem'), 0o644);
const origin = 'http://127.0.0.1:18080';
const env = {
  HETEROCLOUD_LISTEN: '127.0.0.1:18080',
  HETEROCLOUD_DATABASE_URL_FILE: '/run/fixture/database-url',
  HETEROCLOUD_CSRF_KEY_FILE: '/run/fixture/csrf',
  HETEROCLOUD_FLOW_ACCESS_SECRET_FILE: '/run/fixture/flow',
  HETEROCLOUD_SYOUYU_ACCESS_SECRET_FILE: '/run/fixture/syouyu',
  HETEROCLOUD_PROVIDER_SIGNING_KEY_FILE: '/run/fixture/provider.pem',
  HETEROCLOUD_PUBLIC_ORIGIN: origin,
  HETEROCLOUD_SECURE_COOKIE: 'false',
  HETEROCLOUD_FLOW_PUBLIC_ENDPOINTS: 'http://127.0.0.1:18081/',
  HETEROCLOUD_FLOW_INTERNAL_ENDPOINT: 'http://127.0.0.1:18081/',
  HETEROCLOUD_FLASH_INTERNAL_ENDPOINT: 'http://127.0.0.1:18082/',
  HETEROCLOUD_SYOUYU_INTERNAL_ENDPOINT: 'http://127.0.0.1:18083/',
  HETEROCLOUD_BOOTSTRAP_EMAIL: 'fixture@example.test',
  HETEROCLOUD_BOOTSTRAP_PASSWORD_FILE: '/run/fixture/password',
  HETEROCLOUD_CONSOLE_DIR: '/opt/heterocloud/console',
};
function psql(query) {
  return execFileSync('psql', ['-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-U', 'hc_test', '-d', 'heterocloud_test_stage'], {
    input: query, encoding: 'utf8', env: { ...process.env, PGPASSWORD: 'fixture-only' },
  }).trim();
}
async function ready() {
  for (let attempt = 0; attempt < 90; attempt++) {
    const running = execFileSync('docker', ['inspect', '--format', '{{.State.Running}}', 'hc-staged-migration-fixture'], {encoding: 'utf8'}).trim();
    if (running !== 'true') throw new Error('fixture API container exited during startup');
    try {
      if ((await fetch(`${origin}/api/v1/health/ready`, {signal: AbortSignal.timeout(1500)})).ok) return;
    } catch { /* Wait for the application to bind. */ }
    await delay(1000);
  }
  throw new Error('fixture API failed to become ready');
}
const name = 'hc-staged-migration-fixture';
let browser;
try {
  execFileSync('docker', ['run', '-d', '--name', name, '--network=host', '-v', `${secrets}:/run/fixture:ro`,
    ...Object.entries(env).flatMap(([key, value]) => ['-e', `${key}=${value}`]), image], {stdio: 'pipe'});
  await ready();
  assert.equal(psql('SELECT count(*) FROM _sqlx_migrations WHERE version = 36;'), '0');
  browser = await chromium.launch({headless: true});
  const page = await browser.newPage();
  const login = await page.request.post(`${origin}/api/v1/auth/login`, {
    headers: {Origin: origin}, data: {email: 'fixture@example.test', password: 'fixture-only-password'},
  });
  assert.equal(login.status(), 200, 'real fixture login');
  const session = await page.request.get(`${origin}/api/v1/auth/session`);
  assert.equal(session.status(), 200);
  assert.equal((await session.json()).user.email, 'fixture@example.test');
  const initial = await page.goto(`${origin}/console`, {waitUntil: 'domcontentloaded', timeout: 15000});
  assert.equal(initial?.status(), 200);
  await page.getByText('HeteroCloud', {exact: false}).first().waitFor({timeout: 15000});

  // Simulate the subsequent additive release applying its exact embedded SQL.
  psql(`BEGIN;\n${migration}\nINSERT INTO _sqlx_migrations(version, description, success, checksum, execution_time) VALUES (36, 'flash cost budgets', true, decode('${checksum}', 'hex'), 0);\nCOMMIT;`);
  execFileSync('docker', ['restart', name], {stdio: 'pipe'});
  await ready();
  assert.equal(psql('SELECT count(*) FROM _sqlx_migrations WHERE version = 36;'), '1');
  const after = await page.request.get(`${origin}/api/v1/auth/session`);
  assert.equal(after.status(), 200, 'existing session survives a compatibility-image restart');
  assert.equal((await after.json()).user.email, 'fixture@example.test');
  const reload = await page.reload({waitUntil: 'domcontentloaded', timeout: 15000});
  assert.equal(reload?.status(), 200);
  console.log('PASS: exact image, isolated PostgreSQL migration, restart, authenticated Chromium session');
} catch (error) {
  try { process.stderr.write(execFileSync('docker', ['logs', '--tail', '80', name], {encoding: 'utf8'})); } catch {}
  throw error;
} finally {
  if (browser) await browser.close();
  try { execFileSync('docker', ['rm', '-f', name], {stdio: 'pipe'}); } catch {}
}
