// Disposable database and credentials only. This does not connect to production.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from '@playwright/test';

const image = process.env.HC_TEST_IMAGE;
const upgradeImage = process.env.HC_TEST_UPGRADE_IMAGE;
const source = process.env.HC_TEST_SOURCE;
const temporary = process.env.RUNNER_TEMP;
assert.match(image ?? '', /^ghcr\.io\/ipa-cyberlab\/ipa-rs-heterocloud@sha256:[a-f0-9]{64}$/);
assert.match(upgradeImage ?? '', /^ghcr\.io\/ipa-cyberlab\/ipa-rs-heterocloud@sha256:[a-f0-9]{64}$/);
assert.ok(source && temporary);
// Ensure the tested source contains the migration which the new image applies.
assert.ok(readFileSync(join(source, 'migrations', '0036_flash_cost_budgets.sql'), 'utf8').includes('CREATE TABLE flash_weekly_budgets'));
const secrets = join(temporary, 'hc-stage-secrets');
mkdirSync(secrets, { mode: 0o700 });
const write = (name, content) => writeFileSync(join(secrets, name), content, { mode: 0o600 });
write('database-url', 'postgres://hc_test:fixture-only@127.0.0.1:5432/heterocloud_test_stage');
write('csrf', 'fixture-csrf-key-with-more-than-32-bytes');
write('flow', 'fixture-flow-key-with-more-than-32-bytes');
write('syouyu', 'fixture-syouyu-key-with-more-than-32-bytes');
write('password', 'fixture-only-password');
execFileSync('openssl', ['genpkey', '-algorithm', 'ED25519', '-out', join(secrets, 'provider.pem')]);
chmodSync(join(secrets, 'provider.pem'), 0o600);
// The image runs as uid/gid 10001 and refuses world-readable secrets.
execFileSync('sudo', ['chown', '-R', '10001:10001', secrets]);
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
// A disposable Flash-provider fixture, never a production endpoint. Budget
// authorization, the HeteroCloud application and PostgreSQL are all real.
const mockFlash = createServer((request, response) => {
  if (request.url !== '/internal/v1/usage' || !request.headers.authorization?.startsWith('Bearer ')) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, {'Content-Type': 'application/json'});
  response.end(JSON.stringify({generated_at: 345601, week_started_at: 345600, items: []}));
});
await new Promise((resolve, reject) => mockFlash.once('error', reject).listen(18082, '127.0.0.1', resolve));
function startContainer(selectedImage) {
  execFileSync('docker', ['run', '-d', '--name', name, '--network=host', '-v', `${secrets}:/run/fixture:ro`,
    ...Object.entries(env).flatMap(([key, value]) => ['-e', `${key}=${value}`]), selectedImage], {stdio: 'pipe'});
}
function removeContainer() {
  execFileSync('docker', ['rm', '-f', name], {stdio: 'pipe'});
}
let browser;
try {
  startContainer(image);
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

  // Let the real upgrade image apply its own embedded migration.
  removeContainer();
  startContainer(upgradeImage);
  await ready();
  assert.equal(psql('SELECT count(*) FROM _sqlx_migrations WHERE version = 36;'), '1');
  const after = await page.request.get(`${origin}/api/v1/auth/session`);
  assert.equal(after.status(), 200, 'existing session survives the upgrade');
  const sessionData = await after.json();
  assert.equal(sessionData.user.email, 'fixture@example.test');
  assert.equal(sessionData.memberships.length, 1);
  const org = sessionData.memberships[0].organization_id;
  const budgetPath = `${origin}/api/v1/organizations/${org}/flash/weekly-budget`;
  const usagePath = `${origin}/api/v1/organizations/${org}/flash/usage`;
  const budget = {currency: 'USD', amount_microunits: 10000000, warning_percentage: 80};
  const missingCsrf = await page.request.put(budgetPath, {headers: {Origin: origin}, data: budget});
  assert.equal(missingCsrf.status(), 403, 'budget mutation rejects missing CSRF');
  const headers = {Origin: origin, 'x-heterocloud-csrf': sessionData.csrf_token};
  const save = await page.request.put(budgetPath, {headers, data: budget});
  assert.equal(save.status(), 200, `save budget: ${await save.text()}`);
  const usage = await page.request.get(usagePath);
  assert.equal(usage.status(), 200, `load usage: ${await usage.text()}`);
  assert.equal((await usage.json()).estimate.budget.amount_microunits, budget.amount_microunits);
  const view = await page.goto(`${origin}/cost-management`, {waitUntil: 'domcontentloaded', timeout: 15000});
  assert.equal(view?.status(), 200);
  await page.getByText('今週のFlash使用量', {exact: false}).first().waitFor({timeout: 15000});

  // Roll back to the compatibility image, then forward again. Existing
  // sessions and the budget must survive both transitions.
  removeContainer();
  startContainer(image);
  await ready();
  assert.equal((await page.request.get(`${origin}/api/v1/auth/session`)).status(), 200);
  removeContainer();
  startContainer(upgradeImage);
  await ready();
  const restored = await page.request.get(usagePath);
  assert.equal(restored.status(), 200);
  assert.equal((await restored.json()).estimate.budget.amount_microunits, budget.amount_microunits);
  assert.equal((await page.request.delete(budgetPath, {headers})).status(), 204);
  assert.equal((await (await page.request.get(usagePath)).json()).estimate.budget, null);
  console.log('PASS: published images, real PostgreSQL upgrade/rollback, session, CSRF, budget API and Chromium UI (mock Flash provider)');
} catch (error) {
  try { process.stderr.write(execFileSync('docker', ['logs', '--tail', '80', name], {encoding: 'utf8'})); } catch {}
  throw error;
} finally {
  if (browser) await browser.close();
  try { execFileSync('docker', ['rm', '-f', name], {stdio: 'pipe'}); } catch {}
  await new Promise(resolve => mockFlash.close(resolve));
}
