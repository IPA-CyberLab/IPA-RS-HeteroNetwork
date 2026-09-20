#!/usr/bin/env node
// Forward requests to each real gateway while retaining the canonical browser origin.
import fs from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { chromium } from 'playwright';

process.umask(0o077);
const { values } = parseArgs({ options: {
  gateways: { type: 'string' }, output: { type: 'string' },
  fallbackResolv: { type: 'string' },
  canonicalPort: { type: 'string', default: '9781' },
} });
const gateways = values.gateways?.split(',');
if (!gateways?.length || gateways.some(ip => !/^10\.250\.\d{1,3}\.\d{1,3}$/.test(ip))) {
  throw new Error('--gateways must contain registered overlay IPv4 addresses');
}
if (!['80', '9781'].includes(values.canonicalPort)) {
  throw new Error('--canonicalPort must be 80 or 9781');
}
const UI_OPEN_BUDGET_MS = 3_000;
const report = { started_at_utc: new Date().toISOString(), result: 'failed', canonical: null,
  gateways: [], errors: [] };
let browser;
try {
  browser = await chromium.launch({ headless: true, args: ['--disable-dev-shm-usage'] });
  // Exercise the client-visible split-DNS path before pinning each request to
  // a gateway. Direct-IP checks alone cannot detect a broken canonical name.
  {
    const context = await browser.newContext({ serviceWorkers: 'block' });
    try {
      const page = await context.newPage();
      page.on('pageerror', error => report.errors.push(error.message));
      const openedAt = performance.now();
      const canonicalOrigin = values.canonicalPort === '80'
        ? 'http://console.heteronetwork.internal'
        : `http://console.heteronetwork.internal:${values.canonicalPort}`;
      const main = await page.goto(`${canonicalOrigin}/ui/`, {
        waitUntil: 'domcontentloaded', timeout: UI_OPEN_BUDGET_MS,
      });
      const remaining = Math.max(1, UI_OPEN_BUDGET_MS - (performance.now() - openedAt));
      await page.getByRole('button', { name: 'Keycloakでログイン' }).waitFor({ timeout: remaining });
      const openMs = Math.ceil(performance.now() - openedAt);
      if (main.status() !== 200) throw new Error(`canonical console UI HTTP ${main.status()}`);
      if (openMs > UI_OPEN_BUDGET_MS) throw new Error(`canonical console UI opened in ${openMs} ms`);
      report.canonical = { port: Number(values.canonicalPort), ui_http: 200,
        login_button_rendered: true, open_ms: openMs };
    } finally {
      await context.close();
    }
  }
  await browser.close();
  browser = undefined;
  if (values.fallbackResolv) {
    await fs.copyFile(values.fallbackResolv, '/etc/resolv.conf');
  }
  browser = await chromium.launch({ headless: true, args: ['--disable-dev-shm-usage'] });
  for (const gateway of gateways) {
    for (const port of [80, 9781]) {
      const origin = `http://console.heteronetwork.internal${port === 80 ? '' : ':9781'}`;
      const context = await browser.newContext({ serviceWorkers: 'block' });
      try {
        const page = await context.newPage();
        page.setDefaultTimeout(15_000);
        page.on('pageerror', error => report.errors.push(error.message));
        // This selects the network destination only. Status, headers and body
        // come unchanged from the actual server; no fixture response is used.
        await context.route(`${origin}/**`, async route => {
          const original = new URL(route.request().url());
          const destination = new URL(original);
          destination.hostname = gateway;
          const response = await route.fetch({ url: destination.href, maxRedirects: 0,
            headers: { ...route.request().headers(), host: original.host } });
          await route.fulfill({ response });
        });
        const openedAt = performance.now();
        const main = await page.goto(`${origin}/ui/`, {
          waitUntil: 'domcontentloaded', timeout: UI_OPEN_BUDGET_MS,
        });
        if (main.status() !== 200) throw new Error(`${gateway}:${port} UI HTTP ${main.status()}`);
        const remaining = Math.max(1, UI_OPEN_BUDGET_MS - (performance.now() - openedAt));
        await page.getByRole('button', { name: 'Keycloakでログイン' }).waitFor({ timeout: remaining });
        const openMs = Math.ceil(performance.now() - openedAt);
        if (openMs > UI_OPEN_BUDGET_MS) {
          throw new Error(`${gateway}:${port} console UI opened in ${openMs} ms`);
        }
        const configuration = await page.evaluate(async () => {
          const response = await fetch('/ui/config');
          return { status: response.status, config: await response.json() };
        });
        const config = configuration.config;
        if (configuration.status !== 200 || config.auth_enabled !== true || config.provider !== 'keycloak' ||
            config.issuer_url !== 'https://heterocloud.mizuame.app/id/realms/heterocloud' ||
            config.device_verification_origin !== 'https://heterocloud.mizuame.app') {
          throw new Error(`${gateway}:${port} console authentication configuration is invalid`);
        }
        const row = { gateway, port, ui_http: 200, config_http: 200,
          login_button_rendered: true, open_ms: openMs };
        if (port === 80) {
          // The Windows client uses the gateway IP without overriding Host.
          // A failure here makes it repeatedly abandon an otherwise healthy gateway.
          const probe = await context.newPage();
          try {
            const response = await probe.goto(`http://${gateway}/v1/web-ui/healthz`);
            if (response.status() !== 200 || (await response.json()).status !== 'ok') {
              throw new Error(`${gateway} native client IP health probe failed: HTTP ${response.status()}`);
            }
            row.client_ip_health_http = 200;
          } finally {
            await probe.close();
          }
        }
        if (port === 9781) {
          const opened = page.waitForEvent('popup');
          const deviceStarted = page.waitForResponse(response => {
            const url = new URL(response.url());
            return url.pathname === '/v1/web-ui/auth/device' &&
              response.request().method() === 'POST';
          });
          await page.getByRole('button', { name: 'Keycloakでログイン' }).click();
          const popup = await opened;
          const deviceResponse = await deviceStarted;
          const deviceBody = await deviceResponse.json().catch(() => ({}));
          if (!deviceResponse.ok()) {
            throw new Error(`${gateway} device login start returned HTTP ${deviceResponse.status()}: ${deviceBody.error || 'invalid response'}`);
          }
          popup.setDefaultTimeout(15_000);
          popup.on('pageerror', error => report.errors.push(error.message));
          const popupResponses = [];
          popup.on('response', response => {
            if (response.request().resourceType() !== 'document') return;
            const url = new URL(response.url());
            popupResponses.push({ status: response.status(), url: `${url.origin}${url.pathname}` });
          });
          try {
            await popup.locator('input[name="username"]').waitFor();
            await popup.locator('input[name="password"]').waitFor();
          } catch (error) {
            const url = new URL(popup.url());
            report.keycloak_failure = {
              gateway,
              url: `${url.origin}${url.pathname}`,
              title: await popup.title().catch(() => ''),
              body: (await popup.locator('body').innerText().catch(() => '')).slice(0, 1_000),
              closed: popup.isClosed(),
              login_page: (await page.locator('body').innerText().catch(() => '')).slice(0, 1_000),
              verification_origin: (() => {
                try { return new URL(deviceBody.verification_uri).origin; } catch { return ''; }
              })(),
              responses: popupResponses,
            };
            throw error;
          }
          const form = await popup.locator('#kc-login').evaluate(button =>
            ({ action: button.form.action, method: button.form.method }));
          const action = new URL(form.action);
          if (action.origin !== config.device_verification_origin ||
              action.pathname !== '/id/realms/heterocloud/login-actions/authenticate' ||
              form.method.toLowerCase() !== 'post') throw new Error(`${gateway} opened the wrong login form`);
          row.public_keycloak_credential_form = true;
          await popup.close();
        }
        report.gateways.push(row);
      } finally {
        await context.unrouteAll({ behavior: 'ignoreErrors' });
        await context.close();
      }
    }
  }
  if (report.errors.length) throw new Error('Browser JavaScript errors detected');
  report.result = 'passed';
} catch (error) {
  report.failure = String(error.message).replace(/eyJ[A-Za-z0-9_.-]+/g, '[token]');
} finally {
  await browser?.close();
  report.finished_at_utc = new Date().toISOString();
  if (values.output) await fs.writeFile(values.output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(report));
}
process.exitCode = report.result === 'passed' ? 0 : 1;
