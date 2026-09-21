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
const netLogPath = values.output ? `${values.output}.chromium-netlog.json` : null;
let browser;
try {
  const launchArgs = ['--disable-dev-shm-usage'];
  if (netLogPath) {
    launchArgs.push(`--log-net-log=${netLogPath}`, '--net-log-capture-mode=Default');
  }
  browser = await chromium.launch({ headless: true, args: launchArgs });
  // Exercise the client-visible split-DNS path before pinning each request to
  // a gateway. Direct-IP checks alone cannot detect a broken canonical name.
  {
    const context = await browser.newContext({ serviceWorkers: 'block' });
    try {
      const page = await context.newPage();
      const canonicalEvents = [];
      const eventStartedAt = performance.now();
      const recordCanonicalEvent = (kind, request, status = undefined) => {
        const url = new URL(request.url());
        if (url.hostname !== 'console.heteronetwork.internal') return;
        canonicalEvents.push({ kind, path: url.pathname, resource: request.resourceType(), status,
          at_ms: Math.ceil(performance.now() - eventStartedAt) });
      };
      page.on('request', request => recordCanonicalEvent('request', request));
      page.on('response', response => recordCanonicalEvent(
        'response', response.request(), response.status()));
      page.on('requestfinished', request => recordCanonicalEvent('finished', request));
      page.on('pageerror', error => report.errors.push(error.message));
      page.on('requestfailed', request => {
        const failure = request.failure();
        report.canonical_request_failure = failure?.errorText ?? 'unknown';
        recordCanonicalEvent('failed', request);
      });
      const openedAt = performance.now();
      const canonicalOrigin = values.canonicalPort === '80'
        ? 'http://console.heteronetwork.internal'
        : `http://console.heteronetwork.internal:${values.canonicalPort}`;
      let main;
      try {
        main = await page.goto(`${canonicalOrigin}/ui/`, {
          waitUntil: 'domcontentloaded', timeout: UI_OPEN_BUDGET_MS,
        });
      } catch (error) {
        const direct = await context.newPage();
        try {
          const response = await direct.goto(`http://${gateways[0]}/v1/web-ui/healthz`, {
            waitUntil: 'domcontentloaded', timeout: UI_OPEN_BUDGET_MS,
          });
          report.canonical_diagnostic = { direct_gateway_http: response?.status() ?? null };
        } catch (directError) {
          report.canonical_diagnostic = { direct_gateway_error: String(directError.message) };
        } finally {
          await direct.close();
        }
        report.canonical_events = canonicalEvents.slice(-50);
        report.canonical_page = await page.evaluate(() => ({
          ready_state: document.readyState,
          title: document.title,
          body_bytes: document.body?.innerHTML.length ?? 0,
        })).catch(pageError => ({ inspection_error: String(pageError.message) }));
        let noProxyBrowser;
        let noProxyContext;
        try {
          noProxyBrowser = await chromium.launch({ headless: true,
            args: ['--disable-dev-shm-usage', '--no-proxy-server'] });
          noProxyContext = await noProxyBrowser.newContext({ serviceWorkers: 'block' });
          const noProxyPage = await noProxyContext.newPage();
          const noProxyStartedAt = performance.now();
          const noProxyResponse = await noProxyPage.goto(`${canonicalOrigin}/ui/`, {
            waitUntil: 'domcontentloaded', timeout: UI_OPEN_BUDGET_MS,
          });
          report.no_proxy_diagnostic = { http: noProxyResponse?.status() ?? null,
            open_ms: Math.ceil(performance.now() - noProxyStartedAt) };
        } catch (noProxyError) {
          report.no_proxy_diagnostic = { error: String(noProxyError.message) };
        } finally {
          await noProxyContext?.close();
          await noProxyBrowser?.close();
        }
        // Keep the resolver alive briefly after the three-second acceptance
        // deadline so its terminal event is available in the failure report.
        await new Promise(resolve => setTimeout(resolve, 7_000));
        throw error;
      }
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
  for (const gateway of gateways) {
    // Chromium's native resolver override preserves the canonical Host header
    // while sending every browser request directly to this gateway. Using
    // Playwright route.fetch here made the runner proxy and buffer large static
    // responses, which could turn a completed HTTP 200 into ECONNRESET.
    browser = await chromium.launch({ headless: true, args: [
      '--disable-dev-shm-usage',
      '--no-proxy-server',
      `--host-resolver-rules=MAP console.heteronetwork.internal ${gateway},EXCLUDE localhost`,
    ] });
    try {
      for (const port of [80, 9781]) {
        const origin = `http://console.heteronetwork.internal${port === 80 ? '' : ':9781'}`;
        const context = await browser.newContext({ serviceWorkers: 'block' });
        try {
          const page = await context.newPage();
          page.setDefaultTimeout(15_000);
          page.on('pageerror', error => report.errors.push(error.message));
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
          await context.close();
        }
      }
    } finally {
      await browser.close();
      browser = undefined;
    }
  }
  if (report.errors.length) throw new Error('Browser JavaScript errors detected');
  report.result = 'passed';
} catch (error) {
  report.failure = String(error.message).replace(/eyJ[A-Za-z0-9_.-]+/g, '[token]');
} finally {
  await browser?.close();
  if (netLogPath) {
    try {
      if (report.result !== 'passed') {
        const netLog = JSON.parse(await fs.readFile(netLogPath, 'utf8'));
        const eventNames = new Map(Object.entries(netLog.constants?.logEventTypes ?? {})
          .map(([name, id]) => [id, name]));
        const networkEvents = netLog.events ?? [];
        const resolverSourceIds = new Set();
        for (const event of networkEvents) {
          if (JSON.stringify(event.params ?? {}).includes('console.heteronetwork.internal')) {
            if (event.source?.id !== undefined) resolverSourceIds.add(event.source.id);
            if (event.params?.source_dependency?.id !== undefined) {
              resolverSourceIds.add(event.params.source_dependency.id);
            }
          }
        }
        let changed = true;
        while (changed) {
          changed = false;
          for (const event of networkEvents) {
            const sourceId = event.source?.id;
            const dependencyId = event.params?.source_dependency?.id;
            if ((sourceId !== undefined && resolverSourceIds.has(sourceId)) ||
                (dependencyId !== undefined && resolverSourceIds.has(dependencyId))) {
              for (const id of [sourceId, dependencyId]) {
                if (id !== undefined && !resolverSourceIds.has(id)) {
                  resolverSourceIds.add(id);
                  changed = true;
                }
              }
            }
          }
        }
        report.chromium_resolver_events = networkEvents
          .filter(event => {
            const name = eventNames.get(event.type) ?? '';
            return (name.includes('HOST_RESOLVER') || name.includes('DNS')) &&
              resolverSourceIds.has(event.source?.id);
          })
          .slice(-100)
          .map(event => ({
            type: eventNames.get(event.type) ?? event.type,
            phase: event.phase,
            time: event.time,
            source: event.source,
            params: event.params,
          }));
      }
      await fs.unlink(netLogPath);
    } catch (netLogError) {
      report.chromium_netlog_error = String(netLogError.message);
    }
  }
  report.finished_at_utc = new Date().toISOString();
  if (values.output) await fs.writeFile(values.output, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(report));
}
process.exitCode = report.result === 'passed' ? 0 : 1;
