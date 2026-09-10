#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { chromium } from "playwright";

const baseUrl = new URL(
  process.env.HETEROCLOUD_BROWSER_E2E_BASE_URL ??
    "https://heterocloud.mizuame.app",
);
const username = process.env.HETEROCLOUD_BROWSER_E2E_USERNAME ?? process.env.E2E_USERNAME;
const password = process.env.HETEROCLOUD_BROWSER_E2E_PASSWORD ?? process.env.E2E_PASSWORD;
const diagnostic = process.argv.includes("--unauthenticated-diagnostic");
const plannedRoutes = ["/overview", "/organizations", "/projects", "/iam/principals",
  "/iam/policies", "/iam/bindings", "/flow/services", "/flash/services", "/registry",
  "/syouyu/buckets", "/audit-logs", "/settings"];
const attempts = parseBoundedInteger(
  process.env.HETEROCLOUD_BROWSER_E2E_ATTEMPTS ?? "10",
  "HETEROCLOUD_BROWSER_E2E_ATTEMPTS",
  1,
  100,
);
const timeoutMs = parseBoundedInteger(
  process.env.HETEROCLOUD_BROWSER_E2E_TIMEOUT_MS ?? "30000",
  "HETEROCLOUD_BROWSER_E2E_TIMEOUT_MS",
  5_000,
  120_000,
);
const artifactDirectory =
  process.env.HETEROCLOUD_BROWSER_E2E_ARTIFACT_DIR ??
  path.join(process.cwd(), "artifacts");

if ((!username || !password) && !diagnostic) {
  throw new Error(
    "Credentials required; use --unauthenticated-diagnostic explicitly for a NON-PASS diagnostic",
  );
}
if (baseUrl.pathname !== "/" || baseUrl.search || baseUrl.hash || baseUrl.username || baseUrl.password || baseUrl.protocol !== "https:") {
  throw new Error("HETEROCLOUD_BROWSER_E2E_BASE_URL must contain only an origin");
}

process.umask(0o077);
await fs.mkdir(artifactDirectory, { recursive: true, mode: 0o700 });
const runDirectory = await fs.mkdtemp(path.join(artifactDirectory, "heterocloud-browser-"));
await fs.chmod(runDirectory, 0o700);
const report = { startedAt: new Date().toISOString(), mode: diagnostic ? "unauthenticated-diagnostic" : "authenticated", result: "incomplete", attempts: [] };

const browser = await chromium.launch({
  headless: true,
  args: ["--disable-dev-shm-usage"],
});

let failed = false;
try {
  for (let attempt = 1; attempt <= (diagnostic ? 1 : attempts); attempt += 1) {
    const startedAt = Date.now();
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: "block" });
    const page = await context.newPage();
    page.setDefaultTimeout(timeoutMs);
    page.setDefaultNavigationTimeout(timeoutMs);
    const record = { attempt, startedAt: new Date().toISOString(), result: "incomplete", authenticated: false, pages: [], errors: [] };
    report.attempts.push(record);
    const readModels = new Map();
    const expectedErrors = [];
    const serverErrors = [];
    const requestFailures = [];

    page.on("response", (response) => {
      const url = new URL(response.url());
      if (response.status() >= 400) {
        const expected = !record.authenticated && sameOrigin(url.href) && url.pathname === "/api/v1/auth/session" && response.status() === 401;
        (expected ? expectedErrors : serverErrors).push(`${response.status()} ${response.request().method()} ${safeUrl(response.url())}`);
      }
      if (sameOrigin(url.href) && url.pathname.startsWith("/api/v1/") && response.request().method() === "GET" && response.status() === 200) {
        void response.json().then((body) => readModels.set(url.pathname, body)).catch(() => {});
      }
    });
    page.on("requestfailed", (request) => {
        requestFailures.push(
          `${request.method()} ${safeUrl(request.url())}: ${sanitize(request.failure()?.errorText ?? "unknown error")}`,
        );
    });
    page.on("pageerror", (error) => record.errors.push(`javascript: ${sanitize(error.message)}`));
    page.on("console", (message) => {
      if (message.type() !== "error") return;
      const expected = !record.authenticated && safeUrl(message.location().url) === `${baseUrl.origin}/api/v1/auth/session` && message.text().includes("401");
      (expected ? expectedErrors : record.errors).push(`console: ${sanitize(message.text())}`);
    });
    await context.route("**/*", async (route) => {
      const request = route.request();
      if (sameOrigin(request.url()) && new URL(request.url()).pathname.startsWith("/api/") && !["GET", "HEAD", "OPTIONS"].includes(request.method())) {
        record.errors.push(`blocked tenant write: ${request.method()} ${safeUrl(request.url())}`);
        await route.abort("blockedbyclient");
      } else await route.continue();
    });

    try {
      const homepage = await page.goto(baseUrl.href, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
      });
      record.homepageStatus = homepage?.status();
      record.homepageScreenshot = await capture(page, attempt, "homepage");
      if (!homepage || homepage.status() >= 400) throw new Error(`Homepage HTTP ${homepage?.status() ?? "no response"}`);
      const loginLink = page.locator('a[href="/login"]:visible').first();
      if (await loginLink.count()) await loginLink.click();
      const oidcLink = page.locator('a[href="/api/v1/auth/oidc/start"]:visible').first();
      await oidcLink.waitFor({ state: "visible", timeout: timeoutMs });
      await oidcLink.click();
      await page.waitForURL((url) => url.origin === baseUrl.origin && url.pathname.startsWith("/id/realms/heterocloud/"), { timeout: timeoutMs });
      assertKeycloakLoginUrl(page.url());

      const usernameField = page.locator('input[name="username"]');
      const passwordField = page.locator('input[name="password"]');
      const submitButton = page.locator(
        '#kc-login, input[type="submit"], button[type="submit"]',
      ).first();
      await usernameField.waitFor({ state: "visible", timeout: timeoutMs });
      await passwordField.waitFor({ state: "visible", timeout: timeoutMs });
      if (diagnostic) {
        record.loginUrl = safeUrl(page.url());
        record.loginScreenshot = await capture(page, attempt, "login");
        if (serverErrors.length || requestFailures.length || record.errors.length) throw new Error("Unauthenticated browser errors detected");
        record.result = "diagnostic-only-not-full-pass";
        break;
      }
      await usernameField.fill(username);
      await passwordField.fill(password);

      const authenticationResponsePromise = page.waitForResponse(
        (response) => {
          const request = response.request();
          const url = new URL(response.url());
          return (
            request.method() === "POST" &&
            url.pathname.includes("/realms/heterocloud/login-actions/authenticate")
          );
        },
        { timeout: timeoutMs },
      );
      await submitButton.click({ timeout: timeoutMs });
      const authenticationResponse = await authenticationResponsePromise;
      if (authenticationResponse.status() >= 400) {
        throw new Error(
          `Keycloak authentication POST returned HTTP ${authenticationResponse.status()}`,
        );
      }

      await page.waitForURL(
        (candidate) =>
          candidate.origin === baseUrl.origin &&
          !candidate.pathname.startsWith("/id/") &&
          candidate.pathname !== "/login",
        { waitUntil: "domcontentloaded", timeout: timeoutMs },
      );

      const sessionResponse = await context.request.get(
        new URL("/api/v1/auth/session", baseUrl).href,
        { timeout: timeoutMs },
      );
      if (sessionResponse.status() !== 200) {
        throw new Error(`authenticated session returned HTTP ${sessionResponse.status()}`);
      }
      const session = await sessionResponse.json();
      if (session?.user?.email !== username) {
        throw new Error("authenticated session belongs to an unexpected user");
      }
      record.authenticated = true;
      if (session.owner_console) throw new Error("Tenant account required; owner-only navigation cannot cover service pages");
      const selectedOrganization = await page.evaluate(() => {
        try { return localStorage.getItem("heterocloud.active-organization"); }
        catch { return null; }
      });
      const organization = (session.memberships?.find((membership) => membership.organization_id === selectedOrganization)
        ?? session.memberships?.[0])?.organization_id;
      if (!organization) throw new Error("Authenticated account has no organization membership");
      const org = `/api/v1/organizations/${encodeURIComponent(organization)}/`;
      const routes = [
        ["/overview", "コンソールホーム", ["projects", "iam/principals", "iam/policies", "realtime/services", "audit-events"]],
        ["/organizations", "組織", ["/api/v1/organizations"]],
        ["/projects", "プロジェクト", ["projects"]],
        ["/iam/principals", "IAMプリンシパル", ["iam/principals"]],
        ["/iam/policies", "IAMポリシー", ["iam/policies"]],
        ["/iam/bindings", "IAMバインディング", ["iam/principals", "iam/policies"]],
        ["/flow/services", "Flow", ["realtime/services", "projects"], "realtime/services"],
        ["/flash/services", "Flash", ["flash/services", "flash/quota", "projects"], "flash/services"],
        ["/registry", "Flash Registry", ["registry", "registry/images"]],
        ["/syouyu/buckets", "Syouyu", ["syouyu/buckets", "syouyu/quota", "projects"], "syouyu/buckets"],
        ["/audit-logs", "監査ログ", ["audit-events"]],
        ["/settings", "設定", ["/api/v1/auth/session"]],
      ];
      async function visit(routePath, title, endpoints, detail = false) {
        const entry = { route: routePath, result: "failed", apis: [] };
        record.pages.push(entry);
        try {
          const link = page.locator(`a[href="${routePath}"]:visible`).first();
          if (await link.count()) await link.click();
          else if (detail) await page.goto(new URL(routePath, baseUrl).href, { waitUntil: "domcontentloaded" });
          else throw new Error("Console navigation link missing or hidden");
          await page.waitForURL((url) => url.origin === baseUrl.origin && url.pathname === routePath);
          // Reload forces the UI to load its read models rather than reuse Query cache.
          for (const endpoint of endpoints) readModels.delete(endpoint);
          await page.reload({ waitUntil: "domcontentloaded" });
          const deadline = Date.now() + timeoutMs;
          while (!endpoints.every((endpoint) => readModels.has(endpoint)) && Date.now() < deadline) {
            await new Promise((resolve) => setTimeout(resolve, 100));
          }
          if (!endpoints.every((endpoint) => readModels.has(endpoint))) throw new Error("Page read models did not return HTTP 200 JSON before deadline");
          await page.getByRole("heading", { level: 1, name: title, exact: true }).waitFor({ state: "visible" });
          await page.locator('[aria-busy="true"]').first().waitFor({ state: "hidden" });
          await page.getByText(/取得できませんでした|接続できません|所属組織がありません/).first().waitFor({ state: "hidden" });
          entry.apis = endpoints.map((endpoint) => ({ url: safeUrl(endpoint), status: 200 }));
          entry.result = "passed";
        } catch (error) {
          entry.error = sanitize(error.message);
        }
        entry.screenshot = await capture(page, attempt, `page-${record.pages.length}`).catch(() => null);
      }
      const maxDetails = parseBoundedInteger(process.env.HETEROCLOUD_BROWSER_E2E_MAX_DETAILS_PER_SERVICE ?? "20", "MAX_DETAILS_PER_SERVICE", 1, 100);
      for (const [routePath, title, suffixes, collection] of routes) {
        await visit(routePath, title, suffixes.map((suffix) => suffix.startsWith("/") ? suffix : org + suffix));
        if (!collection) continue;
        const items = readModels.get(org + collection)?.items;
        if (!Array.isArray(items)) {
          record.errors.push(`Detail coverage failed: ${collection} read model has no items array`);
          record.pages.at(-1).detailCoverage = { result: "failed", reason: "Missing or invalid items array" };
          continue;
        }
        record.pages.at(-1).detailCoverage = { available: items.length, selected: Math.min(items.length, maxDetails) };
        if (items.length === 0 || items.length > maxDetails) record.errors.push(`Detail coverage incomplete: ${collection}, available=${items.length}, limit=${maxDetails}`);
        for (const item of items.slice(0, maxDetails)) {
          if (typeof item.id !== "string" || !/^[A-Za-z0-9-]+$/.test(item.id)) throw new Error("Invalid resource ID in read model");
          await visit(`${routePath}/${item.id}`, collection === "syouyu/buckets" ? item.spec.bucket_name : item.name, [org + collection + "/" + item.id], true);
        }
      }
      if (record.pages.some((entry) => entry.result !== "passed") || record.errors.length) throw new Error("Page coverage or browser errors detected; see private report");
      if (serverErrors.length > 0 || requestFailures.length > 0) {
        throw new Error(
          [...serverErrors, ...requestFailures].join("\n"),
        );
      }
      record.result = "passed";

      console.log(
        `HeteroCloud browser E2E: attempt ${attempt}/${attempts} passed in ${Date.now() - startedAt}ms`,
      );
    } catch (error) {
      failed = true;
      record.result = "failed";
      record.error = formatError(error);
      record.failureUrl = safeUrl(page.url());
      record.screenshot = await capture(page, attempt, "failed").catch(() => null);
      console.error(
        `HeteroCloud browser E2E: attempt ${attempt}/${attempts} failed: ${formatError(error)}`,
      );
      if (serverErrors.length > 0) {
        console.error(`server errors:\n${serverErrors.join("\n")}`);
      }
      if (requestFailures.length > 0) {
        console.error(`request failures:\n${requestFailures.join("\n")}`);
      }
      break;
    } finally {
      record.finishedAt = new Date().toISOString();
      record.unexecutedPages = plannedRoutes.filter((route) => !record.pages.some((entry) => entry.route === route))
        .map((route) => ({ route, result: "blocked", reason: diagnostic
          ? "Unauthenticated diagnostic; credentials/session/service checks not performed"
          : "Earlier failure prevented this page check" }));
      record.detailChecks = record.authenticated
        ? "See per-service detailCoverage and page results; missing coverage is not a pass"
        : "blocked: no authenticated session; Flow, Flash and Syouyu details not accessed";
      record.serverErrors = serverErrors;
      record.requestFailures = requestFailures;
      record.expectedUnauthenticatedErrors = expectedErrors;
      await context.close();
    }
  }
} finally {
  await browser.close();
  report.finishedAt = new Date().toISOString();
  report.result = failed ? "failed" : diagnostic ? "diagnostic-only-not-full-pass" : "passed";
  await fs.writeFile(path.join(runDirectory, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  console.log(`Private browser evidence: ${runDirectory}`);
}

if (failed) {
  process.exitCode = 1;
} else if (diagnostic) {
  process.exitCode = 2;
  console.log("Unauthenticated diagnostic complete; login/session/service coverage NOT performed; NOT a full pass");
} else {
  console.log(`HeteroCloud browser E2E: all ${attempts} authenticated page sweeps passed`);
}

function assertKeycloakLoginUrl(value) {
  const url = new URL(value);
  if (
    url.origin !== baseUrl.origin ||
    !url.pathname.startsWith("/id/realms/heterocloud/")
  ) {
    throw new Error(`OIDC start did not reach the HeteroCloud Keycloak realm: ${safeUrl(value)}`);
  }
}

function sameOrigin(value) {
  try {
    return new URL(value).origin === baseUrl.origin;
  } catch {
    return false;
  }
}

function parseBoundedInteger(value, name, minimum, maximum) {
  if (!/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function formatError(error) {
  return sanitize(error instanceof Error ? error.message : String(error));
}

function safeUrl(value) {
  try {
    const url = new URL(value, baseUrl);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch { return "[invalid URL]"; }
}

function sanitize(value) {
  let text = String(value);
  for (const secret of [username, password].filter(Boolean)) text = text.split(secret).join("[redacted]");
  return text.replace(/https?:\/\/[^\s<>"']+/g, safeUrl)
    .replace(/\bBearer\s+[^\s,;]+/gi, "Bearer [redacted]")
    .replace(/((?:password|token|secret|cookie|code|state|nonce)\s*[=:]\s*)[^\s,;&]+/gi, "$1[redacted]").slice(0, 2000);
}

async function capture(page, attempt, name) {
  const file = `${attempt}-${name}.png`;
  const buffer = await page.screenshot({ fullPage: true, timeout: timeoutMs, mask: [page.locator("input, textarea, pre, code")] });
  await fs.writeFile(path.join(runDirectory, file), buffer, { mode: 0o600 });
  return file;
}
