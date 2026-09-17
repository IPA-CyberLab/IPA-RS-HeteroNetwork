#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { chromium } from "playwright";

process.umask(0o077);
const credentials = process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_CREDENTIAL_FILE
  ? JSON.parse(await fs.readFile(process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_CREDENTIAL_FILE, "utf8"))
  : {};
const username = process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_USERNAME ?? credentials.username ?? credentials.E2E_USERNAME;
const password = process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_PASSWORD ?? credentials.password ?? credentials.E2E_PASSWORD;
if (typeof username !== "string" || typeof password !== "string" || !username || !password) {
  throw new Error("Console owner credentials are required; a rendered login form is not an E2E pass");
}

const target = new URL(process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_URL ?? "http://console.heteronetwork.internal:9781/ui/");
if (target.hostname !== "console.heteronetwork.internal" || target.protocol !== "http:" ||
    !["", "9781"].includes(target.port) || target.pathname !== "/ui/" ||
    target.username || target.password || target.search || target.hash) {
  throw new Error("Use the canonical console /ui/ URL on port 80 or 9781");
}
const directory = process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_ARTIFACT_DIR ?? "artifacts";
await fs.mkdir(directory, { recursive: true, mode: 0o700 });
const runDirectory = await fs.mkdtemp(path.join(directory, "console-browser-"));
const report = { startedAt: new Date().toISOString(), result: "incomplete", checks: [], responses: [], errors: [] };
const sanitize = (value) => String(value).replaceAll(username, "[test-user]").replaceAll(password, "[redacted]")
  .replace(/eyJ[A-Za-z0-9_.-]+/g, "[token]");
let browser;

try {
  browser = await chromium.launch({
    headless: true,
    args: ["--disable-dev-shm-usage"],
    ...(process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_PROXY
      ? { proxy: { server: process.env.HETERONETWORK_CONSOLE_BROWSER_E2E_PROXY } } : {}),
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: "block" });
  const page = await context.newPage();
  observe(page);
  await page.goto(target.href, { waitUntil: "domcontentloaded" });
  await page.getByRole("button", { name: "Keycloakでログイン" }).waitFor();
  const config = await page.evaluate(async () => (await fetch("/ui/config")).json());
  const verificationOrigin = new URL(config.device_verification_origin);
  if (verificationOrigin.protocol !== "https:" || verificationOrigin.pathname !== "/" ||
      verificationOrigin.username || verificationOrigin.password || verificationOrigin.search || verificationOrigin.hash ||
      config.issuer_url !== `${verificationOrigin.origin}/id/realms/heterocloud`) {
    throw new Error("Console issuer must match the configured public HeteroCloud realm");
  }

  const overview = waitFor(page, "/v1/admin/overview");
  const popupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Keycloakでログイン" }).click();
  const popup = await popupPromise;
  await popup.locator('input[name="username"]').waitFor();
  const form = await popup.locator("#kc-login").evaluate((button) => ({ action: button.form?.action, method: button.form?.method }));
  const action = new URL(form.action);
  if (action.origin !== verificationOrigin.origin || action.pathname !== "/id/realms/heterocloud/login-actions/authenticate" ||
      form.method?.toLowerCase() !== "post") throw new Error("Unexpected Keycloak credential submission origin");
  await popup.locator('input[name="username"]').fill(username);
  await popup.locator('input[name="password"]').fill(password);
  await popup.locator("#kc-login").click();
  await popup.waitForLoadState("domcontentloaded");
  const consent = popup.locator('#kc-accept, button[name="accept"], input[name="accept"]');
  if (await consent.count()) await consent.first().click();
  await accepted(overview, "Authenticated overview");
  await page.locator("#hn-header").waitFor();
  await page.screenshot({ path: path.join(runDirectory, "authenticated.png"), fullPage: true });

  const reloaded = waitFor(page, "/v1/admin/overview");
  await page.reload({ waitUntil: "domcontentloaded" });
  await accepted(reloaded, "Overview after reload");

  // A new tab has no access token in sessionStorage and must restore the cookie.
  const restoredPage = await context.newPage();
  observe(restoredPage);
  const refreshed = waitFor(restoredPage, "/v1/web-ui/auth/refresh");
  const restored = waitFor(restoredPage, "/v1/admin/overview");
  await restoredPage.goto(target.href, { waitUntil: "domcontentloaded" });
  await accepted(refreshed, "Refresh cookie in new tab");
  await accepted(restored, "Authenticated overview in new tab");
  await restoredPage.locator("#hn-header").waitFor();
  if (await restoredPage.getByText("セッションの有効期限が切れました。再度ログインしてください。", { exact: true }).isVisible()) {
    throw new Error("Restored console still displays a session-expired error");
  }
  const cookies = await context.cookies(new URL("/v1/web-ui/auth/refresh", target).href);
  report.httpOnlyRefreshCookie = cookies.some((cookie) => cookie.name === "heteronetwork_web_refresh" && cookie.httpOnly);
  if (!report.httpOnlyRefreshCookie) throw new Error("Missing protected refresh cookie");
  await restoredPage.screenshot({ path: path.join(runDirectory, "restored.png"), fullPage: true });
  if (report.errors.length) throw new Error("Browser JavaScript errors detected");
  report.result = "passed";
} catch (error) {
  report.result = "failed";
  report.failure = sanitize(error.message);
} finally {
  await browser?.close().catch((error) => {
    report.result = "failed";
    report.cleanupFailure = sanitize(error.message);
  });
  report.finishedAt = new Date().toISOString();
  await fs.writeFile(path.join(runDirectory, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  console.log(`Console browser E2E: ${report.result}; private report: ${runDirectory}`);
  if (report.failure) console.error(report.failure);
}
process.exitCode = report.result === "passed" ? 0 : 1;

function observe(page) {
  page.setDefaultTimeout(60_000);
  page.on("pageerror", (error) => report.errors.push(sanitize(error.message)));
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.origin === target.origin && url.pathname.startsWith("/v1/")) {
      report.responses.push({ method: response.request().method(), path: url.pathname, status: response.status() });
    }
  });
}

function waitFor(page, pathname) {
  // Handle rejection immediately while the login/navigation operation runs.
  return page.waitForResponse((response) => {
    const url = new URL(response.url());
    return url.origin === target.origin && url.pathname === pathname;
  }, { timeout: 60_000 }).then((response) => ({ response }), (error) => ({ error }));
}

async function accepted(pending, check) {
  const { response, error } = await pending;
  if (error) throw new Error(`${check}: ${error.message}`);
  report.checks.push({ check, status: response.status() });
  if (response.status() !== 200) throw new Error(`${check} returned HTTP ${response.status()}; owner access was not verified`);
}
