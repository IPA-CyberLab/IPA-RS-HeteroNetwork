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

if (!username || !password) {
  throw new Error(
    "HETEROCLOUD_BROWSER_E2E_USERNAME and HETEROCLOUD_BROWSER_E2E_PASSWORD are required",
  );
}
if (baseUrl.pathname !== "/" || baseUrl.search || baseUrl.hash) {
  throw new Error("HETEROCLOUD_BROWSER_E2E_BASE_URL must contain only an origin");
}

await fs.mkdir(artifactDirectory, { recursive: true, mode: 0o700 });

const browser = await chromium.launch({
  headless: true,
  args: ["--disable-dev-shm-usage"],
});

let failed = false;
try {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    const startedAt = Date.now();
    const context = await browser.newContext();
    const page = await context.newPage();
    const serverErrors = [];
    const requestFailures = [];

    page.on("response", (response) => {
      if (sameOrigin(response.url()) && response.status() >= 500) {
        serverErrors.push(`${response.status()} ${response.request().method()} ${response.url()}`);
      }
    });
    page.on("requestfailed", (request) => {
      if (sameOrigin(request.url())) {
        requestFailures.push(
          `${request.method()} ${request.url()}: ${request.failure()?.errorText ?? "unknown error"}`,
        );
      }
    });

    try {
      await page.goto(new URL("/api/v1/auth/oidc/start", baseUrl).href, {
        waitUntil: "domcontentloaded",
        timeout: timeoutMs,
      });
      assertKeycloakLoginUrl(page.url());

      const usernameField = page.locator('input[name="username"]');
      const passwordField = page.locator('input[name="password"]');
      const submitButton = page.locator(
        '#kc-login, input[type="submit"], button[type="submit"]',
      ).first();
      await usernameField.waitFor({ state: "visible", timeout: timeoutMs });
      await passwordField.waitFor({ state: "visible", timeout: timeoutMs });
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
      if (serverErrors.length > 0 || requestFailures.length > 0) {
        throw new Error(
          [...serverErrors, ...requestFailures].join("\n"),
        );
      }

      console.log(
        `HeteroCloud browser E2E: attempt ${attempt}/${attempts} passed in ${Date.now() - startedAt}ms`,
      );
    } catch (error) {
      failed = true;
      const screenshot = path.join(
        artifactDirectory,
        `heterocloud-browser-e2e-attempt-${attempt}.png`,
      );
      await page.screenshot({ path: screenshot, fullPage: true }).catch(() => {});
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
      await context.close();
    }
  }
} finally {
  await browser.close();
}

if (failed) {
  process.exitCode = 1;
} else {
  console.log(`HeteroCloud browser E2E: all ${attempts} login attempts passed`);
}

function assertKeycloakLoginUrl(value) {
  const url = new URL(value);
  if (
    url.origin !== baseUrl.origin ||
    !url.pathname.startsWith("/id/realms/heterocloud/")
  ) {
    throw new Error(`OIDC start did not reach the HeteroCloud Keycloak realm: ${value}`);
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
  return error instanceof Error ? error.stack ?? error.message : String(error);
}
