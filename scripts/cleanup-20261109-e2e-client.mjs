#!/usr/bin/env node

// One-off cleanup for the disposable client whose private key was lost when
// acceptance run 42626737541 ended. No other client may be removed here.
import { chromium } from "playwright";

const id = "node-420c3c0571136b33156ac64cd33b2461";
const ip = "10.250.0.18";
const username = "heteronetwork-console-e2e@heteronetwork.invalid";
const password = process.env.HNN_E2E_CONSOLE_PASSWORD;
if (!password) throw new Error("Missing protected console credential");

const browser = await chromium.launch({
  headless: true,
  args: ["--disable-dev-shm-usage", "--host-resolver-rules=MAP console.heteronetwork.internal 127.0.0.1"],
});
try {
  const page = await browser.newPage({ serviceWorkers: "block" });
  await page.goto("http://console.heteronetwork.internal:9781/ui/", { waitUntil: "domcontentloaded", timeout: 30_000 });
  const config = await page.evaluate(async () => {
    const response = await fetch("/ui/config");
    if (!response.ok) throw new Error("Console configuration unavailable");
    return response.json();
  });
  const origin = new URL(config.device_verification_origin);
  if (origin.origin !== "https://heterocloud.mizuame.app" || origin.pathname !== "/" ||
      origin.username || origin.password || origin.search || origin.hash ||
      config.issuer_url !== `${origin.origin}/id/realms/heterocloud`) {
    throw new Error("Unexpected identity provider");
  }
  const popupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Keycloakでログイン" }).click();
  const popup = await popupPromise;
  await popup.locator('input[name="username"]').waitFor();
  const form = await popup.locator("#kc-login").evaluate((button) => ({ action: button.form?.action, method: button.form?.method }));
  const action = new URL(form.action);
  if (action.origin !== origin.origin || action.pathname !== "/id/realms/heterocloud/login-actions/authenticate" ||
      form.method?.toLowerCase() !== "post") throw new Error("Unexpected credential submission destination");
  await popup.locator('input[name="username"]').fill(username);
  await popup.locator('input[name="password"]').fill(password);
  await popup.locator("#kc-login").click();
  await page.waitForFunction(() => Boolean(sessionStorage.getItem("heteronetwork_access_token")), null, { timeout: 60_000 });
  const result = await page.evaluate(async ({ id, ip }) => {
    const token = sessionStorage.getItem("heteronetwork_access_token");
    const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
    const list = async () => {
      const response = await fetch("/v1/admin/nodes", { headers });
      if (!response.ok) throw new Error(`node listing HTTP ${response.status}`);
      const nodes = await response.json();
      if (!Array.isArray(nodes)) throw new Error("Unexpected node listing");
      return nodes.filter((item) => item.node?.node_id === id);
    };
    const matches = await list();
    if (!matches.length) return { alreadyAbsent: true };
    if (matches.length !== 1 || matches[0].node.vpn_ip !== ip) throw new Error("Test client identity mismatch");
    const response = await fetch(`/v1/admin/nodes/${id}`, { method: "DELETE", headers });
    if (!response.ok) throw new Error(`client removal HTTP ${response.status}`);
    const removed = await response.json();
    if (removed.node?.node_id !== id || removed.node?.vpn_ip !== ip) throw new Error("Removal response identity mismatch");
    if ((await list()).length) throw new Error("Client remains after removal");
    return { removed: true, verifiedAbsent: true };
  }, { id, ip });
  console.log(JSON.stringify(result));
} catch (error) {
  // Browser errors can contain authorization URLs and must not reach job logs.
  const http = /^(?:node listing|client removal) HTTP \d{3}$/.test(error.message) ? error.message : error.name;
  console.error(`Cleanup failed: ${http}`);
  process.exitCode = 1;
} finally {
  await browser.close();
}
