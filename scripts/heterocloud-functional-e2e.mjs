#!/usr/bin/env node

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { chromium } from "playwright";

const help = `Usage: node scripts/heterocloud-functional-e2e.mjs --allow-own-fixture-mutations

Required: HETEROCLOUD_FUNCTIONAL_E2E_ORGANIZATION_ID matching the private manifest.
Optional: HETEROCLOUD_FUNCTIONAL_E2E_ENV_FILE, HETEROCLOUD_FUNCTIONAL_E2E_FIXTURES,
          HETEROCLOUD_FUNCTIONAL_E2E_ARTIFACT_DIR.
Uses normal public DNS/TLS/login; no origin overrides or stored sessions.
Creates one P2P room, joins once, runs Flash pwd, and waits for room idle cleanup.
`;
if (process.argv.includes("--help")) {
  console.log(help);
  process.exit(0);
}
if (process.argv.length !== 3 || process.argv[2] !== "--allow-own-fixture-mutations") {
  console.error(help);
  process.exit(2);
}

process.umask(0o077);
const base = "https://heterocloud.mizuame.app";
const flowBase = "https://flow.heterocloud.mizuame.app";
const privateRoot = path.join(os.homedir(), ".config/heterocloud");
const timeout = 20_000;
const idleCleanupDelay = 615_000; // Documented ten-minute idle timeout, plus one sweep.
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const runId = randomUUID();
const roomName = `e2e-functional-${runId}`;
const report = {
  run_id: runId, started_at: new Date().toISOString(), result: "incomplete",
  public_origin: base, flow_origin: flowBase, phase: "configuration",
  flow: { cleanup: "not_needed" }, flash: {}, errors: [], login_http: [], browser_errors: [],
};
let directory;
let browser;
let context;
let account;
let organization;
let flow;
let flash;
let project;
let room;
let roomCreatedAt;
let createAttempted = false;
const issuedContexts = new Map();

function fail(code) {
  const error = new Error(code);
  error.safeCode = code;
  throw error;
}

function recordError(error, phase = report.phase) {
  // Never persist Playwright errors/stacks: locator errors can include passwords.
  report.errors.push({ phase, code: error.safeCode ?? "browser_or_transport_error" });
}

async function privateFile(filename) {
  const stat = await fs.lstat(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid()) {
    fail("private_input_must_be_owned_regular_file_mode_600");
  }
  return fs.readFile(filename, "utf8");
}

async function save() {
  if (directory) await fs.writeFile(path.join(directory, "report.json"), JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
}

async function session() {
  const response = await context.request.get(`${base}/api/v1/auth/session`, { timeout });
  if (response.status() !== 200) fail(`session_http_${response.status()}`);
  const value = await response.json();
  if (value.user?.email !== account.E2E_USERNAME || value.owner_console ||
      value.memberships?.length !== 1 || value.memberships[0].organization_id !== organization ||
      value.memberships[0].role !== "owner" || !value.csrf_token) fail("dedicated_tenant_session_guard_failed");
  return value;
}

function servicePath(service) {
  return `/api/v1/organizations/${organization}/${service.collection}/${service.id}`;
}

async function issueContext(permissions) {
  const current = await session();
  const response = await context.request.post(`${base}${servicePath(flow)}/access-credentials`, {
    headers: { Origin: base, "x-heterocloud-csrf": current.csrf_token },
    data: { permissions, expires_in_seconds: 180 }, timeout,
  });
  if (response.status() >= 300) fail(`issue_context_http_${response.status()}`);
  const credential = await response.json();
  if (typeof credential.context_id !== "string" || !/^[a-f0-9-]{36}$/i.test(credential.context_id)) fail("invalid_context_id");
  issuedContexts.set(credential.context_id, credential);
  if (credential.organization_id !== organization || credential.service_instance_id !== flow.id ||
      credential.project_id !== project.id || !credential.headers) fail("signed_context_scope_guard_failed");
  return credential;
}

async function revokeContexts() {
  for (const id of [...issuedContexts.keys()]) {
    try {
      const current = await session();
      const response = await context.request.delete(`${base}${servicePath(flow)}/access-contexts/${id}`, {
        headers: { Origin: base, "x-heterocloud-csrf": current.csrf_token }, timeout,
      });
      if (response.status() !== 204) fail(`revoke_context_http_${response.status()}`);
      issuedContexts.delete(id);
      report.flow.revoked_contexts = (report.flow.revoked_contexts ?? 0) + 1;
    } catch (error) {
      recordError(error, "revoke_context");
    }
  }
}

async function flowRequest(credential, method, route, data) {
  const permitted = (method === "GET" && (route === "/v1/rooms" || route === `/v1/rooms/${room?.id}`)) ||
    (method === "POST" && (route === "/v1/rooms" || route === `/v1/rooms/${room?.id}/join`));
  if (!permitted) fail("flow_request_scope_guard_failed");
  const headers = {};
  for (const [key, value] of Object.entries(credential.headers)) {
    if (["x-flow-principal", "x-flow-timestamp", "x-flow-signature"].includes(key.toLowerCase())) headers[key] = value;
  }
  if (Object.keys(headers).length !== 3) fail("signed_context_headers_missing");
  // Respect the minimal fixture's 1 request/second service limit.
  await sleep(1200);
  return context.request.fetch(`${flowBase}${route}`, { method, headers, data, timeout });
}

async function roomList(credential) {
  const response = await flowRequest(credential, "GET", "/v1/rooms");
  if (response.status() !== 200) fail(`list_rooms_http_${response.status()}`);
  const body = await response.json();
  const items = body.items ?? body.rooms;
  if (!Array.isArray(items)) fail("invalid_room_list");
  return items;
}

function rememberRoom(value) {
  if (!value || !/^[a-f0-9-]{36}$/i.test(value.id) || value.name !== roomName ||
      value.metadata?.test_run_id !== runId || value.organization_id !== organization ||
      value.project_id !== project.id || value.service_instance_id !== flow.id || value.mode !== "p2p") fail("created_room_identity_guard_failed");
  room = value;
  roomCreatedAt = Date.now();
  report.flow.room_id = room.id;
  report.flow.cleanup = "pending_idle_expiry";
}

async function checkFixtures() {
  for (const fixture of [flow, flash]) {
    const response = await context.request.get(`${base}${servicePath(fixture)}`, { timeout });
    if (response.status() !== 200) fail(`fixture_read_http_${response.status()}`);
    const item = await response.json();
    if (item.id !== fixture.id || item.organization_id !== organization || item.project_id !== project.id ||
        item.name !== fixture.name || !item.name.startsWith("e2e-") ||
        item.spec?.metadata?.purpose !== "dedicated-browser-e2e" || item.state !== "ready") fail("dedicated_ready_fixture_guard_failed");
    if (fixture === flash && (item.spec.exposure?.type !== "internal" || item.spec.replicas !== 1)) fail("private_flash_fixture_guard_failed");
  }
}

async function testFlow() {
  report.phase = "flow_contract";
  const response = await context.request.get(`${flowBase}/openapi.json`, { timeout });
  if (response.status() !== 200) fail(`openapi_http_${response.status()}`);
  const schema = await response.json();
  if (!schema.paths?.["/v1/rooms"]?.post || !schema.paths?.["/v1/rooms/{room_id}"]?.get ||
      !schema.paths?.["/v1/rooms/{room_id}/join"]?.post) fail("room_contract_missing");
  const credential = await issueContext(["flow.room.create", "flow.room.read", "flow.room.join"]);
  if ((await roomList(credential)).length !== 0) fail("fixture_has_existing_rooms_no_mutation_performed");
  report.phase = "flow_create";
  createAttempted = true;
  report.flow.cleanup = "creation_outcome_pending";
  await save();
  const created = await flowRequest(credential, "POST", "/v1/rooms", {
    mode: "p2p", name: roomName, max_participants: 2,
    metadata: { purpose: "dedicated-e2e-functional", test_run_id: runId },
  });
  report.flow.create_http = created.status();
  if (created.status() !== 201) fail(`room_create_http_${created.status()}`);
  rememberRoom(await created.json());
  await save();
  report.phase = "flow_join";
  const joined = await flowRequest(credential, "POST", `/v1/rooms/${room.id}/join`, {
    display_name: "dedicated-e2e", can_publish: false, can_subscribe: true,
  });
  report.flow.join_http = joined.status();
  if (joined.status() !== 200) fail(`room_join_http_${joined.status()}`);
  const join = await joined.json();
  const iceKinds = new Set((join.connection?.ice?.ice_servers ?? []).flatMap((entry) => entry.urls ?? []).map((url) => String(url).split(":")[0]));
  if (join.mode !== "p2p" || join.connection?.protocol !== "flow-signaling.v1" ||
      !join.connection.urls?.length || !join.connection.urls.every((url) => new URL(url).protocol === "wss:") ||
      !iceKinds.has("stun") || !iceKinds.has("turn")) fail("p2p_join_contract_invalid");
  report.flow.mode = "p2p";
  report.flow.signaling_protocol = join.connection.protocol;
  report.flow.ice_kinds = [...iceKinds];
  const read = await flowRequest(credential, "GET", `/v1/rooms/${room.id}`);
  report.flow.read_http = read.status();
  if (read.status() !== 200 || (await read.json()).id !== room.id) fail("room_readback_failed");
  report.flow.result = "passed_create_join_readback_not_media_delivery";
  await save();
}

async function testFlash(page) {
  report.phase = "flash_shell";
  const errors = [];
  let frames = "";
  let dialog;
  page.on("pageerror", () => errors.push("pageerror"));
  page.on("websocket", (socket) => {
    const url = new URL(socket.url());
    if (url.origin !== base.replace("https:", "wss:") || url.pathname !== `${servicePath(flash)}/exec`) return;
    socket.on("framereceived", ({ payload }) => { frames = (frames + payload.toString()).slice(-8192); });
    socket.on("socketerror", () => errors.push("shell_socket_error"));
  });
  try {
    await page.goto(`${base}/flash/services/${flash.id}`, { waitUntil: "domcontentloaded" });
    await page.getByRole("heading", { name: flash.name, exact: true }).waitFor();
    await page.getByRole("button", { name: "Web Shell", exact: true }).click();
    dialog = page.getByRole("dialog", { name: `${flash.name} Web Shell`, exact: true });
    await dialog.getByRole("button", { name: "接続", exact: true }).click();
    await dialog.getByText("接続済み", { exact: true }).waitFor();
    frames = "";
    await dialog.locator(".xterm-helper-textarea").focus();
    await page.keyboard.type("pwd");
    await page.keyboard.press("Enter");
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const cleaned = frames.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "").replaceAll("\r", "");
      const cwd = cleaned.split("\n").find((line) => /^\/(?:[A-Za-z0-9._-]+\/?)*$/.test(line));
      if (cwd) { report.flash.pwd_output = cwd; break; }
      await sleep(100);
    }
    if (!report.flash.pwd_output || errors.length) fail("flash_pwd_or_browser_check_failed");
    report.flash.result = "passed";
    await page.screenshot({ path: path.join(directory, "flash-pwd.png") });
  } finally {
    if (dialog && await dialog.isVisible()) {
      const disconnect = dialog.getByRole("button", { name: "切断", exact: true });
      if (await disconnect.count() && await disconnect.isEnabled()) {
        await disconnect.click();
        await dialog.getByText("切断済み", { exact: true }).waitFor();
        report.flash.disconnected = true;
      }
    }
  }
}

async function cleanupRoom() {
  // Recover only this run's uniquely marked room after an ambiguous POST outcome.
  if (createAttempted && !room) {
    const credential = await issueContext(["flow.room.read"]);
    const matching = (await roomList(credential)).filter((item) => item.name === roomName && item.metadata?.test_run_id === runId);
    if (matching.length !== 1) fail("creation_outcome_uncertain_manual_scoped_check_required");
    rememberRoom(matching[0]);
  }
  await revokeContexts();
  if (!room) return;
  const due = roomCreatedAt + idleCleanupDelay;
  report.flow.cleanup_check_at = new Date(due).toISOString();
  await save();
  console.log(`Functional checks finished; waiting for documented room expiry until ${report.flow.cleanup_check_at}`);
  await sleep(Math.max(0, due - Date.now()));
  const credential = await issueContext(["flow.room.read"]);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const response = await flowRequest(credential, "GET", `/v1/rooms/${room.id}`);
    if (response.status() === 404 && !(await roomList(credential)).some((item) => item.id === room.id)) {
      report.flow.cleanup = "verified_automatic_idle_expiry";
      report.flow.cleanup_read_http = 404;
      report.flow.cleanup_list_http = 200;
      return;
    }
    if (![200, 404].includes(response.status())) fail(`cleanup_read_http_${response.status()}`);
    await sleep(20_000);
  }
  fail("room_cleanup_unconfirmed_do_not_delete_fixture_service");
}

try {
  const envFile = process.env.HETEROCLOUD_FUNCTIONAL_E2E_ENV_FILE ?? path.join(privateRoot, "e2e.env");
  account = {};
  for (const line of (await privateFile(envFile)).split(/\r?\n/)) {
    if (!line.trim() || line.startsWith("#")) continue;
    const match = /^(E2E_USERNAME|E2E_PASSWORD)=([^\s]+)$/.exec(line);
    if (!match || Object.hasOwn(account, match[1])) fail("credential_env_requires_unique_unquoted_e2e_keys");
    account[match[1]] = match[2];
  }
  if (!account.E2E_USERNAME?.startsWith("heterocloud-e2e-") || !account.E2E_PASSWORD) fail("dedicated_e2e_account_required");
  const fixtures = JSON.parse(await privateFile(process.env.HETEROCLOUD_FUNCTIONAL_E2E_FIXTURES ?? path.join(privateRoot, "e2e-fixtures.json")));
  organization = process.env.HETEROCLOUD_FUNCTIONAL_E2E_ORGANIZATION_ID;
  if (!organization || organization !== fixtures.organization_id || !/^[a-f0-9-]{36}$/i.test(organization)) fail("explicit_fixture_organization_required");
  [project, flow, flash] = ["projects", "realtime/services", "flash/services"].map((collection) => {
    const matches = fixtures.resources.filter((item) => item.collection === collection);
    if (matches.length !== 1 || !/^[a-f0-9-]{36}$/i.test(matches[0].id)) fail("unique_fixture_manifest_entries_required");
    return matches[0];
  });
  const artifactRoot = process.env.HETEROCLOUD_FUNCTIONAL_E2E_ARTIFACT_DIR ?? path.join(privateRoot, "functional-artifacts");
  await fs.mkdir(artifactRoot, { recursive: true, mode: 0o700 });
  directory = await fs.mkdtemp(path.join(artifactRoot, "run-"));
  await fs.chmod(directory, 0o700);
  report.organization_id = organization;
  report.flow.service_id = flow.id;
  report.flash.service_id = flash.id;
  browser = await chromium.launch({ headless: true });
  context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, serviceWorkers: "block" });
  await context.addInitScript((org) => localStorage.setItem("heterocloud.active-organization", org), organization);
  await context.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const foreignOrg = url.pathname.startsWith("/api/v1/organizations/") && !url.pathname.startsWith(`/api/v1/organizations/${organization}/`);
    if (url.origin !== base || foreignOrg || !["GET", "HEAD", "OPTIONS"].includes(request.method())) await route.abort();
    else await route.continue();
  });
  const page = await context.newPage();
  page.on("pageerror", () => report.browser_errors.push("pageerror"));
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.origin === base && ["/login", "/api/v1/auth/oidc/start", "/api/v1/auth/oidc/callback"].includes(url.pathname)) {
      report.login_http.push({ path: url.pathname, status: response.status() });
    }
  });
  page.setDefaultTimeout(timeout);
  page.setDefaultNavigationTimeout(timeout);
  report.phase = "public_oidc_login";
  await page.goto(`${base}/login`, { waitUntil: "domcontentloaded" });
  await page.locator('a[href="/api/v1/auth/oidc/start"]').click();
  await page.waitForURL((url) => url.origin === base && url.pathname.startsWith("/id/realms/heterocloud/"));
  await page.locator('input[name="username"]').fill(account.E2E_USERNAME);
  await page.locator('input[name="password"]').fill(account.E2E_PASSWORD);
  await page.locator('#kc-login, input[type="submit"], button[type="submit"]').first().click();
  await page.waitForURL((url) => url.origin === base && !url.pathname.startsWith("/id/") && url.pathname !== "/login");
  await session();
  report.login = "passed_normal_public_chromium";
  report.phase = "fixture_preflight";
  await checkFixtures();
  await testFlow();
  await testFlash(page);
} catch (error) {
  recordError(error);
} finally {
  // Close the browser page first so shell disconnection cannot be delayed by room expiry.
  if (context) {
    for (const page of context.pages()) await page.close().catch(() => {});
    report.flash.browser_pages_closed = true;
    try { await cleanupRoom(); } catch (error) { recordError(error, "room_cleanup"); }
    await revokeContexts();
    report.flow.unrevoked_context_count = issuedContexts.size;
    await context.close().catch(() => {});
  }
  if (browser) await browser.close().catch(() => {});
  report.finished_at = new Date().toISOString();
  report.result = report.errors.length === 0 && report.browser_errors.length === 0 && report.flow.result && report.flash.result === "passed" &&
    report.flow.cleanup === "verified_automatic_idle_expiry" && issuedContexts.size === 0 ? "passed" : "failed";
  await save();
  console.log(JSON.stringify({ result: report.result, phase: report.phase, errors: report.errors, private_artifacts: directory ?? null }));
  process.exitCode = report.result === "passed" ? 0 : 1;
}
