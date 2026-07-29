import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

const webuiUrl = new URL("./", import.meta.url);
const indexHtml = await readFile(new URL("index.html", webuiUrl), "utf8");
const appSource = await readFile(new URL("app.js", webuiUrl), "utf8");
const baseUrl = "http://127.0.0.1:18088/ui/";
const accessTokenKey = "heteronetwork_access_token";
const accessTokenExpiresAtKey = "heteronetwork_access_token_expires_at";
const operatorTokenKey = "heteronetwork_operator_token";

test("startup silently restores an OIDC session through the refresh cookie", async (t) => {
  let refreshCalls = 0;
  const overviewAuthorizations = [];
  const window = bootApp(t, {
    fetch: () => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        assert.equal(options.method, "POST");
        assert.equal(options.body, undefined);
        return jsonResponse({ access_token: "restored-token", expires_in: 300 });
      }
      if (path === "/v1/admin/overview") {
        overviewAuthorizations.push(authorization(options));
        return jsonResponse(overview());
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);

  assert.equal(refreshCalls, 1);
  assert.deepEqual(overviewAuthorizations, ["Bearer restored-token"]);
  assert.equal(window.sessionStorage.getItem(accessTokenKey), "restored-token");
  assert.ok(Number(window.sessionStorage.getItem(accessTokenExpiresAtKey)) > Date.now() + 250_000);
  assert.equal(window.localStorage.getItem(accessTokenKey), null);
});

test("overview HA stays degraded until every desired Keycloak replica is ready", async (t) => {
  const window = bootApp(t, {
    storage: {
      [accessTokenKey]: "overview-token",
      [accessTokenExpiresAtKey]: String(Date.now() + 300_000),
    },
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") return jsonResponse(uiConfig());
      if (path === "/v1/admin/overview") {
        const body = overview();
        body.metrics.ha_ready = true;
        return jsonResponse(body);
      }
      if (path === "/v1/admin/keycloak-placement") {
        return jsonResponse({
          desired_replicas: 3,
          replicas: [
            { ready: true },
            { ready: true },
            { ready: false },
          ],
        });
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);

  const haCard = Array.from(window.document.querySelectorAll(".metric-card"))
    .find((card) => card.textContent.includes("High availability"));
  assert.ok(haCard);
  assert.match(haCard.textContent, /Degraded/);
  assert.match(window.document.querySelector("#view-content").textContent, /HA degraded/);
});

test("an OIDC token expiring within 30 seconds refreshes before the API request", async (t) => {
  let refreshCalls = 0;
  const overviewAuthorizations = [];
  const window = bootApp(t, {
    storage: {
      [accessTokenKey]: "expiring-token",
      [accessTokenExpiresAtKey]: String(Date.now() + 5_000),
    },
    fetch: () => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return jsonResponse({ access_token: "renewed-token", expires_in: 180 });
      }
      if (path === "/v1/admin/overview") {
        overviewAuthorizations.push(authorization(options));
        return jsonResponse(overview());
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);

  assert.equal(refreshCalls, 1);
  assert.deepEqual(overviewAuthorizations, ["Bearer renewed-token"]);
  assert.equal(window.sessionStorage.getItem(accessTokenKey), "renewed-token");
});

test("a transient proactive refresh failure preserves a still-valid OIDC session", async (t) => {
  let refreshCalls = 0;
  const overviewAuthorizations = [];
  const window = bootApp(t, {
    storage: {
      [accessTokenKey]: "still-valid-token",
      [accessTokenExpiresAtKey]: String(Date.now() + 20_000),
    },
    fetch: () => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return jsonResponse({ error: "identity provider is temporarily unavailable" }, 503);
      }
      if (path === "/v1/admin/overview") {
        overviewAuthorizations.push(authorization(options));
        return jsonResponse(overview());
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);

  assert.equal(refreshCalls, 1);
  assert.deepEqual(overviewAuthorizations, ["Bearer still-valid-token"]);
  assert.equal(window.sessionStorage.getItem(accessTokenKey), "still-valid-token");
});

test("a legacy OIDC token refreshes after 401 and retries the original request once", async (t) => {
  let refreshCalls = 0;
  const overviewAuthorizations = [];
  const window = bootApp(t, {
    storage: { [accessTokenKey]: "legacy-token" },
    fetch: () => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return jsonResponse({ access_token: "refreshed-token", expires_in: 180 });
      }
      if (path === "/v1/admin/overview") {
        const header = authorization(options);
        overviewAuthorizations.push(header);
        return header === "Bearer legacy-token" ? jsonResponse({ error: "expired" }, 401) : jsonResponse(overview());
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);

  assert.equal(refreshCalls, 1);
  assert.deepEqual(overviewAuthorizations, ["Bearer legacy-token", "Bearer refreshed-token"]);
});

test("parallel API 401 responses share one refresh request", async (t) => {
  let refreshCalls = 0;
  let resolveRefresh;
  const protectedCalls = [];
  const window = bootApp(t, {
    storage: { [accessTokenKey]: "parallel-old-token" },
    fetch: () => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return new Promise((resolve) => {
          resolveRefresh = () => resolve(jsonResponse({ access_token: "parallel-new-token", expires_in: 180 }));
        });
      }
      if (path === "/v1/admin/overview") return jsonResponse(overview());
      if (path === "/v1/admin/topology" || path === "/v1/admin/policy") {
        const header = authorization(options);
        protectedCalls.push({ header, path });
        if (header === "Bearer parallel-old-token") return jsonResponse({ error: "expired" }, 401);
        if (path === "/v1/admin/policy") return jsonResponse({ cluster_policy: clusterPolicy() });
        return jsonResponse(topology());
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);
  window.document.querySelector('[data-view="topology"]').click();
  await waitFor(() => protectedCalls.filter((call) => call.header === "Bearer parallel-old-token").length === 2);

  assert.equal(refreshCalls, 1);
  resolveRefresh();
  await waitFor(() => protectedCalls.filter((call) => call.header === "Bearer parallel-new-token").length === 2);

  assert.equal(refreshCalls, 1);
  assert.deepEqual(
    protectedCalls.filter((call) => call.header === "Bearer parallel-new-token").map((call) => call.path).sort(),
    ["/v1/admin/policy", "/v1/admin/topology"]
  );
});

test("logout bypasses a Web Lock held by a stalled refresh", async (t) => {
  let refreshCalls = 0;
  let logoutCalls = 0;
  let resolveRefresh;
  const locks = serialWebLocks();
  const window = bootApp(t, {
    locks,
    storage: { [accessTokenKey]: "race-old-token" },
    fetch: () => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({
          session_logout_endpoint: "/session/logout",
          session_refresh_endpoint: "/session/refresh",
        }));
      }
      if (path === "/v1/admin/overview") return jsonResponse(overview());
      if (path === "/v1/admin/topology" || path === "/v1/admin/policy") {
        return jsonResponse({ error: "expired" }, 401);
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return new Promise((resolve) => {
          resolveRefresh = () => resolve(jsonResponse({ access_token: "race-new-token", expires_in: 180 }));
        });
      }
      if (path === "/session/logout") {
        logoutCalls += 1;
        assert.equal(options.method, "POST");
        return jsonResponse({ ok: true });
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);
  window.document.querySelector('[data-view="topology"]').click();
  await waitFor(() => refreshCalls === 1);

  window.document.querySelector("#auth-button").click();
  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
  assert.equal(window.document.querySelector("#dashboard").hidden, true);
  assert.equal(window.document.querySelector("#auth-panel").hidden, false);
  await waitFor(() => logoutCalls === 1);
  assert.equal(locks.requests.length, 1);
  assert.equal(window.document.querySelector("#view-content").innerHTML, "");

  resolveRefresh();
  await waitFor(() => logoutCalls === 2);
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
  assert.equal(window.sessionStorage.getItem(accessTokenExpiresAtKey), null);
  assert.deepEqual(
    locks.requests.map((request) => [request.name, request.mode]),
    [
      ["heteronetwork-auth-session", "exclusive"],
    ]
  );
});

test("explicit sign out clears browser state immediately when cookie cleanup stalls", async (t) => {
  let logoutCalls = 0;
  let logoutMethod;
  let logoutBody;
  let logoutTimeout;
  const window = bootApp(t, {
    storage: {
      [accessTokenKey]: "logout-token",
      [accessTokenExpiresAtKey]: String(Date.now() + 300_000),
    },
    setTimeout: (callback) => {
      logoutTimeout = callback;
      return 1;
    },
    clearTimeout: () => {},
    fetch: (browser) => async (input, options = {}) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_logout_endpoint: "/session/logout" }));
      }
      if (path === "/v1/admin/overview") return jsonResponse(overview());
      if (path === "/session/logout") {
        logoutCalls += 1;
        logoutMethod = options.method;
        logoutBody = options.body;
        assert.equal(browser.sessionStorage.getItem(accessTokenKey), null);
        return new Promise(() => {});
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);
  window.document.querySelector("#auth-button").click();

  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
  assert.equal(window.sessionStorage.getItem(accessTokenExpiresAtKey), null);
  assert.equal(window.document.querySelector("#dashboard").hidden, true);
  assert.equal(window.document.querySelector("#auth-panel").hidden, false);
  await waitFor(() => logoutCalls === 1 && typeof logoutTimeout === "function");
  assert.equal(logoutMethod, "POST");
  assert.equal(logoutBody, undefined);
  logoutTimeout();
  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
});

test("a late refresh without Web Locks triggers a second cookie cleanup", async (t) => {
  let logoutCalls = 0;
  let refreshCalls = 0;
  let resolveRefresh;
  const window = bootApp(t, {
    storage: { [accessTokenKey]: "late-old-token" },
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({
          session_logout_endpoint: "/session/logout",
          session_refresh_endpoint: "/session/refresh",
        }));
      }
      if (path === "/v1/admin/overview") return jsonResponse(overview());
      if (path === "/v1/admin/topology" || path === "/v1/admin/policy") {
        return jsonResponse({ error: "expired" }, 401);
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return new Promise((resolve) => {
          resolveRefresh = () => resolve(jsonResponse({
            access_token: "late-new-token",
            expires_in: 180,
          }));
        });
      }
      if (path === "/session/logout") {
        logoutCalls += 1;
        return jsonResponse({ status: "logged_out" });
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => !window.document.querySelector("#dashboard").hidden);
  window.document.querySelector('[data-view="topology"]').click();
  await waitFor(() => refreshCalls === 1);
  window.document.querySelector("#auth-button").click();
  await waitFor(() => logoutCalls === 1);
  resolveRefresh();
  await waitFor(() => logoutCalls === 2);

  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
  assert.equal(window.document.querySelector("#dashboard").hidden, true);
});

test("a delayed overview response cannot restore the dashboard after logout", async (t) => {
  let logoutCalls = 0;
  let overviewCalls = 0;
  let resolveOverview;
  const window = bootApp(t, {
    storage: { [accessTokenKey]: "delayed-overview-token" },
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_logout_endpoint: "/session/logout" }));
      }
      if (path === "/v1/admin/overview") {
        overviewCalls += 1;
        return new Promise((resolve) => {
          resolveOverview = () => resolve(jsonResponse(overview()));
        });
      }
      if (path === "/session/logout") {
        logoutCalls += 1;
        return jsonResponse({ status: "logged_out" });
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => overviewCalls === 1 && typeof resolveOverview === "function");
  window.document.querySelector("#auth-button").click();
  await waitFor(() => logoutCalls === 1);
  resolveOverview();
  await new Promise((resolve) => setTimeout(resolve, 0));

  assert.equal(window.document.querySelector("#dashboard").hidden, true);
  assert.equal(window.document.querySelector("#auth-panel").hidden, false);
  assert.equal(window.document.querySelector("#view-content").innerHTML, "");
  assert.equal(window.document.querySelector("#cluster-name").textContent, "-");

  const locale = window.document.querySelector("#locale-select");
  locale.value = "ja";
  locale.dispatchEvent(new window.Event("change", { bubbles: true }));
  assert.equal(window.document.querySelector("#dashboard").hidden, true);
  assert.equal(window.document.querySelector("#auth-panel").hidden, false);
});

test("explicit logout notifies other tabs without broadcasting credentials", async (t) => {
  const channels = broadcastChannelHarness();
  const tabFetch = () => async (input) => {
    const path = requestPath(input);
    if (path === "/ui/config") {
      return jsonResponse(uiConfig({ session_logout_endpoint: "/session/logout" }));
    }
    if (path === "/v1/admin/overview") return jsonResponse(overview());
    if (path === "/session/logout") return jsonResponse({ ok: true });
    throw new Error(`unexpected fetch: ${path}`);
  };
  const first = bootApp(t, {
    BroadcastChannel: channels.BroadcastChannel,
    storage: { [accessTokenKey]: "first-tab-token" },
    fetch: tabFetch,
  });
  const second = bootApp(t, {
    BroadcastChannel: channels.BroadcastChannel,
    storage: { [accessTokenKey]: "second-tab-token" },
    fetch: tabFetch,
  });

  await waitFor(() => (
    !first.document.querySelector("#dashboard").hidden
    && !second.document.querySelector("#dashboard").hidden
  ));
  first.document.querySelector("#auth-button").click();
  await waitFor(() => second.sessionStorage.getItem(accessTokenKey) === null);

  assert.equal(second.document.querySelector("#dashboard").hidden, true);
  assert.equal(second.document.querySelector("#auth-panel").hidden, false);
  assert.equal(channels.messages.length, 1);
  assert.equal(channels.messages[0].type, "logout");
  assert.equal(JSON.stringify(channels.messages).includes("first-tab-token"), false);
  assert.equal(JSON.stringify(channels.messages).includes("second-tab-token"), false);
});

test("an operator token never calls the OIDC refresh endpoint", async (t) => {
  let refreshCalls = 0;
  let overviewCalls = 0;
  const window = bootApp(t, {
    storage: { [operatorTokenKey]: "operator-token" },
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return jsonResponse({ access_token: "unexpected-token", expires_in: 180 });
      }
      if (path === "/v1/admin/overview") {
        overviewCalls += 1;
        return jsonResponse({ error: "invalid operator token" }, 401);
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => overviewCalls === 1 && window.sessionStorage.getItem(operatorTokenKey) === null);

  assert.equal(refreshCalls, 0);
  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
  assert.match(window.document.querySelector("#auth-error").textContent, /session expired/i);
});

test("a terminal refresh rejection clears the OIDC session", async (t) => {
  let refreshCalls = 0;
  let overviewCalls = 0;
  const window = bootApp(t, {
    storage: {
      [accessTokenKey]: "terminal-token",
      [accessTokenExpiresAtKey]: String(Date.now() + 5_000),
      [operatorTokenKey]: "preserved-operator-token",
    },
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return jsonResponse({ error: "refresh token expired" }, 403);
      }
      if (path === "/v1/admin/overview") {
        overviewCalls += 1;
        return jsonResponse(overview());
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => window.sessionStorage.getItem(accessTokenKey) === null);

  assert.equal(refreshCalls, 1);
  assert.equal(overviewCalls, 0);
  assert.equal(window.sessionStorage.getItem(accessTokenExpiresAtKey), null);
  assert.equal(window.sessionStorage.getItem(operatorTokenKey), "preserved-operator-token");
  assert.match(window.document.querySelector("#auth-error").textContent, /session expired/i);
});

test("a second 401 stops retrying and clears only the OIDC token", async (t) => {
  let refreshCalls = 0;
  let overviewCalls = 0;
  const window = bootApp(t, {
    storage: {
      [accessTokenKey]: "retry-old-token",
      [operatorTokenKey]: "preserved-operator-token",
    },
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        return jsonResponse(uiConfig({ session_refresh_endpoint: "/session/refresh" }));
      }
      if (path === "/session/refresh") {
        refreshCalls += 1;
        return jsonResponse({ access_token: "retry-new-token", expires_in: 180 });
      }
      if (path === "/v1/admin/overview") {
        overviewCalls += 1;
        return jsonResponse({ error: "still unauthorized" }, 401);
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => overviewCalls === 2 && window.sessionStorage.getItem(accessTokenKey) === null);

  assert.equal(refreshCalls, 1);
  assert.equal(overviewCalls, 2);
  assert.equal(window.sessionStorage.getItem(operatorTokenKey), "preserved-operator-token");
  assert.equal(window.sessionStorage.getItem(accessTokenExpiresAtKey), null);
});

test("browser-direct PKCE callback and token exchange are disabled", async (t) => {
  let configCalls = 0;
  let tokenEndpointCalls = 0;
  const window = bootApp(t, {
    url: `${baseUrl}?code=authorization-code&state=login-state`,
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        configCalls += 1;
        return jsonResponse(uiConfig({
          authorization_endpoint: "https://identity.example/authorize",
          client_id: "web-ui",
          token_endpoint: "/oidc/token",
        }));
      }
      if (path === "/oidc/token") {
        tokenEndpointCalls += 1;
        return jsonResponse({ access_token: "unexpected-token", expires_in: 240 });
      }
      throw new Error(`unexpected fetch: ${path}`);
    },
  });

  await waitFor(() => configCalls === 1 && !window.document.querySelector("#auth-panel").hidden);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(tokenEndpointCalls, 0);
  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);

  window.document.querySelector("#oidc-login").click();
  await waitFor(() => /server-side sign-in is unavailable/i.test(
    window.document.querySelector("#auth-error").textContent
  ));

  assert.equal(tokenEndpointCalls, 0);
  assert.equal(window.sessionStorage.getItem(accessTokenKey), null);
  assert.doesNotMatch(appSource, /pkce|heteronetwork_login_state|token_endpoint/i);
});

test("device login poll stores access token expiry metadata", async (t) => {
  let configCalls = 0;
  const popup = {
    closed: false,
    close() { this.closed = true; },
    location: { replace() {} },
    opener: null,
  };
  const window = bootApp(t, {
    immediateTimeout: true,
    fetch: () => async (input) => {
      const path = requestPath(input);
      if (path === "/ui/config") {
        configCalls += 1;
        return jsonResponse(uiConfig({
          device_login_endpoint: "/device/start",
          device_login_poll_endpoint: "/device/poll",
        }));
      }
      if (path === "/device/start") {
        return jsonResponse({
          expires_in: 600,
          handle: "device-handle",
          interval: 1,
          user_code: "TEST-CODE",
          verification_uri: "https://identity.example/device",
        });
      }
      if (path === "/device/poll") {
        return jsonResponse({
          access_token: "device-token",
          expires_in: 210,
          status: "complete",
        });
      }
      if (path === "/v1/admin/overview") return jsonResponse(overview());
      throw new Error(`unexpected fetch: ${path}`);
    },
    open: () => popup,
  });

  await waitFor(() => configCalls === 1);
  await new Promise((resolve) => setTimeout(resolve, 0));
  window.document.querySelector("#oidc-login").click();
  await waitFor(() => !window.document.querySelector("#dashboard").hidden);

  assert.equal(window.sessionStorage.getItem(accessTokenKey), "device-token");
  assert.ok(Number(window.sessionStorage.getItem(accessTokenExpiresAtKey)) > Date.now() + 180_000);
  assert.equal(popup.closed, true);
});

function bootApp(t, options) {
  const dom = new JSDOM(indexHtml, {
    runScripts: "outside-only",
    url: options.url || baseUrl,
  });
  t.after(() => dom.window.close());
  const { window } = dom;
  window.console.error = () => {};
  window.confirm = () => true;
  window.Headers = globalThis.Headers;
  window.Response = globalThis.Response;
  window.mermaid = {
    initialize() {},
    render: async () => ({ svg: '<svg viewBox="0 0 800 400"></svg>' }),
  };
  Object.entries(options.storage || {}).forEach(([key, value]) => {
    window.sessionStorage.setItem(key, value);
  });
  if (options.immediateTimeout) {
    window.setTimeout = (callback) => {
      window.queueMicrotask(callback);
      return 1;
    };
  }
  if (options.setTimeout) window.setTimeout = options.setTimeout;
  if (options.clearTimeout) window.clearTimeout = options.clearTimeout;
  if (options.locks) {
    Object.defineProperty(window.navigator, "locks", {
      configurable: true,
      value: options.locks,
    });
  }
  if (options.BroadcastChannel) window.BroadcastChannel = options.BroadcastChannel;
  if (options.open) window.open = options.open;
  window.fetch = options.fetch(window);
  window.eval(appSource);
  return window;
}

function requestPath(input) {
  return new URL(String(input), baseUrl).pathname;
}

function authorization(options) {
  return new Headers(options.headers || {}).get("Authorization");
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
    status,
  });
}

function serialWebLocks() {
  let tail = Promise.resolve();
  const requests = [];
  return {
    requests,
    request(name, options, callback) {
      requests.push({ mode: options.mode, name });
      const result = tail.then(() => callback({ mode: options.mode, name }));
      tail = result.catch(() => {});
      return result;
    },
  };
}

function broadcastChannelHarness() {
  const channels = new Map();
  const messages = [];
  class TestBroadcastChannel {
    constructor(name) {
      this.name = name;
      this.onmessage = null;
      if (!channels.has(name)) channels.set(name, new Set());
      channels.get(name).add(this);
    }

    postMessage(message) {
      const copy = JSON.parse(JSON.stringify(message));
      messages.push(copy);
      queueMicrotask(() => {
        channels.get(this.name).forEach((channel) => {
          if (channel !== this && channel.onmessage) channel.onmessage({ data: copy });
        });
      });
    }

    close() {
      channels.get(this.name).delete(this);
    }
  }
  return { BroadcastChannel: TestBroadcastChannel, messages };
}

function uiConfig(overrides = {}) {
  return {
    auth_enabled: true,
    bootstrap_required: false,
    client_enrollment_enabled: false,
    enabled: true,
    local_agent: false,
    node_enrollment_enabled: false,
    operator_token_enabled: true,
    provider: "keycloak",
    ...overrides,
  };
}

function clusterPolicy() {
  return {
    acl_rules: [],
    allow_ipv6_direct: true,
    allow_nat_traversal: true,
    allow_relay_fallback: true,
    overlay_block_size: 4,
    overlay_direct_shortcut_limit: 0,
    overlay_max_degree: 4,
    path_state_ttl_seconds: 90,
  };
}

function overview() {
  return {
    cluster_id: "cluster-test",
    cluster_policy: clusterPolicy(),
    generated_at: "2026-07-29T12:00:00Z",
    metrics: {
      active_service_instance_count: 0,
      healthy_node_count: 0,
      node_count: 0,
      path_count: 0,
    },
    nat_discovery: {},
    nodes: [],
    paths: [],
    service_directory: {
      bootstrap_endpoints: [],
      instances: [],
    },
  };
}

function topology() {
  return {
    algorithm: "test",
    cluster_id: "cluster-test",
    direct_shortcut_limit: 0,
    edges: [],
    fanout: 4,
    generated_at: "2026-07-29T12:00:00Z",
    groups: [],
    max_degree: 4,
    nodes: [],
    root_group_id: null,
  };
}

async function waitFor(predicate, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("timed out waiting for condition");
}
