import assert from "node:assert/strict";
import test from "node:test";

class MemoryStorage {
  #values = new Map();
  getItem(key) {
    return this.#values.has(key) ? this.#values.get(key) : null;
  }
  setItem(key, value) {
    this.#values.set(key, String(value));
  }
  removeItem(key) {
    this.#values.delete(key);
  }
  clear() {
    this.#values.clear();
  }
}

globalThis.sessionStorage = new MemoryStorage();
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: {},
  writable: true,
});
const { HeteroNetworkApi } = await import("./api.js");

const ACCESS_TOKEN_KEY = "heteronetwork_access_token";
const ACCESS_TOKEN_EXPIRES_KEY = "heteronetwork_access_token_expires_at";
const OPERATOR_TOKEN_KEY = "heteronetwork_operator_token";

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test.beforeEach(() => {
  sessionStorage.clear();
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {},
    writable: true,
  });
});

test("refresh cookie restores an OIDC browser session", async () => {
  const client = new HeteroNetworkApi();
  client.config = { session_refresh_endpoint: "/ui/auth/refresh" };
  globalThis.fetch = async (url) => {
    assert.equal(url, "/ui/auth/refresh");
    return json({ access_token: "restored", expires_in: 600 });
  };

  await client.refreshSession();

  assert.equal(client.token, "restored");
  assert.equal(client.tokenType, "oidc");
  assert.equal(sessionStorage.getItem(ACCESS_TOKEN_KEY), "restored");
  assert.ok(Number(sessionStorage.getItem(ACCESS_TOKEN_EXPIRES_KEY)) > Date.now());
});

test("an expiring OIDC token refreshes before its API request", async () => {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, "old-token");
  sessionStorage.setItem(ACCESS_TOKEN_EXPIRES_KEY, String(Date.now() + 5_000));
  const client = new HeteroNetworkApi();
  client.config = { session_refresh_endpoint: "/refresh" };
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push([url, options?.headers?.get?.("Authorization")]);
    if (url === "/refresh") return json({ access_token: "new-token", expires_in: 600 });
    return json({ ok: true });
  };

  await client.request("/v1/admin/overview");

  assert.deepEqual(calls, [
    ["/refresh", undefined],
    ["/v1/admin/overview", "Bearer new-token"],
  ]);
});

test("a transient proactive refresh failure keeps a still-valid token", async () => {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, "still-valid");
  sessionStorage.setItem(ACCESS_TOKEN_EXPIRES_KEY, String(Date.now() + 20_000));
  const client = new HeteroNetworkApi();
  client.config = { session_refresh_endpoint: "/refresh" };
  globalThis.fetch = async (url, options) => {
    if (url === "/refresh") return json({ error: "provider unavailable" }, 503);
    assert.equal(options.headers.get("Authorization"), "Bearer still-valid");
    return json({ ok: true });
  };

  assert.deepEqual(await client.request("/v1/admin/overview"), { ok: true });
  assert.equal(client.token, "still-valid");
});

test("parallel 401 responses share one refresh operation", async () => {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, "legacy-token");
  const client = new HeteroNetworkApi();
  client.config = { session_refresh_endpoint: "/refresh" };
  let refreshCount = 0;
  globalThis.fetch = async (url, options) => {
    if (url === "/refresh") {
      refreshCount += 1;
      await new Promise((resolve) => setTimeout(resolve, 5));
      return json({ access_token: "fresh-token", expires_in: 600 });
    }
    return options.headers.get("Authorization") === "Bearer fresh-token"
      ? json({ ok: url })
      : json({ error: "expired" }, 401);
  };

  const results = await Promise.all([
    client.request("/v1/admin/overview"),
    client.request("/v1/admin/topology"),
  ]);

  assert.equal(refreshCount, 1);
  assert.deepEqual(results, [
    { ok: "/v1/admin/overview" },
    { ok: "/v1/admin/topology" },
  ]);
});

test("operator requests never call the OIDC refresh endpoint", async () => {
  const client = new HeteroNetworkApi();
  client.config = { session_refresh_endpoint: "/refresh" };
  client.setOperatorSession("operator-token");
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push(url);
    assert.equal(options.headers.get("Authorization"), "Bearer operator-token");
    return json({ ok: true });
  };

  await client.request("/v1/admin/overview");
  assert.deepEqual(calls, ["/v1/admin/overview"]);
});

test("terminal rejection clears only the active credential type", async () => {
  sessionStorage.setItem(OPERATOR_TOKEN_KEY, "preserved-operator");
  sessionStorage.setItem(ACCESS_TOKEN_KEY, "expired-oidc");
  const client = new HeteroNetworkApi();
  client.config = { session_refresh_endpoint: "/refresh" };
  globalThis.fetch = async (url) =>
    url === "/refresh"
      ? json({ error: "invalid refresh" }, 401)
      : json({ error: "expired" }, 401);

  await assert.rejects(client.request("/v1/admin/overview"), /authentication required/);

  assert.equal(sessionStorage.getItem(ACCESS_TOKEN_KEY), null);
  assert.equal(sessionStorage.getItem(OPERATOR_TOKEN_KEY), "preserved-operator");
});

test("a response arriving after logout cannot restore protected state", async () => {
  const client = new HeteroNetworkApi();
  client.setOperatorSession("operator-token");
  let resolveRequest;
  globalThis.fetch = () =>
    new Promise((resolve) => {
      resolveRequest = resolve;
    });
  const pending = client.request("/v1/admin/overview");
  client.clearSession();
  resolveRequest(json({ cluster_id: "stale" }));

  await assert.rejects(pending, (error) => error.sessionChanged === true);
});

test("explicit logout removes both locally stored credential types", () => {
  sessionStorage.setItem(ACCESS_TOKEN_KEY, "oidc");
  sessionStorage.setItem(OPERATOR_TOKEN_KEY, "operator");
  const client = new HeteroNetworkApi();

  client.clearSession();

  assert.equal(sessionStorage.getItem(ACCESS_TOKEN_KEY), null);
  assert.equal(sessionStorage.getItem(OPERATOR_TOKEN_KEY), null);
});
