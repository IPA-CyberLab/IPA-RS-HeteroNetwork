import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer as createHttpServer } from "node:http";
import test from "node:test";

import { createWebConsoleServer } from "../webconsole/server.mjs";

const configuredPublicOrigin = new URL(
  process.env.HETERONETWORK_WEB_PUBLIC_URL || "http://127.0.0.1:18088",
).origin;

test("standalone WebConsole serves the pinned Mermaid bundle from its own origin", async (t) => {
  const origin = await startServer(t);

  const indexResponse = await fetch(`${origin}/ui/`);
  assert.equal(indexResponse.status, 200);
  const index = await indexResponse.text();
  const mermaidScript = "/ui/vendor/mermaid.min.js";
  assert.ok(index.includes(mermaidScript));
  assert.ok(index.indexOf(mermaidScript) < index.indexOf("/ui/app.js"));

  const bundleResponse = await fetch(`${origin}${mermaidScript}`);
  assert.equal(bundleResponse.status, 200);
  assert.match(bundleResponse.headers.get("content-type") || "", /^text\/javascript\b/);
  assert.equal(bundleResponse.headers.get("cache-control"), "no-store");
  assert.equal(bundleResponse.headers.get("x-content-type-options"), "nosniff");
  const bundle = await bundleResponse.text();
  assert.ok(bundle.length > 100_000);
  assert.match(bundle, /globalThis\.mermaid=/);

  const configResponse = await fetch(`${origin}/ui/config`);
  const config = await configResponse.json();
  assert.equal(config.session_refresh_endpoint, "/ui/auth/refresh");
  assert.equal(config.session_logout_endpoint, "/ui/auth/logout");
});

test("standalone WebConsole binds OIDC state to the initiating browser", async (t) => {
  const origin = await startServer(t);
  const login = await fetch(`${origin}/ui/login`, { redirect: "manual" });
  assert.equal(login.status, 302);
  const stateCookie = login.headers.get("set-cookie") || "";
  assert.match(
    stateCookie,
    /^heteronetwork_web_login_state=[A-Za-z0-9_-]+; Path=\/ui\/callback; Max-Age=300; HttpOnly; SameSite=Lax/,
  );
  const authorization = new URL(login.headers.get("location"));
  const state = authorization.searchParams.get("state");
  assert.ok(state);

  const rejected = await fetch(
    `${origin}/ui/callback?state=${encodeURIComponent(state)}&code=test-code`,
  );
  assert.equal(rejected.status, 400);
  assert.match(
    rejected.headers.get("set-cookie") || "",
    /heteronetwork_web_login_state=; Path=\/ui\/callback; Max-Age=0/,
  );
});

test("standalone WebConsole completes PKCE from the browser-bound callback cookie", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const login = await originalFetch(`${origin}/ui/login`, { redirect: "manual" });
  const authorization = new URL(login.headers.get("location"));
  const state = authorization.searchParams.get("state");
  const cookie = (login.headers.get("set-cookie") || "").split(";", 1)[0];
  assert.ok(state);
  assert.match(cookie, /^heteronetwork_web_login_state=[A-Za-z0-9_-]+$/);

  globalThis.fetch = async (_input, init) => {
    const form = new URLSearchParams(String(init.body));
    assert.equal(form.get("grant_type"), "authorization_code");
    assert.equal(form.get("code"), "test-code");
    assert.match(form.get("code_verifier") || "", /^[A-Za-z0-9_-]{43}$/);
    return oidcResponse({
      access_token: "callback-access-token",
      refresh_token: "callback-refresh-token",
      expires_in: 300,
      refresh_expires_in: 3600,
    });
  };

  const callback = await originalFetch(
    `${origin}/ui/callback?state=${encodeURIComponent(state)}&code=test-code`,
    { headers: { Cookie: cookie } },
  );
  assert.equal(callback.status, 200);
  const policy = callback.headers.get("content-security-policy") || "";
  const nonce = /script-src 'nonce-([A-Za-z0-9_-]+)'/.exec(policy)?.[1];
  assert.ok(nonce);
  assert.match(await callback.text(), new RegExp(`<script nonce="${nonce}">`));
  assert.match(
    callback.headers.get("set-cookie") || "",
    /heteronetwork_web_login_state=; Path=\/ui\/callback; Max-Age=0/,
  );
});

test("standalone WebConsole requires exact same-origin browser headers", async (t) => {
  const origin = await startServer(t);
  const rejectedHeaders = [
    {},
    { Origin: configuredPublicOrigin },
    { "Sec-Fetch-Site": "same-origin" },
    { Origin: `${configuredPublicOrigin}/`, "Sec-Fetch-Site": "same-origin" },
    { Origin: "http://example.invalid", "Sec-Fetch-Site": "same-origin" },
    { Origin: configuredPublicOrigin, "Sec-Fetch-Site": "cross-site" },
  ];

  for (const endpoint of ["refresh", "logout"]) {
    for (const headers of rejectedHeaders) {
      const response = await fetch(`${origin}/ui/auth/${endpoint}`, { method: "POST", headers });
      assert.equal(response.status, 403);
      assert.equal(response.headers.get("set-cookie"), null);
    }
  }

  const missingSession = await fetch(`${origin}/ui/auth/refresh`, {
    method: "POST",
    headers: sessionHeaders(),
  });
  assert.equal(missingSession.status, 401);
  assert.match(missingSession.headers.get("set-cookie") || "", /Max-Age=0/);

  const logout = await fetch(`${origin}/ui/auth/logout`, {
    method: "POST",
    headers: sessionHeaders(),
  });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get("set-cookie") || "", /HttpOnly; SameSite=Strict/);
});

test("standalone WebConsole coalesces concurrent refresh rotation and briefly replays it", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const upstreamStarted = deferred();
  const releaseUpstream = deferred();
  let upstreamCalls = 0;
  globalThis.fetch = async (input, init) => {
    assert.match(String(input), /\/protocol\/openid-connect\/token$/);
    const form = new URLSearchParams(String(init.body));
    assert.equal(form.get("grant_type"), "refresh_token");
    assert.equal(form.get("refresh_token"), "refresh-token");
    upstreamCalls += 1;
    upstreamStarted.resolve();
    await releaseUpstream.promise;
    return oidcResponse({
      access_token: "refreshed-access-token",
      refresh_token: "rotated-refresh-token",
      expires_in: 300,
      refresh_expires_in: 3600,
    });
  };

  const oldCookie = refreshCookieHeader("refresh-token");
  const first = sessionRequest(originalFetch, origin, oldCookie);
  const second = sessionRequest(originalFetch, origin, oldCookie);
  await upstreamStarted.promise;
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(upstreamCalls, 1);
  releaseUpstream.resolve();

  const concurrent = await Promise.all([first, second]);
  const snapshots = await Promise.all(concurrent.map(responseSnapshot));
  assert.equal(snapshots[0].status, 200);
  assert.deepEqual(snapshots[1], snapshots[0]);
  assert.match(snapshots[0].cookie, /Max-Age=3600/);
  assert.ok(!snapshots[0].cookie.includes("rotated-refresh-token"));

  const replay = await responseSnapshot(await sessionRequest(originalFetch, origin, oldCookie));
  assert.equal(upstreamCalls, 1);
  assert.deepEqual(replay, snapshots[0]);
});

test("standalone WebConsole rejects cached old-token replay after rotated-token logout", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  let upstreamCalls = 0;
  globalThis.fetch = async (_input, init) => {
    const refreshToken = new URLSearchParams(String(init.body)).get("refresh_token");
    assert.equal(refreshToken, "refresh-token-a");
    upstreamCalls += 1;
    return oidcResponse({
      access_token: "access-token-from-a",
      refresh_token: "refresh-token-b",
      expires_in: 300,
      refresh_expires_in: 3600,
    });
  };

  const cookieA = refreshCookieHeader("refresh-token-a");
  const refreshed = await sessionRequest(originalFetch, origin, cookieA);
  assert.equal(refreshed.status, 200);
  assert.equal(upstreamCalls, 1);

  const logout = await originalFetch(`${origin}/ui/auth/logout`, {
    method: "POST",
    headers: sessionHeaders(refreshCookieHeader("refresh-token-b")),
  });
  assert.equal(logout.status, 200);

  const replay = await sessionRequest(originalFetch, origin, cookieA);
  assert.equal(replay.status, 401);
  assert.match(replay.headers.get("set-cookie") || "", /Max-Age=0/);
  assert.equal(upstreamCalls, 1);
});

test("standalone WebConsole logout invalidates an in-flight refresh", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const upstreamStarted = deferred();
  const releaseUpstream = deferred();
  globalThis.fetch = async () => {
    upstreamStarted.resolve();
    await releaseUpstream.promise;
    return oidcResponse({
      access_token: "late-access-token",
      refresh_token: "late-rotated-refresh-token",
      expires_in: 300,
      refresh_expires_in: 3600,
    });
  };

  const oldCookie = refreshCookieHeader("logout-race-refresh-token");
  const refresh = sessionRequest(originalFetch, origin, oldCookie);
  await upstreamStarted.promise;
  const logout = await originalFetch(`${origin}/ui/auth/logout`, {
    method: "POST",
    headers: sessionHeaders(oldCookie),
  });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get("set-cookie") || "", /Max-Age=0/);

  releaseUpstream.resolve();
  const refreshResponse = await refresh;
  assert.equal(refreshResponse.status, 401);
  assert.match(refreshResponse.headers.get("set-cookie") || "", /Max-Age=0/);
});

test("standalone WebConsole records logout tombstones while every refresh slot is occupied", async (t) => {
  const origin = await startServer(t, { refreshRuntime: { maxEntries: 2 } });
  const originalFetch = globalThis.fetch;
  const pending = new Map([
    ["busy-refresh-one", deferred()],
    ["busy-refresh-two", deferred()],
  ]);
  const started = new Map([
    ["busy-refresh-one", deferred()],
    ["busy-refresh-two", deferred()],
  ]);
  t.after(() => {
    globalThis.fetch = originalFetch;
    for (const [token, operation] of pending) {
      operation.resolve(oidcResponse({
        access_token: `access-for-${token}`,
        refresh_token: `rotated-${token}`,
        expires_in: 300,
      }));
    }
  });
  let upstreamCalls = 0;
  globalThis.fetch = async (_input, init) => {
    const refreshToken = new URLSearchParams(String(init.body)).get("refresh_token");
    upstreamCalls += 1;
    const operation = pending.get(refreshToken);
    if (!operation) {
      return oidcResponse({
        access_token: "unexpected-access-token",
        refresh_token: "unexpected-refresh-token",
        expires_in: 300,
      });
    }
    started.get(refreshToken).resolve();
    return operation.promise;
  };

  const occupied = [...pending.keys()].map((token) => (
    sessionRequest(originalFetch, origin, refreshCookieHeader(token))
  ));
  await Promise.all([...started.values()].map((operation) => operation.promise));
  assert.equal(upstreamCalls, 2);

  const revokedCookie = refreshCookieHeader("revoked-while-full");
  const logout = await originalFetch(`${origin}/ui/auth/logout`, {
    method: "POST",
    headers: sessionHeaders(revokedCookie),
  });
  assert.equal(logout.status, 200);

  const rejected = await sessionRequest(originalFetch, origin, revokedCookie);
  assert.equal(rejected.status, 401);
  assert.equal(upstreamCalls, 2);

  for (const [token, operation] of pending) {
    operation.resolve(oidcResponse({
      access_token: `access-for-${token}`,
      refresh_token: `rotated-${token}`,
      expires_in: 300,
    }));
  }
  const completed = await Promise.all(occupied);
  assert.deepEqual(completed.map((response) => response.status), [200, 200]);
});

test("standalone WebConsole aborts timed-out refreshes and releases their coordinator slot", async (t) => {
  const timers = [];
  const scheduleAbort = (abort, delayMs) => {
    const timer = { abort, cancelled: false, delayMs };
    timers.push(timer);
    return () => {
      timer.cancelled = true;
    };
  };
  const origin = await startServer(t, { refreshRuntime: { maxEntries: 1, scheduleAbort } });
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const upstreamStarted = deferred();
  let upstreamCalls = 0;
  let upstreamAborted = false;
  globalThis.fetch = async (_input, init) => {
    upstreamCalls += 1;
    if (upstreamCalls > 1) {
      return oidcResponse({
        access_token: "access-after-timeout",
        refresh_token: "refresh-after-timeout",
        expires_in: 300,
      });
    }
    upstreamStarted.resolve();
    return new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => {
        upstreamAborted = true;
        reject(init.signal.reason);
      }, { once: true });
    });
  };

  const cookie = refreshCookieHeader("timeout-refresh-token");
  const timedOut = sessionRequest(originalFetch, origin, cookie);
  await upstreamStarted.promise;
  assert.equal(timers.length, 1);
  assert.equal(timers[0].delayMs, 10_000);
  timers[0].abort();

  const timedOutResponse = await timedOut;
  assert.equal(timedOutResponse.status, 503);
  assert.equal(timedOutResponse.headers.get("set-cookie"), null);
  assert.equal(upstreamAborted, true);
  assert.equal(timers[0].cancelled, true);

  const retry = await sessionRequest(originalFetch, origin, cookie);
  assert.equal(retry.status, 200);
  assert.equal(upstreamCalls, 2);
  assert.equal(timers[1].cancelled, true);
});

test("standalone WebConsole persists refresh cookies when the provider omits expiry", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async () => oidcResponse({
    access_token: "refreshed-access-token",
    refresh_token: "rotated-refresh-token",
    expires_in: 300,
  });

  const response = await sessionRequest(
    originalFetch,
    origin,
    refreshCookieHeader("refresh-token-without-expiry"),
  );
  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie") || "", /Max-Age=36000/);
});

test("standalone WebConsole preserves cookies for transient refresh failures", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const failures = new Map([
    ["invalid-client", { status: 400, error: "invalid_client" }],
    ["generic-401", { status: 401, error: "temporarily_unavailable" }],
    ["generic-403", { status: 403, error: "temporarily_unavailable" }],
    ["rate-limited", { status: 429, error: "invalid_token" }],
    ["server-error", { status: 503, error: "invalid_grant" }],
    ["expired", { status: 400, error: "invalid_grant" }],
  ]);
  globalThis.fetch = async (_input, init) => {
    const refreshToken = new URLSearchParams(String(init.body)).get("refresh_token");
    const failure = failures.get(refreshToken);
    assert.ok(failure, `unexpected refresh token: ${refreshToken}`);
    return oidcResponse({ error: failure.error }, failure.status);
  };

  for (const token of ["invalid-client", "generic-401", "generic-403", "rate-limited", "server-error"]) {
    const response = await sessionRequest(originalFetch, origin, refreshCookieHeader(token));
    assert.equal(response.status, 503, token);
    assert.equal(response.headers.get("set-cookie"), null, token);
  }

  const expired = await sessionRequest(originalFetch, origin, refreshCookieHeader("expired"));
  assert.equal(expired.status, 401);
  assert.match(expired.headers.get("set-cookie") || "", /Max-Age=0/);
});

test("standalone WebConsole stops reading oversized OIDC responses", async (t) => {
  const origin = await startServer(t);
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  let pulls = 0;
  let cancelled = false;
  globalThis.fetch = async () => new Response(new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array(64 * 1024).fill(0x7b));
    },
    cancel() {
      cancelled = true;
    },
  }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

  const response = await sessionRequest(
    originalFetch,
    origin,
    refreshCookieHeader("oversized-response"),
  );
  assert.equal(response.status, 502);
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(cancelled, true);
  assert.ok(pulls <= 6);
});

test("customer console caches successful UserInfo validation and rejects invalid JWTs", async (t) => {
  let userinfoCalls = 0;
  let apiCalls = 0;
  const apiRequestTargets = [];
  const upstream = await startHttpServer(t, (request, response) => {
    const pathname = new URL(request.url || "/", "http://upstream.invalid").pathname;
    if (pathname.endsWith("/protocol/openid-connect/userinfo")) {
      userinfoCalls += 1;
      const payload = testJwtPayload(request.headers.authorization);
      if (payload.jti === "fake-token") {
        return writeJson(response, 401, { error: "invalid_token" });
      }
      return writeJson(response, 200, {
        email: `${payload.sub}@example.test`,
        sub: payload.sub,
      });
    }
    if (pathname === "/api/v1/customer/session") {
      apiCalls += 1;
      apiRequestTargets.push(request.url);
      return writeJson(response, 200, { status: "ok" });
    }
    return writeJson(response, 404, { error: "not found" });
  });
  const customer = await startCustomerConsole(t, upstream.origin);
  const token = customerJwt(customer.issuer, { jti: "cache-hit" });

  const first = await customerRequest(customer.origin, token);
  const second = await customerRequest(
    customer.origin,
    token,
    "/v1/customer/session?cursor=prj_01&limit=100",
  );
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(userinfoCalls, 1);
  assert.equal(apiCalls, 2);
  assert.deepEqual(apiRequestTargets, [
    "/api/v1/customer/session",
    "/api/v1/customer/session?cursor=prj_01&limit=100",
  ]);

  const expired = customerJwt(customer.issuer, {
    expiresAt: Math.floor(Date.now() / 1_000) - 1,
    jti: "expired-token",
  });
  assert.equal((await customerRequest(customer.origin, expired)).status, 401);
  assert.equal(userinfoCalls, 1);

  const fake = customerJwt(customer.issuer, { jti: "fake-token" });
  assert.equal((await customerRequest(customer.origin, fake)).status, 401);
  assert.equal(userinfoCalls, 2);
  assert.equal(apiCalls, 2);
});

test("customer console bounds concurrent uncached UserInfo calls", async (t) => {
  const releaseUserinfo = deferred();
  t.after(() => releaseUserinfo.resolve());
  let activeUserinfo = 0;
  let maxActiveUserinfo = 0;
  let userinfoCalls = 0;
  const upstream = await startHttpServer(t, async (request, response) => {
    const pathname = new URL(request.url || "/", "http://upstream.invalid").pathname;
    if (pathname.endsWith("/protocol/openid-connect/userinfo")) {
      userinfoCalls += 1;
      activeUserinfo += 1;
      maxActiveUserinfo = Math.max(maxActiveUserinfo, activeUserinfo);
      await releaseUserinfo.promise;
      activeUserinfo -= 1;
      return writeJson(response, 200, { sub: testJwtPayload(request.headers.authorization).sub });
    }
    if (pathname.startsWith("/api/v1/customer/")) {
      return writeJson(response, 200, { status: "ok" });
    }
    return writeJson(response, 404, { error: "not found" });
  });
  const customer = await startCustomerConsole(t, upstream.origin, {
    HETERONETWORK_CUSTOMER_USERINFO_MAX_CONCURRENT: "2",
    HETERONETWORK_CUSTOMER_USERINFO_RATE_BURST: "32",
    HETERONETWORK_CUSTOMER_USERINFO_RATE_PER_SECOND: "32",
  });
  const requests = Array.from({ length: 8 }, (_, index) => (
    customerRequest(
      customer.origin,
      customerJwt(customer.issuer, { jti: `concurrent-${index}` }),
    )
  ));

  await waitFor(() => userinfoCalls === 2);
  assert.equal(maxActiveUserinfo, 2);
  releaseUserinfo.resolve();
  const responses = await Promise.all(requests);
  assert.deepEqual(
    responses.map(({ status }) => status).sort((left, right) => left - right),
    [200, 200, 503, 503, 503, 503, 503, 503],
  );
  assert.equal(userinfoCalls, 2);
});

test("customer console rate-limits uncached tokens before UserInfo fan-out", async (t) => {
  let userinfoCalls = 0;
  const upstream = await startHttpServer(t, (request, response) => {
    const pathname = new URL(request.url || "/", "http://upstream.invalid").pathname;
    if (pathname.endsWith("/protocol/openid-connect/userinfo")) {
      userinfoCalls += 1;
      return writeJson(response, 200, { sub: testJwtPayload(request.headers.authorization).sub });
    }
    if (pathname.startsWith("/api/v1/customer/")) {
      return writeJson(response, 200, { status: "ok" });
    }
    return writeJson(response, 404, { error: "not found" });
  });
  const customer = await startCustomerConsole(t, upstream.origin, {
    HETERONETWORK_CUSTOMER_USERINFO_MAX_CONCURRENT: "8",
    HETERONETWORK_CUSTOMER_USERINFO_RATE_BURST: "2",
    HETERONETWORK_CUSTOMER_USERINFO_RATE_PER_SECOND: "1",
  });
  const responses = await Promise.all(Array.from({ length: 8 }, (_, index) => (
    customerRequest(
      customer.origin,
      customerJwt(customer.issuer, { jti: `rate-${index}` }),
    )
  )));

  assert.deepEqual(
    responses.map(({ status }) => status).sort((left, right) => left - right),
    [200, 200, 429, 429, 429, 429, 429, 429],
  );
  assert.equal(userinfoCalls, 2);
});

async function startServer(t, options) {
  const server = createWebConsoleServer(options);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const address = server.address();
  assert.equal(typeof address, "object");
  return `http://127.0.0.1:${address.port}`;
}

async function startHttpServer(t, handler) {
  const server = createHttpServer((request, response) => {
    Promise.resolve(handler(request, response)).catch((error) => {
      if (!response.headersSent) {
        writeJson(response, 500, { error: error.message });
      } else {
        response.destroy(error);
      }
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const address = server.address();
  assert.equal(typeof address, "object");
  return { origin: `http://127.0.0.1:${address.port}` };
}

async function startCustomerConsole(t, upstreamOrigin, extraEnv = {}) {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const issuer = `${upstreamOrigin}/realms/heteronetwork-customers`;
  const child = spawn(process.execPath, ["webconsole/server.mjs"], {
    cwd: new URL("..", import.meta.url),
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      HETERONETWORK_CONSOLE_MODE: "customer",
      HETERONETWORK_CUSTOMER_API_URL: `${upstreamOrigin}/api`,
      HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL: issuer,
      HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL: origin,
      ...extraEnv,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  t.after(async () => {
    if (child.exitCode != null || child.signalCode != null) return;
    child.kill("SIGTERM");
    await once(child, "exit");
  });
  await waitFor(async () => {
    if (child.exitCode != null) {
      throw new Error(`customer console exited before becoming ready: ${stderr}`);
    }
    try {
      return (await fetch(`${origin}/cloud/config`)).ok;
    } catch {
      return false;
    }
  });
  return { issuer, origin };
}

async function availablePort() {
  const server = createHttpServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.equal(typeof address, "object");
  const available = address.port;
  server.close();
  await once(server, "close");
  return available;
}

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (await predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("condition was not met before timeout");
}

function customerRequest(origin, token, path = "/v1/customer/session") {
  return fetch(`${origin}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

function customerJwt(issuer, {
  expiresAt = Math.floor(Date.now() / 1_000) + 300,
  jti,
  sub = "customer-1",
}) {
  return [
    encodeJwtPart({ alg: "RS256", typ: "JWT" }),
    encodeJwtPart({
      aud: "heteronetwork-customer-api",
      azp: "heteronetwork-customer-console",
      exp: expiresAt,
      iss: issuer,
      jti,
      realm_access: { roles: ["heteronetwork-customer"] },
      sub,
    }),
    "test-signature",
  ].join(".");
}

function testJwtPayload(authorization) {
  const token = String(authorization || "").replace(/^Bearer\s+/i, "");
  return JSON.parse(Buffer.from(token.split(".")[1] || "", "base64url").toString("utf8"));
}

function encodeJwtPart(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function writeJson(response, status, body) {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}

function sessionHeaders(cookie = "") {
  const headers = {
    Origin: configuredPublicOrigin,
    "Sec-Fetch-Site": "same-origin",
  };
  if (cookie) headers.Cookie = cookie;
  return headers;
}

function sessionRequest(clientFetch, origin, cookie) {
  return clientFetch(`${origin}/ui/auth/refresh`, {
    method: "POST",
    headers: sessionHeaders(cookie),
  });
}

function refreshCookieHeader(token) {
  return `heteronetwork_web_refresh=${Buffer.from(token).toString("base64url")}`;
}

function oidcResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function responseSnapshot(response) {
  return {
    status: response.status,
    body: await response.json(),
    cookie: response.headers.get("set-cookie") || "",
  };
}

function deferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}
