import { createServer } from "node:http";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const uiBasePath = "/ui";
const webuiDir = process.env.HETERONETWORK_WEBUI_DIR || path.join(root, "webui");

const bindHost = process.env.HOST || "0.0.0.0";
const port = Number(process.env.PORT || 18088);
const publicUrl = trimSlash(
  process.env.HETERONETWORK_WEB_PUBLIC_URL || `http://127.0.0.1:${port}`,
);
const controlPlaneUrl = trimSlash(
  process.env.HETERONETWORK_CONTROL_PLANE_URL || "http://127.0.0.1:8443",
);
const keycloakIssuer = exactIssuer(
  process.env.HETERONETWORK_WEB_OIDC_ISSUER_URL
    || "http://127.0.0.1:18080/realms/heteronetwork",
);
const keycloakClientId = process.env.HETERONETWORK_WEB_OIDC_CLIENT_ID
  || "heteronetwork-web";
const oidcScopes = process.env.HETERONETWORK_WEB_OIDC_SCOPES
  || "openid profile email";
const readRoles = csv(
  process.env.HETERONETWORK_WEB_READ_ROLES
    || "heteronetwork-admin,heteronetwork-operator,heteronetwork-viewer",
);
const writeRoles = csv(
  process.env.HETERONETWORK_WEB_WRITE_ROLES || "heteronetwork-admin",
);
const allowedEmails = csv(process.env.HETERONETWORK_WEB_ALLOWED_EMAILS || "");
const refreshCookieName = "heteronetwork_web_refresh";
const refreshCookiePath = `${uiBasePath}/auth`;
const loginStateCookieName = "heteronetwork_web_login_state";
const loginStateCookiePath = `${uiBasePath}/callback`;
const accessTokenStorageKey = "heteronetwork_access_token";
const accessTokenExpiresStorageKey = "heteronetwork_access_token_expires_at";
const maxRefreshTokenBytes = 2_800;
const maxAccessTokenBytes = 16 * 1024;
const maxSessionSeconds = 30 * 24 * 60 * 60;
const fallbackRefreshCookieSeconds = 10 * 60 * 60;
const maxOidcResponseBytes = 256 * 1024;
const maxProxyResponseBytes = 16 * 1024 * 1024;
const refreshReplayWindowMs = 5_000;
const maxRefreshReplayEntries = 256;
const maxRefreshTombstoneEntries = 1_024;
const refreshTombstoneWindowMs = maxSessionSeconds * 1_000;
const upstreamRefreshTimeoutMs = 10_000;
const publicOrigin = new URL(publicUrl).origin;
const secureCookies = new URL(publicUrl).protocol === "https:";

const oidc = {
  authorizationEndpoint: `${keycloakIssuer}/protocol/openid-connect/auth`,
  tokenEndpoint: `${keycloakIssuer}/protocol/openid-connect/token`,
  userinfoEndpoint: `${keycloakIssuer}/protocol/openid-connect/userinfo`,
  logoutEndpoint: `${keycloakIssuer}/protocol/openid-connect/logout`,
};

export function createWebConsoleServer({ refreshRuntime = {} } = {}) {
  const scheduleAbort = refreshRuntime.scheduleAbort || scheduleRefreshAbort;
  const configuredEntryLimit = Number(refreshRuntime.maxEntries);
  const entryLimit = Number.isSafeInteger(configuredEntryLimit) && configuredEntryLimit > 0
    ? configuredEntryLimit
    : maxRefreshReplayEntries;
  const refreshCoordinator = createRefreshCoordinator({
    entryLimit,
    exchange: (refreshToken) => exchangeRefreshToken(refreshToken, scheduleAbort),
  });
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url || "/", publicUrl);
      if (url.pathname === "/") return redirect(response, `${uiBasePath}/`);
      if (request.method === "GET" && url.pathname === `${uiBasePath}/login`) return handleLogin(response);
      if (request.method === "GET" && url.pathname === `${uiBasePath}/callback`) {
        return await handleCallback(request, response, url);
      }
      if (request.method === "POST" && url.pathname === `${uiBasePath}/auth/refresh`) {
        return await handleRefresh(request, response, refreshCoordinator);
      }
      if (request.method === "POST" && url.pathname === `${uiBasePath}/auth/logout`) {
        return handleLogout(request, response, refreshCoordinator);
      }
      if (request.method === "GET" && url.pathname === `${uiBasePath}/config`) return sendJson(response, publicConfig());
      if (request.method === "GET" && (url.pathname === uiBasePath || url.pathname === `${uiBasePath}/`)) {
        return sendFile(response, path.join(webuiDir, "index.html"), "text/html; charset=utf-8");
      }
      if (request.method === "GET" && url.pathname === `${uiBasePath}/app.js`) {
        return sendFile(response, path.join(webuiDir, "app.js"), "text/javascript; charset=utf-8");
      }
      if (request.method === "GET" && url.pathname === `${uiBasePath}/theme.js`) {
        return sendFile(response, path.join(webuiDir, "theme.js"), "text/javascript; charset=utf-8");
      }
      if (request.method === "GET" && url.pathname === `${uiBasePath}/styles.css`) {
        return sendFile(response, path.join(webuiDir, "styles.css"), "text/css; charset=utf-8");
      }
      if (request.method === "GET" && url.pathname === `${uiBasePath}/vendor/mermaid.min.js`) {
        return sendFile(
          response,
          path.join(webuiDir, "vendor", "mermaid.min.js"),
          "text/javascript; charset=utf-8",
        );
      }
      if (request.method === "GET" && url.pathname === `${uiBasePath}/fonts/noto-sans-jp-ui.ttf`) {
        return sendFile(response, path.join(webuiDir, "noto-sans-jp-ui.ttf"), "font/ttf");
      }
      if (url.pathname.startsWith("/v1/admin/")) {
        return await handleAdmin(request, response, url.pathname);
      }
      if (request.method === "GET" && (url.pathname === "/v1/metrics" || url.pathname === "/v1/policy")) {
        const token = await requireAuth(request, readRoles);
        return await proxyControlPlane(request, response, url.pathname, token);
      }
      sendJson(response, { error: "not found" }, 404);
    } catch (error) {
      const status = Number(error.statusCode || 500);
      sendJson(response, { error: error.message || "internal server error" }, status);
    }
  });
}

export function startWebConsoleServer() {
  const server = createWebConsoleServer();
  server.listen(port, bindHost, () => {
    console.log(`HeteroNetwork WebConsole listening on http://${bindHost}:${port}`);
  });
  return server;
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) startWebConsoleServer();

function handleLogin(response) {
  const state = randomId(24);
  const verifier = randomId(32);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: keycloakClientId,
    redirect_uri: `${publicUrl}${uiBasePath}/callback`,
    scope: oidcScopes,
    state,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: "S256",
  });
  redirect(
    response,
    `${oidc.authorizationEndpoint}?${params.toString()}`,
    { "Set-Cookie": loginStateCookie(state, verifier) },
  );
}

async function handleCallback(request, response, url) {
  const state = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  const browserState = loginStateFromRequest(request);
  if (
    !state
    || !code
    || !browserState
    || !constantTimeEqual(state, browserState.state)
  ) {
    return sendJson(
      response,
      { error: "missing, expired, or browser-mismatched OIDC state" },
      400,
      { "Set-Cookie": clearLoginStateCookie() },
    );
  }
  let tokens;
  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: keycloakClientId,
      code,
      redirect_uri: `${publicUrl}${uiBasePath}/callback`,
      code_verifier: browserState.verifier,
    });
    const tokenResponse = await fetch(oidc.tokenEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body,
    });
    if (!tokenResponse.ok) {
      throw httpError(401, `OIDC token exchange failed (${tokenResponse.status})`);
    }
    tokens = validateOidcTokens(await boundedJson(tokenResponse));
  } catch (error) {
    return sendJson(
      response,
      { error: error.message || "OIDC callback failed" },
      Number(error.statusCode || 500),
      { "Set-Cookie": clearLoginStateCookie() },
    );
  }
  const setCookie = tokens.refresh_token
    ? refreshCookie(tokens.refresh_token, tokens.refresh_expires_in)
    : clearRefreshCookie();
  const scriptNonce = randomId(18);
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...browserSecurityHeaders(
      `default-src 'none'; script-src 'nonce-${scriptNonce}'; base-uri 'none'; frame-ancestors 'none'`,
    ),
    "Set-Cookie": [clearLoginStateCookie(), setCookie],
  });
  response.end(`<!doctype html><meta charset="utf-8"><title>HeteroNetwork Login</title><script nonce="${scriptNonce}">
sessionStorage.setItem(${safeJson(accessTokenStorageKey)}, ${safeJson(tokens.access_token)});
sessionStorage.setItem(${safeJson(accessTokenExpiresStorageKey)},String(Date.now()+${tokens.expires_in}*1000));
location.replace(${safeJson(`${uiBasePath}/`)});
</script>`);
}

async function handleRefresh(request, response, refreshCoordinator) {
  requireSameOrigin(request);
  const previousRefreshToken = refreshTokenFromRequest(request);
  if (!previousRefreshToken) {
    return sendJson(
      response,
      { error: "Web UI refresh session is missing or invalid" },
      401,
      { "Set-Cookie": clearRefreshCookie(), "WWW-Authenticate": "Bearer" },
    );
  }
  const result = await refreshCoordinator.refresh(previousRefreshToken);
  if (result.kind === "terminal") {
    return sendJson(
      response,
      { error: "Web UI refresh session expired or was rejected" },
      401,
      { "Set-Cookie": clearRefreshCookie(), "WWW-Authenticate": "Bearer" },
    );
  }
  sendJson(
    response,
    { access_token: result.accessToken, expires_in: result.expiresIn },
    200,
    { "Set-Cookie": refreshCookie(result.refreshToken, result.refreshExpiresIn) },
  );
}

async function exchangeRefreshToken(previousRefreshToken, scheduleAbort) {
  const controller = new AbortController();
  let timedOut = false;
  let cancelTimeout = () => {};
  const timeout = new Promise((_, reject) => {
    cancelTimeout = scheduleAbort(() => {
      timedOut = true;
      controller.abort();
      reject(httpError(503, "Keycloak refresh endpoint timed out"));
    }, upstreamRefreshTimeoutMs);
  });
  let tokenResponse;
  let body;
  try {
    ({ tokenResponse, body } = await Promise.race([
      (async () => {
        const response = await fetch(oidc.tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: keycloakClientId,
            refresh_token: previousRefreshToken,
          }),
          signal: controller.signal,
        });
        return { tokenResponse: response, body: await boundedJson(response) };
      })(),
      timeout,
    ]));
  } catch (error) {
    if (timedOut || controller.signal.aborted) {
      throw httpError(503, "Keycloak refresh endpoint timed out");
    }
    if (error?.statusCode) throw error;
    throw httpError(503, "Keycloak refresh endpoint is unavailable");
  } finally {
    cancelTimeout();
  }
  if (!tokenResponse.ok) {
    const terminalError = ["invalid_grant", "invalid_token", "expired_token"]
      .includes(String(body.error || ""));
    if (tokenResponse.status < 500 && tokenResponse.status !== 429 && terminalError) {
      return { kind: "terminal" };
    }
    throw httpError(503, `Keycloak refresh request failed (${tokenResponse.status})`);
  }
  const tokens = validateOidcTokens(body);
  return {
    kind: "success",
    accessToken: tokens.access_token,
    expiresIn: tokens.expires_in,
    refreshToken: tokens.refresh_token || previousRefreshToken,
    refreshExpiresIn: tokens.refresh_expires_in,
  };
}

function scheduleRefreshAbort(abort, delayMs) {
  const timeout = setTimeout(abort, delayMs);
  return () => clearTimeout(timeout);
}

function createRefreshCoordinator({ entryLimit, exchange }) {
  const entries = new Map();
  const tombstones = new Map();

  function revokeDigestAndAncestors(rootDigest, now) {
    const revoked = new Set();
    const pending = [rootDigest];
    while (pending.length) {
      const digest = pending.pop();
      if (revoked.has(digest)) continue;
      revoked.add(digest);
      for (const [candidateDigest, entry] of entries) {
        if (entry.issuedDigest === digest && !revoked.has(candidateDigest)) {
          pending.push(candidateDigest);
        }
      }
    }

    for (const digest of revoked) {
      addRefreshTombstone(tombstones, digest, now);
      const entry = entries.get(digest);
      if (!entry) continue;
      entry.revoked = true;
      if (!entry.inFlight) entries.delete(digest);
    }
  }

  return {
    refresh(refreshToken) {
      const now = Date.now();
      pruneRefreshEntries(entries, now);
      pruneRefreshTombstones(tombstones, now);
      const digest = refreshTokenDigest(refreshToken);
      if (hasRefreshTombstone(tombstones, digest, now)) {
        return Promise.resolve({ kind: "terminal" });
      }
      const existing = entries.get(digest);
      if (existing?.inFlight) return existing.inFlight;
      if (existing?.result && existing.expiresAt > now) return Promise.resolve(existing.result);

      if (!makeRefreshEntryRoom(entries, entryLimit)) {
        return Promise.reject(httpError(503, "too many Web UI session refreshes are in progress"));
      }
      const entry = {
        expiresAt: Number.POSITIVE_INFINITY,
        inFlight: null,
        issuedDigest: null,
        result: null,
        revoked: false,
      };
      const inFlight = exchange(refreshToken).then(
        (result) => {
          if (entries.get(digest) !== entry) return result;
          const completedAt = Date.now();
          entry.inFlight = null;
          if (result.kind === "success") {
            entry.issuedDigest = refreshTokenDigest(result.refreshToken);
          }
          if (
            entry.revoked
            || hasRefreshTombstone(tombstones, digest, completedAt)
            || (
              entry.issuedDigest
              && hasRefreshTombstone(tombstones, entry.issuedDigest, completedAt)
            )
          ) {
            revokeDigestAndAncestors(digest, completedAt);
            return { kind: "terminal" };
          }
          if (result.kind !== "success") {
            entries.delete(digest);
            return result;
          }
          entry.result = result;
          entry.expiresAt = completedAt + refreshReplayWindowMs;
          return result;
        },
        (error) => {
          if (entries.get(digest) === entry) entries.delete(digest);
          throw error;
        },
      );
      entry.inFlight = inFlight;
      entries.set(digest, entry);
      return inFlight;
    },
    invalidate(refreshToken) {
      const now = Date.now();
      pruneRefreshEntries(entries, now);
      pruneRefreshTombstones(tombstones, now);
      revokeDigestAndAncestors(refreshTokenDigest(refreshToken), now);
    },
  };
}

function refreshTokenDigest(refreshToken) {
  return createHash("sha256").update(refreshToken, "utf8").digest("base64url");
}

function pruneRefreshEntries(entries, now) {
  for (const [digest, entry] of entries) {
    if (!entry.inFlight && entry.expiresAt <= now) entries.delete(digest);
  }
}

function makeRefreshEntryRoom(entries, entryLimit) {
  while (entries.size >= entryLimit) {
    const completed = [...entries].find(([, entry]) => !entry.inFlight);
    const digest = completed?.[0];
    if (!digest) return false;
    entries.delete(digest);
  }
  return true;
}

function addRefreshTombstone(tombstones, digest, now) {
  pruneRefreshTombstones(tombstones, now);
  tombstones.delete(digest);
  while (tombstones.size >= maxRefreshTombstoneEntries) {
    const oldestDigest = tombstones.keys().next().value;
    if (oldestDigest == null) break;
    tombstones.delete(oldestDigest);
  }
  tombstones.set(digest, now + refreshTombstoneWindowMs);
}

function hasRefreshTombstone(tombstones, digest, now) {
  const expiresAt = tombstones.get(digest);
  if (expiresAt == null) return false;
  if (expiresAt <= now) {
    tombstones.delete(digest);
    return false;
  }
  return true;
}

function pruneRefreshTombstones(tombstones, now) {
  for (const [digest, expiresAt] of tombstones) {
    if (expiresAt <= now) tombstones.delete(digest);
  }
}

function handleLogout(request, response, refreshCoordinator) {
  requireSameOrigin(request);
  const refreshToken = refreshTokenFromRequest(request);
  if (refreshToken) refreshCoordinator.invalidate(refreshToken);
  sendJson(
    response,
    { status: "logged_out" },
    200,
    { "Set-Cookie": clearRefreshCookie() },
  );
}

async function handleAdmin(request, response, pathname) {
  const token = await requireAuth(request, request.method === "GET" ? readRoles : writeRoles);
  return await proxyControlPlane(request, response, pathname, token);
}

async function requireAuth(request, requiredRoles) {
  const token = bearerToken(request.headers.authorization);
  if (!token) throw httpError(401, "missing bearer token");
  const userinfo = await validateTokenWithUserinfo(token);
  validateTokenBinding(token, userinfo);
  if (allowedEmails.length && !allowedEmails.includes(String(userinfo.email || "").toLowerCase())) {
    throw httpError(403, "authenticated user is not in the configured email allowlist");
  }
  const tokenRoles = rolesFromJwt(token);
  if (requiredRoles.length && !requiredRoles.some((role) => tokenRoles.includes(role))) {
    throw httpError(403, "authenticated user is missing the required WebConsole role");
  }
  return token;
}

async function validateTokenWithUserinfo(token) {
  const response = await fetch(oidc.userinfoEndpoint, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!response.ok) throw httpError(401, "Keycloak token validation failed");
  return boundedJson(response);
}

async function proxyControlPlane(request, response, pathname, token) {
  const headers = {
    Accept: request.headers.accept || "application/json",
    Authorization: `Bearer ${token}`,
  };
  const init = { method: request.method, headers };
  if (request.method !== "GET" && request.method !== "HEAD") {
    const body = await readRequestBody(request);
    if (body.length) {
      init.body = body;
      if (request.headers["content-type"]) headers["Content-Type"] = request.headers["content-type"];
    }
  }
  const upstream = await fetch(`${controlPlaneUrl}${pathname}`, init);
  const body = await boundedProxyResponse(upstream);
  const responseHeaders = {
    "Content-Type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...browserSecurityHeaders("default-src 'none'; frame-ancestors 'none'"),
  };
  const wwwAuthenticate = upstream.headers.get("www-authenticate");
  if (wwwAuthenticate) responseHeaders["WWW-Authenticate"] = wwwAuthenticate;
  const retryAfter = upstream.headers.get("retry-after");
  if (retryAfter) responseHeaders["Retry-After"] = retryAfter;
  response.writeHead(upstream.status, responseHeaders);
  response.end(body);
}

async function boundedProxyResponse(response) {
  const declaredLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxProxyResponseBytes) {
    try {
      await response.body?.cancel();
    } catch {
      // The size failure is authoritative even if cancellation also fails.
    }
    throw httpError(502, "upstream API response is too large");
  }
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > maxProxyResponseBytes) {
        try {
          await reader.cancel();
        } catch {
          // The size failure is authoritative even if cancellation also fails.
        }
        throw httpError(502, "upstream API response is too large");
      }
      size += value.byteLength;
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, size);
}

function readRequestBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) {
        reject(httpError(413, "request body is too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function publicConfig() {
  return {
    enabled: true,
    auth_enabled: true,
    operator_token_enabled: false,
    provider: "keycloak",
    issuer_url: keycloakIssuer,
    client_id: keycloakClientId,
    scopes: oidcScopes,
    authorization_endpoint: oidc.authorizationEndpoint,
    token_endpoint: oidc.tokenEndpoint,
    logout_endpoint: oidc.logoutEndpoint,
    login_endpoint: `${uiBasePath}/login`,
    session_refresh_endpoint: `${uiBasePath}/auth/refresh`,
    session_logout_endpoint: `${uiBasePath}/auth/logout`,
  };
}

async function sendFile(response, filename, contentType) {
  try {
    const contents = await readFile(filename);
    response.writeHead(200, {
      "Content-Type": contentType,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...browserSecurityHeaders(
        "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
      ),
    });
    response.end(contents);
  } catch (error) {
    if (response.destroyed) return;
    if (response.headersSent) {
      response.destroy(error);
      return;
    }
    const status = error.code === "ENOENT" || error.code === "ENOTDIR" ? 404 : 500;
    sendJson(response, { error: status === 404 ? "not found" : "internal server error" }, status);
  }
}

function redirect(response, location, additionalHeaders = {}) {
  response.writeHead(302, {
    Location: location,
    ...browserSecurityHeaders("default-src 'none'; frame-ancestors 'none'"),
    ...additionalHeaders,
  });
  response.end();
}

function sendJson(response, body, status = 200, additionalHeaders = {}) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...browserSecurityHeaders("default-src 'none'; frame-ancestors 'none'"),
    ...additionalHeaders,
  });
  response.end(JSON.stringify(body));
}

function browserSecurityHeaders(contentSecurityPolicy) {
  return {
    "Content-Security-Policy": contentSecurityPolicy,
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    ...(secureCookies
      ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" }
      : {}),
  };
}

function requireSameOrigin(request) {
  if (
    request.headers.origin !== publicOrigin
    || request.headers["sec-fetch-site"] !== "same-origin"
  ) {
    throw httpError(403, "Web UI session request did not come from the configured origin");
  }
}

function validateOidcTokens(value) {
  const accessToken = String(value?.access_token || "");
  if (!accessToken || accessToken.length > maxAccessTokenBytes || /\s/.test(accessToken)) {
    throw httpError(502, "OIDC response contained an invalid access token");
  }
  const refreshToken = value?.refresh_token == null ? "" : String(value.refresh_token);
  if (
    refreshToken
    && (Buffer.byteLength(refreshToken) > maxRefreshTokenBytes || /\s|[\u0000-\u001f\u007f]/.test(refreshToken))
  ) {
    throw httpError(502, "OIDC response contained an invalid refresh token");
  }
  const expires = Number(value?.expires_in);
  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: Number.isFinite(expires) && expires > 0
      ? Math.min(Math.floor(expires), maxSessionSeconds)
      : 5 * 60,
    refresh_expires_in: value?.refresh_expires_in,
  };
}

function refreshCookie(token, refreshExpiresIn) {
  const bytes = Buffer.from(token, "utf8");
  if (!bytes.length || bytes.length > maxRefreshTokenBytes) {
    throw httpError(502, "OIDC response contained an invalid refresh token");
  }
  const encoded = bytes.toString("base64url");
  const seconds = Number(refreshExpiresIn);
  let maxAge = fallbackRefreshCookieSeconds;
  if (refreshExpiresIn != null && refreshExpiresIn !== "" && Number.isFinite(seconds) && seconds >= 0) {
    maxAge = seconds === 0
      ? maxSessionSeconds
      : Math.min(Math.floor(seconds), maxSessionSeconds);
  }
  return `${refreshCookieName}=${encoded}; Path=${refreshCookiePath}; Max-Age=${maxAge}; HttpOnly; SameSite=Strict${secureCookies ? "; Secure" : ""}`;
}

function clearRefreshCookie() {
  return `${refreshCookieName}=; Path=${refreshCookiePath}; Max-Age=0; HttpOnly; SameSite=Strict${secureCookies ? "; Secure" : ""}`;
}

function loginStateCookie(state, verifier) {
  const payload = Buffer.from(JSON.stringify({ state, verifier }), "utf8").toString("base64url");
  return `${loginStateCookieName}=${payload}; Path=${loginStateCookiePath}; Max-Age=300; HttpOnly; SameSite=Lax${secureCookies ? "; Secure" : ""}`;
}

function clearLoginStateCookie() {
  return `${loginStateCookieName}=; Path=${loginStateCookiePath}; Max-Age=0; HttpOnly; SameSite=Lax${secureCookies ? "; Secure" : ""}`;
}

function refreshTokenFromRequest(request) {
  const matches = String(request.headers.cookie || "")
    .split(";")
    .map((part) => part.trim().split("=", 2))
    .filter(([name, value]) => name === refreshCookieName && value);
  if (matches.length !== 1) return "";
  const encoded = matches[0][1];
  if (!encoded || encoded.length > Math.ceil(maxRefreshTokenBytes * 4 / 3) + 4) return "";
  let decoded;
  try {
    decoded = Buffer.from(encoded, "base64url");
  } catch {
    return "";
  }
  if (decoded.toString("base64url") !== encoded || !decoded.length || decoded.length > maxRefreshTokenBytes) {
    return "";
  }
  const token = decoded.toString("utf8");
  return Buffer.from(token, "utf8").equals(decoded) && !/\s|[\u0000-\u001f\u007f]/.test(token)
    ? token
    : "";
}

function cookieValue(request, name, maxBytes) {
  const matches = String(request.headers.cookie || "")
    .split(";")
    .map((part) => part.trim().split("=", 2))
    .filter(([candidate, value]) => candidate === name && value);
  if (matches.length !== 1) return "";
  const value = matches[0][1];
  return Buffer.byteLength(value) <= maxBytes && /^[A-Za-z0-9_-]+$/.test(value) ? value : "";
}

function loginStateFromRequest(request) {
  const encoded = cookieValue(request, loginStateCookieName, 512);
  if (!encoded) return null;
  let decoded;
  try {
    decoded = Buffer.from(encoded, "base64url");
  } catch {
    return null;
  }
  if (!decoded.length || decoded.toString("base64url") !== encoded) return null;
  let payload;
  try {
    payload = JSON.parse(decoded.toString("utf8"));
  } catch {
    return null;
  }
  if (
    !payload
    || typeof payload !== "object"
    || Array.isArray(payload)
    || Object.keys(payload).sort().join(",") !== "state,verifier"
    || !/^[A-Za-z0-9_-]{32}$/.test(payload.state)
    || !/^[A-Za-z0-9_-]{43}$/.test(payload.verifier)
  ) {
    return null;
  }
  return payload;
}

function constantTimeEqual(left, right) {
  const leftBytes = Buffer.from(String(left));
  const rightBytes = Buffer.from(String(right));
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

async function boundedJson(response) {
  if (!response.body) throw httpError(502, "OIDC response is not valid JSON");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (size + value.byteLength > maxOidcResponseBytes) {
        try {
          await reader.cancel();
        } catch {
          // The size failure is authoritative even if cancellation also fails.
        }
        throw httpError(502, "OIDC response is too large");
      }
      size += value.byteLength;
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  const body = Buffer.concat(chunks, size).toString("utf8");
  try {
    return JSON.parse(body);
  } catch {
    throw httpError(502, "OIDC response is not valid JSON");
  }
}

function safeJson(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

function bearerToken(header) {
  const match = /^Bearer\s+(.+)$/i.exec(String(header || ""));
  return match ? match[1].trim() : "";
}

function rolesFromJwt(token) {
  const payload = decodeJwtPayload(token);
  const realmRoles = payload.realm_access?.roles || [];
  const clientRoles = payload.resource_access?.[keycloakClientId]?.roles || [];
  return [...new Set([...realmRoles, ...clientRoles])];
}

function validateTokenBinding(token, userinfo) {
  const payload = decodeJwtPayload(token);
  if (payload.iss !== keycloakIssuer) {
    throw httpError(401, "Keycloak token issuer does not match this console");
  }
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud].filter(Boolean);
  const audienceMatches = audiences.includes(keycloakClientId);
  const authorizedPartyMatches = payload.azp === keycloakClientId;
  if (!audienceMatches && !authorizedPartyMatches) {
    throw httpError(401, "Keycloak token audience does not match this console");
  }
  if (!payload.sub || payload.sub !== userinfo.sub) {
    throw httpError(401, "Keycloak token subject does not match userinfo");
  }
}

function decodeJwtPayload(token) {
  const payload = String(token).split(".")[1] || "";
  if (!payload) return {};
  try {
    return JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  } catch {
    return {};
  }
}

function trimSlash(value) {
  return String(value).replace(/\/+$/, "");
}

function exactIssuer(value) {
  const issuer = String(value);
  if (!issuer || issuer !== trimSlash(issuer)) {
    throw new Error("OIDC issuer must be a non-empty exact URL without a trailing slash");
  }
  return issuer;
}

function csv(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => (item.includes("@") ? item.toLowerCase() : item));
}

function httpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function randomId(bytes) {
  return randomBytes(bytes).toString("base64url");
}

function pkceChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}
