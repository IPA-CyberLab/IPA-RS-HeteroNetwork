import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const webuiDir = process.env.HETERONETWORK_WEBUI_DIR || path.join(root, "webui");

const bindHost = process.env.HOST || "0.0.0.0";
const port = Number(process.env.PORT || 18088);
const publicUrl = trimSlash(process.env.HETERONETWORK_WEB_PUBLIC_URL || `http://127.0.0.1:${port}`);
const controlPlaneUrl = trimSlash(process.env.HETERONETWORK_CONTROL_PLANE_URL || "http://127.0.0.1:8443");
const keycloakIssuer = trimSlash(
  process.env.HETERONETWORK_WEB_OIDC_ISSUER_URL || "http://127.0.0.1:18080/realms/heteronetwork",
);
const keycloakClientId = process.env.HETERONETWORK_WEB_OIDC_CLIENT_ID || "heteronetwork-web";
const oidcScopes = process.env.HETERONETWORK_WEB_OIDC_SCOPES || "openid profile email";
const readRoles = csv(process.env.HETERONETWORK_WEB_READ_ROLES || "heteronetwork-admin,heteronetwork-operator,heteronetwork-viewer");
const writeRoles = csv(process.env.HETERONETWORK_WEB_WRITE_ROLES || "heteronetwork-admin");
const allowedEmails = csv(process.env.HETERONETWORK_WEB_ALLOWED_EMAILS || "");

const oidc = {
  authorizationEndpoint: `${keycloakIssuer}/protocol/openid-connect/auth`,
  tokenEndpoint: `${keycloakIssuer}/protocol/openid-connect/token`,
  userinfoEndpoint: `${keycloakIssuer}/protocol/openid-connect/userinfo`,
  logoutEndpoint: `${keycloakIssuer}/protocol/openid-connect/logout`,
};
const loginStates = new Map();

createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", publicUrl);
    if (url.pathname === "/") return redirect(response, "/ui/");
    if (request.method === "GET" && url.pathname === "/ui/login") return handleLogin(response);
    if (request.method === "GET" && url.pathname === "/ui/callback") {
      return await handleCallback(response, url);
    }
    if (request.method === "GET" && url.pathname === "/ui/config") return sendJson(response, publicConfig());
    if (request.method === "GET" && (url.pathname === "/ui" || url.pathname === "/ui/")) {
      return sendFile(response, path.join(webuiDir, "index.html"), "text/html; charset=utf-8");
    }
    if (request.method === "GET" && url.pathname === "/ui/app.js") {
      return sendFile(response, path.join(webuiDir, "app.js"), "text/javascript; charset=utf-8");
    }
    if (request.method === "GET" && url.pathname === "/ui/styles.css") {
      return sendFile(response, path.join(webuiDir, "styles.css"), "text/css; charset=utf-8");
    }
    if (url.pathname.startsWith("/v1/admin/")) return await handleAdmin(request, response, url.pathname);
    if (request.method === "GET" && (url.pathname === "/v1/metrics" || url.pathname === "/v1/policy")) {
      const token = await requireAuth(request, readRoles);
      return await proxyControlPlane(request, response, url.pathname, token);
    }
    sendJson(response, { error: "not found" }, 404);
  } catch (error) {
    const status = Number(error.statusCode || 500);
    sendJson(response, { error: error.message || "internal server error" }, status);
  }
}).listen(port, bindHost, () => {
  console.log(`HeteroNetwork WebConsole listening on http://${bindHost}:${port}`);
});

function handleLogin(response) {
  cleanupLoginStates();
  const state = randomId(24);
  const verifier = randomId(32);
  loginStates.set(state, { verifier, createdAt: Date.now() });
  const params = new URLSearchParams({
    response_type: "code",
    client_id: keycloakClientId,
    redirect_uri: `${publicUrl}/ui/callback`,
    scope: oidcScopes,
    state,
    code_challenge: pkceChallenge(verifier),
    code_challenge_method: "S256",
  });
  redirect(response, `${oidc.authorizationEndpoint}?${params.toString()}`);
}

async function handleCallback(response, url) {
  const state = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  const record = loginStates.get(state);
  loginStates.delete(state);
  if (!state || !code || !record) throw httpError(400, "missing or expired OIDC state");
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: keycloakClientId,
    code,
    redirect_uri: `${publicUrl}/ui/callback`,
    code_verifier: record.verifier,
  });
  const tokenResponse = await fetch(oidc.tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
    body,
  });
  if (!tokenResponse.ok) throw httpError(401, `OIDC token exchange failed (${tokenResponse.status})`);
  const tokens = await tokenResponse.json();
  if (!tokens.access_token) throw httpError(401, "OIDC response did not include an access token");
  response.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(`<!doctype html><meta charset="utf-8"><title>HeteroNetwork Login</title><script>
sessionStorage.setItem("heteronetwork_access_token", ${JSON.stringify(tokens.access_token)});
location.replace("/ui/");
</script>`);
}

async function handleAdmin(request, response, pathname) {
  const token = await requireAuth(request, request.method === "GET" ? readRoles : writeRoles);
  return await proxyControlPlane(request, response, pathname, token);
}

async function requireAuth(request, requiredRoles) {
  const token = bearerToken(request.headers.authorization);
  if (!token) throw httpError(401, "missing bearer token");
  const userinfo = await validateTokenWithUserinfo(token);
  if (allowedEmails.length && allowedEmails.includes(String(userinfo.email || "").toLowerCase())) {
    return userinfo;
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
  return response.json();
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
  const body = await upstream.text();
  const responseHeaders = {
    "Content-Type": upstream.headers.get("content-type") || "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };
  const wwwAuthenticate = upstream.headers.get("www-authenticate");
  if (wwwAuthenticate) responseHeaders["WWW-Authenticate"] = wwwAuthenticate;
  response.writeHead(upstream.status, responseHeaders);
  response.end(body);
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
    login_endpoint: "/ui/login",
  };
}

function sendFile(response, filename, contentType) {
  response.writeHead(200, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  createReadStream(filename).pipe(response);
}

function redirect(response, location) {
  response.writeHead(302, { Location: location });
  response.end();
}

function sendJson(response, body, status = 200) {
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  response.end(JSON.stringify(body));
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

function cleanupLoginStates() {
  const expiresBefore = Date.now() - 5 * 60 * 1000;
  for (const [state, record] of loginStates) {
    if (record.createdAt < expiresBefore) loginStates.delete(state);
  }
}
