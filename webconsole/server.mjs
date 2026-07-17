import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const webuiDir = process.env.IPARS_WEBUI_DIR || path.join(root, "webui");
const statePath = process.env.IPARS_LAB_STATE_PATH || path.join(process.cwd(), "state.json");

const bindHost = process.env.HOST || "0.0.0.0";
const port = Number(process.env.PORT || 18088);
const publicUrl = trimSlash(process.env.IPARS_WEB_PUBLIC_URL || `http://127.0.0.1:${port}`);
const controlPlaneUrl = trimSlash(process.env.IPARS_CONTROL_PLANE_URL || "http://127.0.0.1:8443");
const keycloakIssuer = trimSlash(
  process.env.IPARS_WEB_OIDC_ISSUER_URL || "http://127.0.0.1:18080/realms/kakurizai",
);
const keycloakClientId = process.env.IPARS_WEB_OIDC_CLIENT_ID || "ipars-web";
const oidcScopes = process.env.IPARS_WEB_OIDC_SCOPES || "openid profile email";
const readRoles = csv(process.env.IPARS_WEB_READ_ROLES || "kakurizai-admin,kakurizai-operator,kakurizai-viewer");
const writeRoles = csv(process.env.IPARS_WEB_WRITE_ROLES || "kakurizai-admin");
const allowedEmails = csv(process.env.IPARS_WEB_ALLOWED_EMAILS || "");

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
      await requireAuth(request, readRoles);
      return await proxyJson(response, url.pathname);
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
  response.end(`<!doctype html><meta charset="utf-8"><title>IPARS Login</title><script>
sessionStorage.setItem("ipars_access_token", ${JSON.stringify(tokens.access_token)});
location.replace("/ui/");
</script>`);
}

async function handleAdmin(request, response, pathname) {
  if (request.method === "GET" && pathname === "/v1/admin/overview") {
    await requireAuth(request, readRoles);
    return sendJson(response, await buildOverview());
  }
  if (request.method === "GET" && pathname === "/v1/admin/nodes") {
    await requireAuth(request, readRoles);
    return sendJson(response, (await buildOverview()).nodes);
  }
  if (request.method === "GET" && pathname === "/v1/admin/paths") {
    await requireAuth(request, readRoles);
    return sendJson(response, (await buildOverview()).paths);
  }
  if (request.method === "GET" && pathname === "/v1/admin/policy") {
    await requireAuth(request, readRoles);
    return sendJson(response, await fetchJson("/v1/policy"));
  }
  await requireAuth(request, writeRoles);
  sendJson(response, { error: "write operations require a newer iparsd control-plane backend" }, 501);
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
  return userinfo;
}

async function validateTokenWithUserinfo(token) {
  const response = await fetch(oidc.userinfoEndpoint, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!response.ok) throw httpError(401, "Keycloak token validation failed");
  return response.json();
}

async function buildOverview() {
  const [metrics, policy, labState] = await Promise.all([
    fetchJson("/v1/metrics"),
    fetchJson("/v1/policy"),
    readLabState(),
  ]);
  const generatedAt = new Date().toISOString();
  const nodes = (labState.nodes || []).map((entry) => ({
    node: {
      node_id: entry.nodeId,
      vpn_ip: entry.overlay || "-",
      role: roleFor(entry.role),
      tags: [entry.role, entry.name].filter(Boolean),
      routes: [],
      relay_capability: (entry.services || []).includes("relay")
        ? {
            enabled_by_policy: true,
            public_endpoint: entry.underlay ? `${entry.underlay}:51820` : null,
            admission_url: entry.underlay ? `http://${entry.underlay}:9580` : null,
            max_sessions: 10000,
            active_sessions: 0,
            max_mbps: 1000,
            e2e_only: true,
          }
        : null,
      registered_at: labState.generatedAt || generatedAt,
    },
    health: {
      state: "healthy",
      last_seen_at: generatedAt,
      candidate_count: entry.candidate ? 1 : 0,
    },
  }));
  const paths = (labState.paths || []).map((entry) => ({
    key: { local: entry.local, remote: entry.remote },
    selected_state: String(entry.state || "unknown").toLowerCase(),
    selected_candidate: null,
    relay_node: entry.relay || null,
    score: {
      value: entry.dataplane === "down" ? 85 : 100,
      reasons: [entry.state ? `state=${entry.state}` : "state=unknown", `dataplane=${entry.dataplane || "unknown"}`],
    },
    updated_at: labState.generatedAt || generatedAt,
    pinned: false,
  }));
  return {
    cluster_id: metrics.cluster_id || policy.cluster_id,
    vpn_pool: policy.vpn_pool || "100.64.0.0/10",
    cluster_policy: normalizePolicy(policy.cluster_policy || {}),
    metrics: {
      ...metrics,
      path_count: paths.length,
      stale_path_count: Number(metrics.stale_path_count || 0),
    },
    nodes,
    paths,
    generated_at: generatedAt,
  };
}

function normalizePolicy(policy) {
  return {
    allow_ipv6_direct: Boolean(policy.allow_ipv6_direct),
    allow_nat_traversal: Boolean(policy.allow_nat_traversal),
    allow_relay_fallback: Boolean(policy.allow_relay_fallback),
    idle_timeout_seconds: Number(policy.idle_timeout_seconds || 300),
    relay_health_ttl_seconds: Number(policy.relay_health_ttl_seconds || 90),
    endpoint_candidate_ttl_seconds: Number(policy.endpoint_candidate_ttl_seconds || 120),
    nat_classification_ttl_seconds: Number(policy.nat_classification_ttl_seconds || 300),
    nat_classification_min_confidence_percent: Number(policy.nat_classification_min_confidence_percent || 50),
    path_state_ttl_seconds: Number(policy.path_state_ttl_seconds || 300),
    pinned_roles: Array.isArray(policy.pinned_roles) ? policy.pinned_roles : [],
    pinned_tags: Array.isArray(policy.pinned_tags) ? policy.pinned_tags : [],
    acl_rules: Array.isArray(policy.acl_rules) ? policy.acl_rules : [],
  };
}

async function readLabState() {
  try {
    return JSON.parse(await readFile(statePath, "utf8"));
  } catch {
    return { generatedAt: new Date().toISOString(), nodes: [], paths: [] };
  }
}

async function fetchJson(pathname) {
  const response = await fetch(`${controlPlaneUrl}${pathname}`, { headers: { Accept: "application/json" } });
  if (!response.ok) throw httpError(response.status, `control-plane request failed: ${pathname}`);
  return response.json();
}

async function proxyJson(response, pathname) {
  sendJson(response, await fetchJson(pathname));
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

function roleFor(role) {
  if (role === "public-relay") return "control-plane";
  if (role === "double-nat") return "edge";
  return role || "edge";
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
