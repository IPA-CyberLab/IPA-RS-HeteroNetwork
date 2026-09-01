import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const checker = path.join(scriptDirectory, "keycloak-ha-e2e.sh");
let baseUrl = "";
let privateBaseUrl = "";
let failureMode = "healthy";

function discovery(issuer) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
  };
}

function json(response, status, body) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, baseUrl);
  const publicIssuer = `${baseUrl}/id/realms/heterocloud`;
  const privateIssuer = `${privateBaseUrl}/realms/heterocloud`;

  if (url.pathname === "/api/v1/auth/oidc/start") {
    const target = new URL(`${publicIssuer}/protocol/openid-connect/auth`);
    target.searchParams.set("response_type", "code");
    target.searchParams.set("client_id", "heterocloud-web");
    target.searchParams.set("redirect_uri", `${baseUrl}/api/v1/auth/oidc/callback`);
    target.searchParams.set("scope", "openid profile email");
    target.searchParams.set("state", "s".repeat(43));
    target.searchParams.set("nonce", "n".repeat(43));
    target.searchParams.set("code_challenge", "c".repeat(43));
    target.searchParams.set("code_challenge_method", "S256");
    response.writeHead(303, {
      location: target.toString(),
      "set-cookie": "hc_oidc_transaction=test; HttpOnly; SameSite=Lax; Secure; Path=/api/v1/auth/oidc/callback; Max-Age=300",
    });
    response.end();
    return;
  }

  if (url.pathname === "/id/realms/heterocloud/.well-known/openid-configuration") {
    json(response, 200, discovery(publicIssuer));
    return;
  }

  if (url.pathname === "/id/realms/heterocloud/protocol/openid-connect/auth") {
    if (failureMode === "login") {
      response.writeHead(503, { "content-type": "text/plain" });
      response.end("503 Service Unavailable: No server is available");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><html><head>
      <link href="/id/resources/test/common.css" rel="stylesheet">
      <link href="/id/resources/test/login.css" rel="stylesheet">
      <script src="/id/resources/test/login.js"></script>
      </head><body><input name="username"><input name="password">
      <a href="/id/realms/heterocloud/login-actions/registration?client_id=heterocloud-web&amp;tab_id=test">Register</a>
      </body></html>`);
    return;
  }

  if (url.pathname === "/id/realms/heterocloud/login-actions/registration") {
    if (failureMode === "registration") {
      response.writeHead(503, { "content-type": "text/plain" });
      response.end("503 Service Unavailable");
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(`<!doctype html><html><body>
      <input name="email"><input name="firstName"><input name="lastName">
      <input name="password"><input name="password-confirm">
      </body></html>`);
    return;
  }

  if (url.pathname.startsWith("/id/resources/test/")) {
    if (failureMode === "asset") {
      response.writeHead(404, { "content-type": "text/plain" });
      response.end("missing");
      return;
    }
    const javascript = url.pathname.endsWith(".js");
    response.writeHead(200, {
      "content-type": javascript ? "text/javascript" : "text/css",
    });
    response.end(javascript ? "void 0;" : "body { display: block; }");
    return;
  }

  if (url.pathname === "/health/ready") {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("ready");
    return;
  }

  if (url.pathname === "/realms/heterocloud/.well-known/openid-configuration") {
    if (failureMode === "backend" && request.headers["x-forwarded-host"]) {
      response.writeHead(503, { "content-type": "text/plain" });
      response.end("backend unavailable");
      return;
    }
    const requestedHost =
      request.headers["x-forwarded-host"] || request.headers.host || "";
    json(
      response,
      200,
      discovery(requestedHost.startsWith("localhost:") ? privateIssuer : publicIssuer),
    );
    return;
  }

  if (url.pathname === "/v1/web-ui/auth/device" && request.method === "POST") {
    if (failureMode === "device") {
      json(response, 503, { error: "identity provider unavailable" });
      return;
    }
    json(response, 200, {
      handle: "h".repeat(43),
      user_code: "ABCD-EFGH",
      verification_uri: `${privateIssuer}/device`,
      verification_uri_complete: `${privateIssuer}/device?user_code=ABCD-EFGH`,
      expires_in: 600,
      interval: 5,
    });
    return;
  }

  response.writeHead(404, { "content-type": "text/plain" });
  response.end("not found");
});

async function runChecker(extraArguments = []) {
  const arguments_ = [
    "--public-base-url",
    baseUrl,
    "--private-edge-url",
    privateBaseUrl,
    "--agent-gateway-url",
    baseUrl,
    "--backend-url",
    baseUrl,
    "--require-backends",
    "1",
    "--attempts",
    "3",
    ...extraArguments,
  ];
  return await new Promise((resolve, reject) => {
    const child = spawn(checker, arguments_, {
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status, signal) => resolve({ status, signal, stdout, stderr }));
  });
}

await new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", resolve);
});
const address = server.address();
assert(address && typeof address === "object");
baseUrl = `http://127.0.0.1:${address.port}`;
privateBaseUrl = `http://localhost:${address.port}`;

try {
  const healthy = await runChecker();
  assert.equal(healthy.status, 0, healthy.stderr || healthy.stdout);
  assert.match(healthy.stdout, /public OIDC login passed 3\/3 attempts/);
  assert.match(healthy.stdout, /direct replica discovery passed 1\/1 backends/);

  const expectedFailures = new Map([
    ["login", "returned HTTP 503"],
    ["asset", "asset is unavailable"],
    ["registration", "self-registration returned HTTP 503"],
    ["device", "authorization returned HTTP 503"],
    ["backend", "private realm returned HTTP 503"],
  ]);
  for (const [mode, expectedFailure] of expectedFailures) {
    failureMode = mode;
    const failed = await runChecker();
    assert.notEqual(failed.status, 0, `${mode} failure was not detected`);
    assert.match(failed.stderr, new RegExp(expectedFailure));
    failureMode = "healthy";
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}

console.log("keycloak HA E2E smoke: ok");
