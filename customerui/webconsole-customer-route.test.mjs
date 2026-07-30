import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("customer console exposes only the customer UI and API surface", async (t) => {
  const port = await availablePort();
  const origin = `http://127.0.0.1:${port}`;
  const child = spawn(process.execPath, ["webconsole/server.mjs"], {
    cwd: root,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: String(port),
      HETERONETWORK_CONSOLE_MODE: "customer",
      HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL: origin,
      HETERONETWORK_CUSTOMER_API_URL: "http://127.0.0.1:19443",
      HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL:
        "https://identity.example.test/realms/heteronetwork-customers",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill("SIGTERM"));
  await waitUntilReady(child, `${origin}/cloud/config`);

  const indexResponse = await fetch(`${origin}/cloud/`);
  assert.equal(indexResponse.status, 200);
  assert.match(
    indexResponse.headers.get("content-security-policy") || "",
    /script-src 'self'/,
  );
  assert.equal(indexResponse.headers.get("x-frame-options"), "DENY");
  assert.equal(indexResponse.headers.get("referrer-policy"), "no-referrer");
  assert.match(await indexResponse.text(), /HeteroNetwork Cloud/);

  const configResponse = await fetch(`${origin}/cloud/config`);
  assert.equal(configResponse.status, 200);
  const config = await configResponse.json();
  assert.equal(config.client_id, "heteronetwork-customer-console");
  assert.equal(
    config.issuer_url,
    "https://identity.example.test/realms/heteronetwork-customers",
  );
  assert.equal(config.login_endpoint, "/cloud/login");

  assert.equal((await fetch(`${origin}/ui/`)).status, 404);
  assert.equal((await fetch(`${origin}/v1/admin/overview`)).status, 404);
  assert.equal((await fetch(`${origin}/v1/metrics`)).status, 404);

  const customerApi = await fetch(`${origin}/v1/customer/session`);
  assert.equal(customerApi.status, 401);
});

test("customer console fails closed without customer-specific endpoints", async () => {
  const child = spawn(process.execPath, ["webconsole/server.mjs"], {
    cwd: root,
    env: {
      ...process.env,
      HETERONETWORK_CONSOLE_MODE: "customer",
      HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL: "",
      HETERONETWORK_CUSTOMER_API_URL: "",
      HETERONETWORK_CUSTOMER_OIDC_ISSUER_URL: "",
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const [code] = await once(child, "exit");
  assert.notEqual(code, 0);
  assert.match(stderr, /HETERONETWORK_CUSTOMER_WEB_PUBLIC_URL is required/);
});

async function availablePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  server.close();
  await once(server, "close");
  return port;
}

async function waitUntilReady(child, url) {
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode != null) {
      throw new Error(`customer console exited before becoming ready: ${stderr}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The listener has not started yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`customer console did not become ready: ${stderr}`);
}
