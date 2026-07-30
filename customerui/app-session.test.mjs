import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { JSDOM } from "jsdom";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("customer console restores an expired browser session through the refresh cookie", async () => {
  const html = await readFile(path.join(root, "customerui/index.html"), "utf8");
  const dom = new JSDOM(html, { url: "https://cloud.example.test/cloud/" });
  const calls = [];
  const previous = installDomGlobals(dom);
  globalThis.fetch = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method || "GET" });
    if (url === "/cloud/config") {
      return jsonResponse({
        session_refresh_endpoint: "/cloud/auth/refresh",
        session_logout_endpoint: "/cloud/auth/logout",
      });
    }
    if (url === "/cloud/auth/refresh") {
      return jsonResponse({ access_token: "refreshed-access-token", expires_in: 300 });
    }
    if (url === "/v1/customer/session") {
      assert.equal(init.headers.Authorization, "Bearer refreshed-access-token");
      return jsonResponse({
        principal: {
          subject: "customer-a",
          preferred_username: "customer-a",
        },
        account: {
          account_id: "acct_00000000000000000000000000000000",
          quota: { max_projects: 10, max_public_services: 100 },
        },
      });
    }
    if (url === "/v1/customer/projects") {
      return jsonResponse({ projects: [] });
    }
    return jsonResponse({ error: "unexpected request" }, 500);
  };

  try {
    await import(`${pathToFileURL(path.join(root, "customerui/app.js")).href}?session-test=1`);
    await waitFor(() => !dom.window.document.getElementById("workspace").hidden);
    assert.equal(
      dom.window.sessionStorage.getItem("heteronetwork_customer_access_token"),
      "refreshed-access-token",
    );
    assert.ok(calls.some((call) => call.url === "/cloud/auth/refresh"));
    assert.equal(dom.window.document.getElementById("auth-panel").hidden, true);
  } finally {
    restoreDomGlobals(previous);
    dom.window.close();
  }
});

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

async function waitFor(predicate) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("customer console did not finish loading");
}

function installDomGlobals(dom) {
  const names = [
    "document",
    "window",
    "location",
    "sessionStorage",
    "FormData",
    "confirm",
    "fetch",
  ];
  const previous = new Map(names.map((name) => [name, globalThis[name]]));
  globalThis.document = dom.window.document;
  globalThis.window = dom.window;
  globalThis.location = dom.window.location;
  globalThis.sessionStorage = dom.window.sessionStorage;
  globalThis.FormData = dom.window.FormData;
  globalThis.confirm = () => true;
  return previous;
}

function restoreDomGlobals(previous) {
  for (const [name, value] of previous) {
    if (value === undefined) {
      delete globalThis[name];
    } else {
      globalThis[name] = value;
    }
  }
}
