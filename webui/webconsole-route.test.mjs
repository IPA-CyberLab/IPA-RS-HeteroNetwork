import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";

import { createWebConsoleServer } from "../webconsole/server.mjs";

test("standalone WebConsole serves the pinned Mermaid bundle from its own origin", async (t) => {
  const server = createWebConsoleServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());

  const address = server.address();
  assert.equal(typeof address, "object");
  const origin = `http://127.0.0.1:${address.port}`;

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
});
