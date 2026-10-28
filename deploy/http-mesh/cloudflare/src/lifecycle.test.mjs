import assert from "node:assert/strict";
import test from "node:test";
import { MemberLifecycle } from "./lifecycle.mjs";

function fixture() {
  const values = new Map(), starts = [], alarms = [], signals = [];
  const container = {
    running: false, images: { base: "registry.cloudflare.com/account/member@sha256:verified" },
    start(options) { starts.push(options); this.running = true; },
    monitor() { return new Promise(() => {}); },
    async setInactivityTimeout(ms) { assert.equal(ms, 300000); },
    getTcpPort(port) { assert.equal(port, 8080); return { fetch: async () => new Response(null, { status: 204 }) }; },
    signal(value) { signals.push(value); this.running = false; },
    async destroy() { assert.fail("graceful stop should finish before destruction"); },
  };
  const storage = { get: async key => values.get(key), put: async (key, value) => values.set(key, value),
    setAlarm: async at => alarms.push(at), deleteAlarm: async () => alarms.splice(0) };
  const env = { HETERONETWORK_ENDPOINT: "https://control.example", HETERONETWORK_JOIN_TOKEN: "join-secret",
    MANAGEMENT_TOKEN: "management-must-stay-in-the-worker", HETERONETWORK_ARGS: ["--publish", "18081=127.0.0.1:8080"] };
  return { member: new MemberLifecycle({ container, storage, waitUntil() {} }, env, async () => {}), container, storage, starts, alarms, signals };
}
test("cold start uses the prepared image and keeps management credentials outside the VM", async () => {
  const f = fixture();
  assert.equal((await f.member.fetch()).status, 204); assert.equal((await f.member.fetch()).status, 204);
  assert.equal(f.starts.length, 1); assert.equal(f.starts[0].image, f.container.images.base);
  assert.equal(f.starts[0].instance, "lite"); assert.equal(f.starts[0].env.HETERONETWORK_JOIN_TOKEN, "join-secret");
  assert.equal(f.starts[0].env.MANAGEMENT_TOKEN, undefined);
  assert.deepEqual(f.starts[0].entrypoint, ["/heteronet-headless", "--publish", "18081=127.0.0.1:8080"]);
});
test("stopped membership stays stopped across alarms and Durable Object reconstruction", async () => {
  const f = fixture(); await f.member.fetch(); await f.member.stop();
  await f.member.alarm(); await f.member.restore();
  assert.equal(f.starts.length, 1); assert.equal(f.alarms.length, 0);
  assert.deepEqual(f.signals, [15]); assert.equal(await f.storage.get("enabled"), false);
});
test("idle VPN membership is renewed and recovered after a VM exit", async () => {
  const f = fixture(); await f.member.fetch(); await f.member.alarm(); assert.equal(f.starts.length, 1);
  f.container.running = false; await f.member.alarm();
  assert.equal(f.starts.length, 2); assert.ok(f.alarms.length > 0);
});
test("runtime diagnostics redact both raw and JSON-escaped credential values", () => {
  const f = fixture(), captured = [], original = console.error;
  f.member.env.HETERONETWORK_JOIN_TOKEN = '{"claims":{"role":"worker"},"signature":"sensitive-signature"}';
  try {
    console.error = (...args) => captured.push(args);
    const token = f.member.env.HETERONETWORK_JOIN_TOKEN;
    f.member.failure("process", new Error(token + " " + JSON.stringify(token).slice(1, -1)
      + " " + f.member.env.MANAGEMENT_TOKEN));
  } finally { console.error = original; }
  const output = JSON.stringify(captured);
  assert.ok(output.includes("[REDACTED]"));
  assert.equal(output.includes("sensitive-signature"), false);
  assert.equal(output.includes(f.member.env.MANAGEMENT_TOKEN), false);
});
