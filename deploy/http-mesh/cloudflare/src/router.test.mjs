import assert from "node:assert/strict";
import test from "node:test";
import { route } from "./router.mjs";

test("unauthenticated requests cannot start or stop containers", async () => {
  let resolved = 0;
  const env = { MANAGEMENT_TOKEN: "m".repeat(32) };
  for (const token of ["", "Bearer wrong", "Bearer " + "x".repeat(32)]) {
    const response = await route(new Request("https://members.example/nodes/a", { method: "PUT", headers: { Authorization: token } }), env, () => { resolved++; });
    assert.equal(response.status, 401);
  }
  assert.equal(resolved, 0);
});
test("management authenticates before lifecycle operations and exposes no secrets", async () => {
  const env = { MANAGEMENT_TOKEN: "m".repeat(32) };
  let stopped = false, calls = 0;
  const resolve = (_, id) => {
    calls++; assert.equal(id,"replica-2");
    return { fetch: async () => new Response("secret must not reach response",{status:200}), stop:async()=>{stopped=true;} };
  };
  for (const method of ["PUT","GET","DELETE"]) {
    const response = await route(new Request("https://members.example/nodes/replica-2",{method,headers:{Authorization:`Bearer ${env.MANAGEMENT_TOKEN}`}}),env,resolve);
    assert.equal(response.status,204); assert.equal(await response.text(),"");
  }
  assert.equal(calls,3);assert.equal(stopped,true);
});
