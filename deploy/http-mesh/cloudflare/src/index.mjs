import { DurableObject } from "cloudflare:workers";
import { MemberLifecycle } from "./lifecycle.mjs";
import { route } from "./router.mjs";

export class HeteronetMember extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.member = new MemberLifecycle(ctx, env);
    ctx.blockConcurrencyWhile(() => this.member.restore());
  }
  fetch(request) { return this.member.fetch(request); }
  stop() { return this.member.stop(); }
  alarm() { return this.member.alarm(); }
}
export default {
  fetch: (request, env) => route(request, env, (namespace, name) => namespace.getByName(name)),
};
