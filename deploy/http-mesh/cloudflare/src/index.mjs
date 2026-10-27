import { Container, getContainer } from "@cloudflare/containers";
import { route } from "./router.mjs";

export class HeteronetMember extends Container {
  defaultPort = 8080;
  sleepAfter = "5m";
  enableInternet = true;
  envVars = {
    HETERONETWORK_ENDPOINT: this.env.HETERONETWORK_ENDPOINT,
    HETERONETWORK_JOIN_TOKEN: this.env.HETERONETWORK_JOIN_TOKEN,
  };
  // VPN membership must remain online even without incoming Worker requests.
  async onActivityExpired() { this.renewActivityTimeout(); }
}
export default { fetch: (request, env) => route(request, env, getContainer) };
