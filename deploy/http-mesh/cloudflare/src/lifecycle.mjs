const INACTIVITY_MS = 5 * 60 * 1000;
const HEARTBEAT_MS = 60 * 1000;
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export class MemberLifecycle {
  constructor(ctx, env, sleep = pause) {
    this.ctx = ctx;
    this.env = env;
    this.sleep = sleep;
  }
  failure(stage, error) {
    let detail = String(error?.message || error);
    for (const secret of [this.env.MANAGEMENT_TOKEN, this.env.HETERONETWORK_JOIN_TOKEN]) {
      if (secret) detail = detail.replaceAll(secret, "[REDACTED]").replaceAll(JSON.stringify(secret).slice(1, -1), "[REDACTED]");
    }
    console.error("Heteronet container failure", { stage, detail: detail.slice(0, 500) });
  }
  async restore() {
    if (await this.ctx.storage.get("enabled")) {
      if (this.ctx.container.running) await this.ctx.container.setInactivityTimeout(INACTIVITY_MS);
      await this.ctx.storage.setAlarm(Date.now() + HEARTBEAT_MS);
    }
  }
  async ensureRunning() {
    const container = this.ctx.container;
    if (!container.running) {
      container.start({
        image: container.images.base,
        instance: this.env.HETERONETWORK_INSTANCE || "lite",
        enableInternet: true,
        entrypoint: ["/heteronet-headless", ...(this.env.HETERONETWORK_ARGS || [])],
        env: {
          HETERONETWORK_ENDPOINT: this.env.HETERONETWORK_ENDPOINT,
          HETERONETWORK_JOIN_TOKEN: this.env.HETERONETWORK_JOIN_TOKEN,
          ...(this.env.HETERONETWORK_HTTP_MESH_ENDPOINT
            ? { HETERONETWORK_HTTP_MESH_ENDPOINT: this.env.HETERONETWORK_HTTP_MESH_ENDPOINT }
            : {}),
          GOMEMLIMIT: "192MiB", GOMAXPROCS: "1",
        },
      });
      this.ctx.waitUntil(container.monitor().catch(error => this.failure("process", error)));
    }
    await container.setInactivityTimeout(INACTIVITY_MS);
  }
  async fetch() {
    await this.ctx.storage.put("enabled", true);
    await this.ctx.storage.setAlarm(Date.now() + HEARTBEAT_MS);
    await this.ensureRunning();
    // start() returns before the VM and the VPN are ready. Health retries have
    // no application side effects and never return the container's response body.
    for (let attempt = 0; attempt < 100; attempt++) {
      if (!await this.ctx.storage.get("enabled")) return new Response(null, { status: 503 });
      try {
        const response = await this.ctx.container.getTcpPort(8080).fetch("http://container/readyz");
        const ready = response.ok;
        await response.body?.cancel();
        if (ready) return new Response(null, { status: 204 });
      } catch (error) {
        if (attempt === 99) this.failure("readiness", error);
      }
      await this.sleep(500);
    }
    return new Response(null, { status: 503 });
  }
  async stop() {
    // Persist the stop before signaling so an in-flight alarm cannot revive it.
    await this.ctx.storage.put("enabled", false);
    await this.ctx.storage.deleteAlarm();
    const container = this.ctx.container;
    if (!container.running) return;
    container.signal(15);
    for (let attempt = 0; attempt < 20 && container.running; attempt++) await this.sleep(250);
    if (container.running) await container.destroy("Stopped by authenticated management request");
  }
  async alarm() {
    if (!await this.ctx.storage.get("enabled")) return;
    try { await this.ensureRunning(); }
    finally {
      if (await this.ctx.storage.get("enabled")) await this.ctx.storage.setAlarm(Date.now() + HEARTBEAT_MS);
    }
  }
}
