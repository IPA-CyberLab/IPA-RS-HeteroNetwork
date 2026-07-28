import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { JSDOM } from "jsdom";

const webuiUrl = new URL("./", import.meta.url);
const indexHtml = await readFile(new URL("index.html", webuiUrl), "utf8");
const appSource = await readFile(new URL("app.js", webuiUrl), "utf8");
const mermaidBundle = await readFile(new URL("vendor/mermaid.min.js", webuiUrl), "utf8");

test("topology rendering rejects stale Mermaid results and preserves the SVG fallback", async (t) => {
  const dom = new JSDOM(indexHtml, {
    runScripts: "outside-only",
    url: "http://127.0.0.1:18088/ui/",
  });
  t.after(() => dom.window.close());
  const { window } = dom;
  window.console.error = () => {};
  window.confirm = () => true;
  window.Headers = globalThis.Headers;
  window.Response = globalThis.Response;
  window.sessionStorage.setItem("heteronetwork_operator_token", "test-token");

  const renderCalls = [];
  let mermaidConfig;
  window.mermaid = {
    initialize(config) {
      mermaidConfig = config;
    },
    render(id, source) {
      return new Promise((resolve, reject) => {
        renderCalls.push({ id, reject, resolve, source });
      });
    },
  };
  window.fetch = async (input) => {
    const pathname = new URL(String(input), window.location.href).pathname;
    if (pathname === "/ui/config") return jsonResponse(uiConfig());
    if (pathname === "/v1/admin/overview") return jsonResponse(overview());
    if (pathname === "/v1/admin/topology") return jsonResponse(topology());
    if (pathname === "/v1/admin/policy") {
      return jsonResponse({ cluster_policy: clusterPolicy() });
    }
    throw new Error(`unexpected fetch: ${pathname}`);
  };

  window.eval(appSource);
  await waitFor(() => !window.document.querySelector("#dashboard").hidden);
  window.document.querySelector('[data-view="topology"]').click();
  await waitFor(() => renderCalls.length === 1);

  const firstTarget = window.document.querySelector("#overlay-mermaid-diagram");
  assert.ok(firstTarget.querySelector("svg.overlay-topology-svg"));
  const sourcePanel = window.document.querySelector(".overlay-mermaid-panel code").textContent;
  assert.equal(renderCalls[0].source, sourcePanel);

  window.document.querySelector("button[data-topology-group]").click();
  const secondTarget = window.document.querySelector("#overlay-mermaid-diagram");
  assert.notEqual(secondTarget, firstTarget);
  renderCalls[0].resolve({ svg: '<svg id="stale" viewBox="0 0 800 400"></svg>' });
  await waitFor(() => renderCalls.length === 2);
  renderCalls[1].resolve({ svg: '<svg id="fresh" viewBox="0 0 900 400"></svg>' });
  await waitFor(() => secondTarget.dataset.renderer === "mermaid");

  assert.equal(firstTarget.querySelector("#stale"), null);
  assert.ok(secondTarget.querySelector("svg#fresh.overlay-mermaid-svg"));
  assert.equal(secondTarget.querySelector("svg").style.width, "900px");
  window.document.querySelector('[data-topology-zoom="in"]').click();
  assert.equal(secondTarget.querySelector("svg").style.width, "1080px");

  window.document.querySelector("button[data-topology-group]").click();
  await waitFor(() => renderCalls.length === 3);
  renderCalls[2].reject(new Error("synthetic renderer failure"));
  const fallbackTarget = window.document.querySelector("#overlay-mermaid-diagram");
  await waitFor(() => fallbackTarget.querySelector(".overlay-mermaid-fallback-notice"));
  assert.equal(fallbackTarget.dataset.renderer, "fallback");
  assert.ok(fallbackTarget.querySelector("svg.overlay-topology-svg"));

  assert.equal(mermaidConfig.securityLevel, "strict");
  assert.equal(mermaidConfig.startOnLoad, false);
  assert.equal(mermaidConfig.suppressErrorRendering, true);
  assert.equal(mermaidConfig.flowchart.htmlLabels, false);
});

test("the pinned Mermaid bundle renders the topology source offline in strict mode", async (t) => {
  const dom = new JSDOM("<!doctype html><body></body>", {
    runScripts: "outside-only",
    url: "http://127.0.0.1:18088/ui/",
  });
  t.after(() => dom.window.close());
  const { window } = dom;
  window.SVGElement.prototype.getBBox = function () {
    return {
      height: 20,
      width: Math.max(80, String(this.textContent || "").length * 7),
      x: 0,
      y: 0,
    };
  };
  window.SVGElement.prototype.getComputedTextLength = function () {
    return Math.max(20, String(this.textContent || "").length * 7);
  };
  window.eval(mermaidBundle);
  window.mermaid.initialize({
    flowchart: { htmlLabels: false, useMaxWidth: false },
    securityLevel: "strict",
    startOnLoad: false,
    suppressErrorRendering: true,
  });

  const source = [
    "flowchart TB",
    '  subgraph sg_group_0["Depth 0 · group-root"]',
    "    direction TB",
    '    group_0["2 nodes · reps node-a p0, node-b p1"]',
    '    subgraph sg_group_1["Depth 1 · group-child"]',
    "      direction TB",
    '      group_1["1 nodes · reps node-b p0"]',
    "    end",
    "  end",
    "  group_0 --> group_1",
    "  group_0 -.-|sibling p0 ×1| group_1",
    "  class group_0,group_1 group",
  ].join("\n");
  const result = await window.mermaid.render("offline-topology", source);
  assert.match(result.svg, /^<svg\b/);
  assert.match(result.svg, /id="offline-topology"/);
  assert.match(result.svg, /group-root/);
  assert.ok(result.svg.length > 1_000);
});

function jsonResponse(body) {
  return {
    headers: new Headers(),
    json: async () => structuredClone(body),
    ok: true,
    status: 200,
    statusText: "OK",
  };
}

function uiConfig() {
  return {
    auth_enabled: false,
    bootstrap_required: false,
    client_enrollment_enabled: false,
    enabled: true,
    local_agent: false,
    node_enrollment_enabled: false,
    operator_token_enabled: true,
  };
}

function clusterPolicy() {
  return {
    acl_rules: [],
    allow_ipv6_direct: true,
    allow_nat_traversal: true,
    allow_relay_fallback: true,
    overlay_block_size: 4,
    overlay_direct_shortcut_limit: 0,
    overlay_max_degree: 4,
    path_state_ttl_seconds: 90,
  };
}

function overview() {
  return {
    cluster_id: "cluster-test",
    cluster_policy: clusterPolicy(),
    generated_at: "2026-07-28T12:00:00Z",
    metrics: {
      active_service_instance_count: 0,
      healthy_node_count: 2,
      node_count: 2,
      path_count: 0,
    },
    nat_discovery: {},
    nodes: [],
    paths: [],
    service_directory: {
      bootstrap_endpoints: [],
      instances: [],
    },
  };
}

function topology() {
  return {
    algorithm: "recursive-hash-prefix-block-ring-v3",
    cluster_id: "cluster-test",
    diameter_lower_bound: 1,
    direct_shortcut_limit: 0,
    edge_count: 1,
    edges: [{
      last_observed_at: null,
      observed_status: "unknown",
      path_states: [],
      placements: [{
        depth: 0,
        group_id: "group-root",
        kind: "leaf_cycle",
        plane: 0,
      }],
      source: "node-a",
      target: "node-b",
    }],
    fanout: 4,
    generated_at: "2026-07-28T12:00:00Z",
    group_count: 1,
    groups: [{
      child_group_ids: [],
      depth: 0,
      group_id: "group-root",
      leaf: true,
      node_ids: ["node-a", "node-b"],
      representatives: [{
        node_id: "node-a",
        plane: 0,
        role: "primary",
      }, {
        node_id: "node-b",
        plane: 1,
        role: "secondary",
      }],
    }],
    level_count: 1,
    max_degree: 4,
    max_observed_degree: 1,
    node_count: 2,
    nodes: [{
      ancestry: ["group-root"],
      degree: 1,
      health_state: "healthy",
      last_seen_at: "2026-07-28T12:00:00Z",
      leaf_group_id: "group-root",
      node_id: "node-a",
      representative_for: [{ depth: 0, group_id: "group-root", plane: 0 }],
      role: "edge",
      tags: [],
      vpn_ip: "10.250.0.1",
    }, {
      ancestry: ["group-root"],
      degree: 1,
      health_state: "healthy",
      last_seen_at: "2026-07-28T12:00:00Z",
      leaf_group_id: "group-root",
      node_id: "node-b",
      representative_for: [{ depth: 0, group_id: "group-root", plane: 1 }],
      role: "worker",
      tags: [],
      vpn_ip: "10.250.0.2",
    }],
    root_group_id: "group-root",
    topology_epoch: "123456789",
  };
}

async function waitFor(predicate, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  assert.fail("timed out waiting for condition");
}
