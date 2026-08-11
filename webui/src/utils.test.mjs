import assert from "node:assert/strict";
import test from "node:test";
import {
  agentBuild,
  connectivity,
  nodeDisplayName,
  pathState,
  shortId,
  topologyMermaid,
} from "./utils.js";

test("agent build metadata is normalized for node views", () => {
  assert.deepEqual(agentBuild({ agent_build: { version: "0.1.0", commit: "abc1234" } }), {
    version: "0.1.0",
    commit: "abc1234",
  });
  assert.equal(agentBuild({}), null);
});

test("node and path presentation helpers normalize API values", () => {
  assert.equal(shortId("node-abcdefghijklmnopqrstuvwxyz").includes("…"), true);
  assert.equal(
    nodeDisplayName({
      node_id: "node-a",
      display_name: "uc-k8sv1",
      hostname: "compute-vm",
    }),
    "uc-k8sv1",
  );
  assert.equal(nodeDisplayName({ node_id: "node-a", hostname: "uc-k8sp1" }), "uc-k8sp1");
  assert.equal(nodeDisplayName({ node_id: "node-a" }), "node-a");
  assert.equal(pathState("DirectNatTraversal"), "direct_nat_traversal");
  assert.deepEqual(connectivity({ connectivity_state: "public" }), {
    state: "healthy",
    label: "公開",
  });
  assert.deepEqual(connectivity({ connectivity_state: "mapped_public" }), {
    state: "healthy",
    label: "公開",
  });
  assert.deepEqual(
    connectivity({
      nat_classification: { connectivity_state: "mapped_public" },
    }),
    {
      state: "healthy",
      label: "公開",
    },
  );
});

test("Mermaid source includes hierarchy, members, and observed links", () => {
  const source = topologyMermaid({
    groups: [
      {
        group_id: "root",
        depth: 0,
        leaf: false,
        child_group_ids: ["leaf"],
      },
      {
        group_id: "leaf",
        depth: 1,
        leaf: true,
        child_group_ids: [],
      },
    ],
    nodes: [
      {
        node_id: "node-a",
        hostname: "uc-k8sp1",
        vpn_ip: "10.250.0.1",
        leaf_group_id: "leaf",
      },
      { node_id: "node-b", vpn_ip: "10.250.0.2", leaf_group_id: "leaf" },
    ],
    edges: [
      {
        source: "node-a",
        target: "node-b",
        placements: [{ kind: "leaf_cycle" }],
      },
    ],
  });

  assert.match(source, /^flowchart TB/m);
  assert.match(source, /root/);
  assert.match(source, /10\.250\.0\.1/);
  assert.match(source, /uc-k8sp1/);
  assert.match(source, /Leaf Cycle/);
  assert.match(source, /-->/);
  assert.match(source, /---\|/);
});

test("Mermaid labels neutralize quotes and line breaks", () => {
  const source = topologyMermaid({
    groups: [],
    nodes: [
      {
        node_id: 'node-"unsafe\nvalue',
        vpn_ip: "10.250.0.1",
      },
    ],
    edges: [],
  });
  assert.doesNotMatch(source, /unsafe\nvalue/);
  assert.match(source, /'unsafe value/);
});
