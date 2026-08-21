import { expect, test } from "@playwright/test";
import path from "node:path";
import { fileURLToPath } from "node:url";

const webuiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const nodes = Array.from({ length: 5 }, (_, index) => ({
  node: {
    node_id: `node-${index + 1}-0123456789abcdef`,
    hostname: `uc-k8sp${index + 1}`,
    vpn_ip: `10.250.0.${index + 1}`,
    role: index < 2 ? "edge" : "worker",
    tags: index < 3 ? ["kubernetes-control-plane"] : ["kubernetes-worker"],
    routes: [],
    registered_at: "2026-08-04T06:00:00Z",
  },
  health: {
    state: "healthy",
    last_seen_at: "2026-08-04T07:00:00Z",
  },
  connectivity_state: index < 2 ? "public" : "private",
  public_ips: index < 2 ? [`163.220.236.${51 + index}`] : [],
}));

const paths = nodes.flatMap((local, localIndex) =>
  nodes
    .filter((_, remoteIndex) => remoteIndex !== localIndex)
    .map((remote, remoteIndex) => ({
      local_node_id: local.node.node_id,
      remote_node_id: remote.node.node_id,
      selected_state: remoteIndex % 2 === 0 ? "DirectNatTraversal" : "Relay",
      relay_node_id: remoteIndex % 2 === 0 ? null : nodes[0].node.node_id,
      score: 100 - remoteIndex,
      pinned: false,
      updated_at: "2026-08-04T07:00:00Z",
    })),
);

const policy = {
  allow_relay_fallback: true,
  overlay_block_size: 4,
  overlay_max_degree: 4,
  overlay_direct_shortcut_limit: 0,
  overlay_on_demand_peer_limit: 4,
  acl_rules: [],
};

const topology = {
  node_count: 5,
  group_count: 3,
  level_count: 2,
  edge_count: 5,
  max_observed_degree: 4,
  diameter_lower_bound: 3,
  fanout: 4,
  max_degree: 4,
  direct_shortcut_limit: 0,
  on_demand_peer_limit: 4,
  topology_epoch: 12,
  groups: [
    {
      group_id: "root",
      depth: 0,
      leaf: false,
      node_ids: [],
      child_group_ids: ["leaf-a", "leaf-b"],
      representatives: [{ node_id: nodes[0].node.node_id, role: "primary" }],
    },
    {
      group_id: "leaf-a",
      parent_group_id: "root",
      depth: 1,
      leaf: true,
      node_ids: nodes.slice(0, 3).map((entry) => entry.node.node_id),
      child_group_ids: [],
      representatives: [{ node_id: nodes[0].node.node_id, role: "primary" }],
    },
    {
      group_id: "leaf-b",
      parent_group_id: "root",
      depth: 1,
      leaf: true,
      node_ids: nodes.slice(3).map((entry) => entry.node.node_id),
      child_group_ids: [],
      representatives: [{ node_id: nodes[3].node.node_id, role: "primary" }],
    },
  ],
  nodes: nodes.map((entry, index) => ({
    node_id: entry.node.node_id,
    hostname: entry.node.hostname,
    vpn_ip: entry.node.vpn_ip,
    leaf_group_id: index < 3 ? "leaf-a" : "leaf-b",
  })),
  edges: nodes.map((entry, index) => ({
    source: entry.node.node_id,
    target: nodes[(index + 1) % nodes.length].node.node_id,
    placements: [{ kind: "leaf_cycle" }],
    observed_status: "connected",
    last_observed_at: "2026-08-04T07:00:00Z",
  })),
};

const overview = {
  cluster_id: "cloudscape-e2e",
  nodes,
  paths,
  cluster_policy: policy,
  service_directory: { instances: [] },
  metrics: {
    node_count: 5,
    healthy_node_count: 5,
    path_count: paths.length,
    stale_path_count: 0,
    active_control_plane_count: 3,
    active_signal_count: 3,
    active_stun_count: 3,
    active_relay_count: 3,
    active_web_ui_count: 3,
    ha_ready: true,
  },
};

async function installMockBackend(page) {
  const localOverview = JSON.parse(JSON.stringify(overview));
  const localTopology = JSON.parse(JSON.stringify(topology));
  await page.addInitScript(() => {
    sessionStorage.setItem("heteronetwork_operator_token", "e2e-operator-token");
  });
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const assets = {
      "/ui/": ["index.html", "text/html; charset=utf-8"],
      "/ui/auth/wait": ["auth-wait.html", "text/html; charset=utf-8"],
      "/ui/app.js": ["app.js", "text/javascript; charset=utf-8"],
      "/ui/styles.css": ["styles.css", "text/css; charset=utf-8"],
      "/ui/theme.js": ["theme.js", "text/javascript; charset=utf-8"],
      "/ui/vendor/mermaid.min.js": [
        "vendor/mermaid.min.js",
        "text/javascript; charset=utf-8",
      ],
      "/ui/fonts/noto-sans-jp-ui.ttf": ["noto-sans-jp-ui.ttf", "font/ttf"],
    };
    if (assets[url.pathname]) {
      const [asset, contentType] = assets[url.pathname];
      await route.fulfill({ path: path.join(webuiDir, asset), contentType });
      return;
    }
    const displayNameMatch = url.pathname.match(
      /^\/v1\/admin\/nodes\/([^/]+)\/display-name$/,
    );
    if (displayNameMatch && route.request().method() === "PUT") {
      const nodeId = decodeURIComponent(displayNameMatch[1]);
      const request = route.request().postDataJSON();
      const entry = localOverview.nodes.find((candidate) => candidate.node.node_id === nodeId);
      if (!entry) {
        await route.fulfill({ status: 404, json: { error: "node not found" } });
        return;
      }
      entry.node.display_name = request.display_name || null;
      const topologyNode = localTopology.nodes.find((candidate) => candidate.node_id === nodeId);
      if (topologyNode) topologyNode.display_name = request.display_name || null;
      await route.fulfill({ json: entry.node });
      return;
    }
    const responses = {
      "/ui/config": {
        auth_enabled: false,
        operator_token_enabled: true,
        local_agent: false,
      },
      "/v1/admin/overview": localOverview,
      "/v1/admin/keycloak-placement": {
        desired_replicas: 5,
        replicas: nodes.slice(0, 5).map((entry) => ({
          node_id: entry.node.node_id,
          ready: true,
        })),
      },
      "/v1/admin/topology": localTopology,
      "/v1/admin/policy": { cluster_policy: policy },
    };
    if (responses[url.pathname]) {
      await route.fulfill({ json: responses[url.pathname] });
      return;
    }
    await route.fulfill({ status: 404, body: "not found" });
  });
}

async function installDelayedLoginBackend(page) {
  await page.context().route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const assets = {
      "/ui/": ["index.html", "text/html; charset=utf-8"],
      "/ui/auth/wait": ["auth-wait.html", "text/html; charset=utf-8"],
      "/ui/app.js": ["app.js", "text/javascript; charset=utf-8"],
      "/ui/styles.css": ["styles.css", "text/css; charset=utf-8"],
      "/ui/theme.js": ["theme.js", "text/javascript; charset=utf-8"],
      "/ui/vendor/mermaid.min.js": [
        "vendor/mermaid.min.js",
        "text/javascript; charset=utf-8",
      ],
      "/ui/fonts/noto-sans-jp-ui.ttf": ["noto-sans-jp-ui.ttf", "font/ttf"],
    };
    if (assets[url.pathname]) {
      const [asset, contentType] = assets[url.pathname];
      await route.fulfill({ path: path.join(webuiDir, asset), contentType });
      return;
    }
    if (url.pathname === "/ui/config") {
      await route.fulfill({
        json: {
          auth_enabled: true,
          operator_token_enabled: true,
          provider: "keycloak",
          device_login_endpoint: "/v1/web-ui/auth/device",
          device_login_poll_endpoint: "/v1/web-ui/auth/device/poll",
        },
      });
      return;
    }
    if (url.pathname === "/v1/web-ui/auth/device") {
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      await route.fulfill({ status: 503, json: { error: "test completed" } });
      return;
    }
    await route.fulfill({ status: 404, body: "not found" });
  });
}

test("device login shows a local waiting page before Keycloak responds", async ({ page }) => {
  await installDelayedLoginBackend(page);
  await page.goto("/ui/");

  await expect(page.locator('input[type="password"]')).toHaveCount(0);
  await expect(page.getByText("オペレータートークン")).toHaveCount(0);
  const popupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Keycloakでログイン" }).click();
  const popup = await popupPromise;

  await expect(popup).toHaveURL(/\/ui\/auth\/wait$/);
  await expect(popup.getByRole("heading", { name: "Keycloakに接続しています" })).toBeVisible();
  await popup.close();
});

test("Cloudscape console renders overview and hierarchical topology", async ({ page }) => {
  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  await installMockBackend(page);
  await page.goto("/ui/");

  await expect(page.getByRole("heading", { name: "ネットワーク概要" })).toBeVisible();
  await expect(page.getByText("5台が正常")).toBeVisible();
  await expect(page.getByRole("link", { name: "Argo CD" })).toHaveAttribute(
    "href",
    "http://argocd.heteronetwork.internal:8088",
  );
  await expect(page.getByRole("link", { name: "Grafana" })).toHaveAttribute(
    "href",
    "http://grafana.heteronetwork.internal:13000",
  );
  await expect(page.getByRole("link", { name: "Prometheus" })).toHaveAttribute(
    "href",
    "http://prometheus.heteronetwork.internal:9090",
  );
  await expect(page.getByRole("link", { name: "HeteroCloud 所有者" })).toHaveAttribute(
    "href",
    "http://owner.heteronetwork.internal:21443",
  );
  await expect(page.getByRole("table").last().getByRole("row")).toHaveCount(6);

  await page.getByText("ノード", { exact: true }).first().click();
  await expect(page.getByRole("heading", { name: "ノード", exact: true })).toBeVisible();
  await expect(page.getByText("uc-k8sp1", { exact: true })).toBeVisible();
  await expect(page.getByText("163.220.236.51", { exact: true })).toBeVisible();

  await page.getByText("オーバーレイトポロジー", { exact: true }).first().click();
  await expect(page.getByRole("heading", { name: "オーバーレイトポロジー" })).toBeVisible();
  await expect(page.locator(".topology-diagram svg")).toHaveCount(1);
  await expect(page.locator(".topology-diagram svg")).toContainText("uc-k8sp1");
  expect(pageErrors).toEqual([]);
});

test("Cloudscape console remains operable on a mobile viewport", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await installMockBackend(page);
  await page.goto("/ui/#/topology");

  await expect(page.getByRole("heading", { name: "オーバーレイトポロジー" })).toBeVisible();
  await expect(page.locator(".topology-diagram svg")).toHaveCount(1);
  const content = page.locator("main").first();
  await expect(content).toBeVisible();
  const bounds = await content.boundingBox();
  expect(bounds?.x ?? -1).toBeGreaterThanOrEqual(0);
  expect((bounds?.x ?? 0) + (bounds?.width ?? 0)).toBeLessThanOrEqual(390);
});

test("node display names can be changed without replacing the OS hostname", async ({ page }) => {
  await installMockBackend(page);
  await page.goto("/ui/#/nodes");

  await page.getByRole("button", { name: "uc-k8sp1" }).click();
  const dialog = page.getByRole("dialog", { name: "ノード詳細" });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "ノード名を変更" }).click();
  await dialog.getByRole("textbox", { name: "ノード名" }).fill("uc-k8sv1");
  await dialog.getByRole("button", { name: "保存" }).click();

  await expect(dialog.getByText("uc-k8sv1", { exact: true })).toBeVisible();
  await expect(dialog.getByText("uc-k8sp1", { exact: true })).toBeVisible();
});
