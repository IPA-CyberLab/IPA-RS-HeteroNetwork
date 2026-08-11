import BarChart from "@cloudscape-design/components/bar-chart";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Container from "@cloudscape-design/components/container";
import Header from "@cloudscape-design/components/header";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { ResourceTable, Status } from "../components.jsx";
import {
  age,
  agentBuild,
  connectivity,
  nodeDisplayName,
  pathLabels,
  pathState,
} from "../utils.js";

const operationsConsoles = [
  {
    label: "Argo CD",
    href: "http://argocd.heteronetwork.internal:8088",
  },
  {
    label: "Grafana",
    href: "http://grafana.heteronetwork.internal:33000",
  },
  {
    label: "Prometheus",
    href: "http://prometheus.heteronetwork.internal:9090",
  },
];

function Metric({ label, value, detail }) {
  return (
    <div>
      <Box variant="awsui-key-label">{label}</Box>
      <Box variant="awsui-value-large">{value}</Box>
      <Box color="text-body-secondary">{detail}</Box>
    </div>
  );
}

function activeWebUiCount(overview) {
  if (overview.metrics?.active_web_ui_count != null) {
    return overview.metrics.active_web_ui_count;
  }
  return (overview.service_directory?.instances || []).filter((instance) =>
    (instance.endpoints || []).some((endpoint) => endpoint.kind === "web_ui"),
  ).length;
}

export function OverviewPage({ overview, onNavigate, onOpenNode }) {
  const metrics = overview.metrics || {};
  const nodes = overview.nodes || [];
  const paths = overview.paths || [];
  const policy = overview.cluster_policy || {};
  const routeCount = nodes.reduce(
    (total, entry) => total + (entry.node?.routes || []).length,
    0,
  );
  const pathCounts = paths.reduce((counts, path) => {
    const state = pathState(path.selected_state);
    counts[state] = (counts[state] || 0) + 1;
    return counts;
  }, {});
  const keycloakPlacement = overview.keycloak_placement || {};
  const keycloakReplicas = keycloakPlacement.replicas || [];
  const keycloakReady = keycloakReplicas.filter((replica) => replica.ready).length;
  const keycloakDesired = keycloakPlacement.desired_replicas || 3;
  const haReady = Boolean(metrics.ha_ready) && keycloakReady >= keycloakDesired;
  const serviceHealth = [
    ["コントロールプレーン", metrics.active_control_plane_count || 0],
    ["シグナル", metrics.active_signal_count || 0],
    ["STUN", metrics.active_stun_count || 0],
    ["リレー", metrics.active_relay_count || 0],
    ["Web UI", activeWebUiCount(overview)],
  ];
  const recentNodes = nodes
    .slice()
    .sort(
      (left, right) =>
        new Date(right.health?.last_seen_at || 0).getTime() -
        new Date(left.health?.last_seen_at || 0).getTime(),
    )
    .slice(0, 6);

  const nodeColumns = [
    {
      id: "node",
      header: "ノード",
      cell: (entry) => (
        <Button variant="inline-link" onClick={() => onOpenNode(entry)}>
          {nodeDisplayName(entry)}
        </Button>
      ),
      sortingComparator: (a, b) =>
        nodeDisplayName(a).localeCompare(nodeDisplayName(b)),
    },
    {
      id: "vpn",
      header: "VPNアドレス",
      cell: (entry) => entry.node?.vpn_ip || "-",
    },
    {
      id: "health",
      header: "状態",
      cell: (entry) => (
        <Status value={entry.health?.state || "unknown"}>
          {entry.health?.state === "healthy" ? "正常" : "要確認"}
        </Status>
      ),
    },
    {
      id: "agentBuild",
      header: "展開バージョン",
      cell: (entry) => {
        const build = agentBuild(entry);
        return build ? `${build.version} / ${build.commit}` : "未報告";
      },
    },
    {
      id: "connectivity",
      header: "接続性",
      cell: (entry) => {
        const value = connectivity(entry);
        return <Status value={value.state}>{value.label}</Status>;
      },
    },
    {
      id: "seen",
      header: "最終確認",
      cell: (entry) => age(entry.health?.last_seen_at || entry.node?.registered_at),
    },
  ];

  return (
    <SpaceBetween size="l">
      <Container header={<Header variant="h2">運用ツール</Header>}>
        <ColumnLayout columns={3} variant="text-grid">
          {operationsConsoles.map((console) => (
            <Button
              key={console.label}
              href={console.href}
              target="_blank"
              iconName="external"
              fullWidth
            >
              {console.label}
            </Button>
          ))}
        </ColumnLayout>
      </Container>

      <Container header={<Header variant="h2">ネットワーク概要</Header>}>
        <ColumnLayout columns={4} variant="text-grid">
          <Metric
            label="ノード"
            value={metrics.node_count || 0}
            detail={`${metrics.healthy_node_count || 0}台が正常`}
          />
          <Metric
            label="接続"
            value={metrics.path_count || 0}
            detail={`${metrics.stale_path_count || 0}件が期限切れ`}
          />
          <Metric label="広報ルート" value={routeCount} detail="登録ノード全体" />
          <Metric
            label="アクセスルール"
            value={(policy.acl_rules || []).length}
            detail={policy.allow_relay_fallback ? "リレー許可" : "リレー無効"}
          />
        </ColumnLayout>
      </Container>

      <ColumnLayout columns={2} variant="text-grid">
        <Container
          header={
            <Header variant="h2" description="選択されている経路の分布">
              接続状態
            </Header>
          }
        >
          <BarChart
            statusType="finished"
            height={250}
            xScaleType="categorical"
            series={[
              {
                title: "接続数",
                type: "bar",
                data: Object.keys(pathLabels).map((state) => ({
                  x: pathLabels[state],
                  y: pathCounts[state] || 0,
                })),
              },
            ]}
            xTitle="経路"
            yTitle="接続数"
            hideFilter
            hideLegend
            empty={<Box textAlign="center">接続データがありません</Box>}
            i18nStrings={{
              filterLabel: "表示する系列",
              filterPlaceholder: "系列を選択",
              xTickFormatter: (value) => String(value),
              yTickFormatter: (value) => String(value),
            }}
          />
        </Container>

        <Container
          header={
            <Header
              variant="h2"
              description="到達可能ノードで自動選出されたサービス"
              actions={
                <Status value={haReady ? "healthy" : "degraded"}>
                  {haReady ? "HA準備完了" : "HA縮退"}
                </Status>
              }
            >
              サービス可用性
            </Header>
          }
        >
          <KeyValuePairs
            columns={2}
            items={[
              ...serviceHealth.map(([label, count]) => ({
                label,
                value: (
                  <Status value={count >= 2 ? "healthy" : count ? "degraded" : "unreachable"}>
                    {count}台稼働
                  </Status>
                ),
              })),
              {
                label: "Keycloak",
                value: (
                  <Status value={keycloakReady >= keycloakDesired ? "healthy" : "degraded"}>
                    {keycloakReady} / {keycloakDesired}準備完了
                  </Status>
                ),
              },
            ]}
          />
        </Container>
      </ColumnLayout>

      <ResourceTable
        header="最近確認したノード"
        description="コントロールプレーンによる最新の観測"
        actions={
          <Button onClick={() => onNavigate("nodes")}>
            すべて表示
          </Button>
        }
        items={recentNodes}
        columns={nodeColumns}
        trackBy={(entry) => entry.node?.node_id}
        searchPlaceholder="ノードを検索"
        searchText={(entry) =>
          [entry.node?.node_id, entry.node?.vpn_ip, entry.node?.role].join(" ")
        }
        emptyTitle="登録済みノードがありません"
        emptyDescription="ノードを追加するとここに表示されます。"
        onRowClick={onOpenNode}
      />
    </SpaceBetween>
  );
}
