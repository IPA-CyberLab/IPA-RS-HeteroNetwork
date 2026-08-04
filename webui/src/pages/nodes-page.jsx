import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import Modal from "@cloudscape-design/components/modal";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import { useEffect, useMemo, useState } from "react";
import { ResourceTable, Status } from "../components.jsx";
import {
  age,
  connectivity,
  formatDateTime,
  pretty,
  shortId,
} from "../utils.js";

const serviceKinds = [
  ["control_plane", "Control Plane"],
  ["signal", "Signal"],
  ["stun", "STUN"],
  ["relay", "TURN"],
  ["keycloak", "Keycloak"],
  ["web_ui", "Web UI"],
];

function serviceLeases(overview) {
  const result = new Map(
    (overview.nodes || []).map((entry) => [entry.node?.node_id, []]),
  );
  for (const instance of overview.service_directory?.instances || []) {
    if (result.has(instance.owner_node_id)) {
      result.get(instance.owner_node_id).push(instance);
    }
  }
  return result;
}

function serviceStatus(overview, leases, nodeId, kind) {
  if (kind === "keycloak") {
    const replica = (overview.keycloak_placement?.replicas || []).find(
      (entry) => entry.node_id === nodeId,
    );
    return replica
      ? { value: replica.ready ? "healthy" : "warming", label: replica.ready ? "稼働中" : "起動中" }
      : { value: "not_running", label: "未割当" };
  }
  const endpoints = (leases.get(nodeId) || []).flatMap((instance) =>
    (instance.endpoints || []).filter((endpoint) => endpoint.kind === kind),
  );
  return endpoints.length
    ? { value: "healthy", label: "稼働中", endpoints }
    : { value: "not_running", label: "未割当", endpoints: [] };
}

export function NodesPage({ overview, onOpenNode }) {
  const leases = useMemo(() => serviceLeases(overview), [overview]);
  const columns = useMemo(
    () => [
      {
        id: "node",
        header: "ノード",
        cell: (entry) => (
          <Button variant="inline-link" onClick={() => onOpenNode(entry)}>
            {shortId(entry.node?.node_id)}
          </Button>
        ),
        sortingComparator: (a, b) =>
          String(a.node?.node_id).localeCompare(String(b.node?.node_id)),
      },
      {
        id: "vpn",
        header: "VPNアドレス",
        cell: (entry) => <Box variant="code">{entry.node?.vpn_ip || "-"}</Box>,
        sortingComparator: (a, b) =>
          String(a.node?.vpn_ip).localeCompare(String(b.node?.vpn_ip)),
      },
      {
        id: "health",
        header: "エージェント",
        cell: (entry) => (
          <Status value={entry.health?.state || "unknown"}>
            {entry.health?.state === "healthy" ? "正常" : pretty(entry.health?.state)}
          </Status>
        ),
      },
      {
        id: "role",
        header: "ロール",
        cell: (entry) => <Badge>{pretty(entry.node?.role)}</Badge>,
      },
      {
        id: "connectivity",
        header: "接続性",
        cell: (entry) => {
          const info = connectivity(entry);
          return <Status value={info.state}>{info.label}</Status>;
        },
      },
      {
        id: "tags",
        header: "タグ",
        cell: (entry) => (
          <SpaceBetween direction="horizontal" size="xxs">
            {(entry.node?.tags || []).length
              ? entry.node.tags.map((tag) => <Badge key={tag}>{tag}</Badge>)
              : "-"}
          </SpaceBetween>
        ),
      },
      ...serviceKinds.map(([kind, label]) => ({
        id: kind,
        header: label,
        cell: (entry) => {
          const status = serviceStatus(
            overview,
            leases,
            entry.node?.node_id,
            kind,
          );
          return <Status value={status.value}>{status.label}</Status>;
        },
      })),
      {
        id: "seen",
        header: "最終確認",
        cell: (entry) => age(entry.health?.last_seen_at || entry.node?.registered_at),
        sortingComparator: (a, b) =>
          new Date(a.health?.last_seen_at || 0).getTime() -
          new Date(b.health?.last_seen_at || 0).getTime(),
      },
    ],
    [leases, onOpenNode, overview],
  );

  return (
    <ResourceTable
      header="ノード"
      description="HeteroNetworkに参加している実マシンと、その上で稼働するサービス"
      items={overview.nodes || []}
      columns={columns}
      trackBy={(entry) => entry.node?.node_id}
      searchPlaceholder="ノード、VPNアドレス、タグを検索"
      searchText={(entry) =>
        [
          entry.node?.node_id,
          entry.node?.vpn_ip,
          entry.node?.role,
          ...(entry.node?.tags || []),
          entry.health?.state,
        ].join(" ")
      }
      emptyTitle="登録済みノードがありません"
      emptyDescription="ノードを追加するとここに表示されます。"
      onRowClick={onOpenNode}
    />
  );
}

export function NodeDetailModal({ entry, visible, onDismiss, onRemove, loading }) {
  const [confirming, setConfirming] = useState(false);
  useEffect(() => setConfirming(false), [entry, visible]);
  const node = entry?.node || {};
  const health = entry?.health || {};
  const info = connectivity(entry);
  const routes = node.routes || [];

  return (
    <Modal
      visible={visible}
      onDismiss={onDismiss}
      size="large"
      header="ノード詳細"
      footer={
        <Box float="right">
          <SpaceBetween direction="horizontal" size="xs">
            <Button onClick={onDismiss}>閉じる</Button>
            {confirming ? (
              <Button
                variant="primary"
                loading={loading}
                onClick={() => onRemove(node.node_id)}
              >
                削除を確定
              </Button>
            ) : (
              <Button onClick={() => setConfirming(true)}>ノードを削除</Button>
            )}
          </SpaceBetween>
        </Box>
      }
    >
      <SpaceBetween size="l">
        {confirming ? (
          <Box color="text-status-error">
            このノードをクラスターから削除します。再参加には登録操作が必要です。
          </Box>
        ) : null}
        <KeyValuePairs
          columns={3}
          items={[
            { label: "ノードID", value: <Box variant="code">{node.node_id || "-"}</Box> },
            { label: "VPNアドレス", value: <Box variant="code">{node.vpn_ip || "-"}</Box> },
            { label: "ロール", value: pretty(node.role) },
            {
              label: "状態",
              value: <Status value={health.state}>{pretty(health.state)}</Status>,
            },
            {
              label: "接続性",
              value: <Status value={info.state}>{info.label}</Status>,
            },
            { label: "登録日時", value: formatDateTime(node.registered_at) },
            { label: "最終確認", value: formatDateTime(health.last_seen_at) },
            {
              label: "タグ",
              value: (node.tags || []).join(", ") || "-",
            },
          ]}
        />
        <Table
          variant="embedded"
          header={<Box variant="h3">広報ルート</Box>}
          items={routes}
          trackBy="id"
          columnDefinitions={[
            { id: "id", header: "ルートID", cell: (route) => route.id || "-" },
            { id: "cidr", header: "ネットワーク", cell: (route) => route.cidr || "-" },
          ]}
          empty={<Box textAlign="center">広報ルートはありません</Box>}
        />
      </SpaceBetween>
    </Modal>
  );
}
