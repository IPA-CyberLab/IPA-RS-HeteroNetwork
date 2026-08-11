import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import FormField from "@cloudscape-design/components/form-field";
import Input from "@cloudscape-design/components/input";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import Modal from "@cloudscape-design/components/modal";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Table from "@cloudscape-design/components/table";
import { useEffect, useMemo, useState } from "react";
import { ResourceTable, Status } from "../components.jsx";
import {
  age,
  agentBuild,
  connectivity,
  formatDateTime,
  nodeDisplayName,
  pretty,
  shortId,
} from "../utils.js";

const serviceKinds = [
  ["control_plane", "Control Plane"],
  ["signal", "Signal"],
  ["stun", "STUN"],
  ["relay", "リレー"],
  ["keycloak", "Keycloak"],
  ["web_ui", "Web UI"],
];

function validNodeDisplayName(value) {
  return (
    value.length > 0 &&
    value.length <= 253 &&
    !value.startsWith(".") &&
    !value.endsWith(".") &&
    !value.includes("..") &&
    /^[A-Za-z0-9._-]+$/.test(value)
  );
}

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
          <SpaceBetween size="xxs">
            <Button variant="inline-link" onClick={() => onOpenNode(entry)}>
              {nodeDisplayName(entry)}
            </Button>
            {entry.node?.hostname ? (
              <Box variant="small" color="text-body-secondary">
                {shortId(entry.node?.node_id)}
              </Box>
            ) : null}
          </SpaceBetween>
        ),
        sortingComparator: (a, b) =>
          nodeDisplayName(a).localeCompare(nodeDisplayName(b)),
      },
      {
        id: "vpn",
        header: "VPNアドレス",
        cell: (entry) => <Box variant="code">{entry.node?.vpn_ip || "-"}</Box>,
        sortingComparator: (a, b) =>
          String(a.node?.vpn_ip).localeCompare(String(b.node?.vpn_ip)),
      },
      {
        id: "publicIp",
        header: "グローバルIP",
        cell: (entry) =>
          (entry.public_ips || []).length ? (
            <SpaceBetween size="xxs">
              {entry.public_ips.map((address) => (
                <Box key={address} variant="code">
                  {address}
                </Box>
              ))}
            </SpaceBetween>
          ) : (
            "-"
          ),
        sortingComparator: (a, b) =>
          String(a.public_ips?.[0] || "").localeCompare(String(b.public_ips?.[0] || "")),
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
        id: "agentBuild",
        header: "展開バージョン",
        cell: (entry) => {
          const build = agentBuild(entry);
          return build ? (
            <SpaceBetween size="xxs">
              <Box>{build.version}</Box>
              <Box variant="code">{build.commit}</Box>
            </SpaceBetween>
          ) : (
            "未報告"
          );
        },
        sortingComparator: (a, b) =>
          `${agentBuild(a)?.version || ""}-${agentBuild(a)?.commit || ""}`.localeCompare(
            `${agentBuild(b)?.version || ""}-${agentBuild(b)?.commit || ""}`,
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
      searchPlaceholder="ホスト名、IPアドレス、タグを検索"
      searchText={(entry) =>
        [
          entry.node?.node_id,
          entry.node?.hostname,
          entry.node?.vpn_ip,
          ...(entry.public_ips || []),
          entry.node?.role,
          ...(entry.node?.tags || []),
          entry.health?.state,
          entry.agent_build?.version,
          entry.agent_build?.commit,
        ].join(" ")
      }
      emptyTitle="登録済みノードがありません"
      emptyDescription="ノードを追加するとここに表示されます。"
      onRowClick={onOpenNode}
    />
  );
}

export function NodeDetailModal({
  entry,
  visible,
  onDismiss,
  onRemove,
  onRename,
  loading,
  renaming,
}) {
  const [confirming, setConfirming] = useState(false);
  const [editingName, setEditingName] = useState(false);
  const [displayName, setDisplayName] = useState("");
  useEffect(() => {
    setConfirming(false);
    setEditingName(false);
    setDisplayName(entry?.node?.display_name || entry?.node?.hostname || "");
  }, [entry, visible]);
  const node = entry?.node || {};
  const health = entry?.health || {};
  const info = connectivity(entry);
  const build = agentBuild(entry);
  const routes = node.routes || [];
  const trimmedDisplayName = displayName.trim();
  const displayNameValid = validNodeDisplayName(trimmedDisplayName);

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
        {editingName ? (
          <FormField
            label="ノード名"
            errorText={
              trimmedDisplayName && !displayNameValid
                ? "英数字、ピリオド、ハイフン、アンダースコアで入力してください。"
                : null
            }
          >
            <SpaceBetween size="xs">
              <Input
                value={displayName}
                disabled={renaming}
                invalid={Boolean(trimmedDisplayName && !displayNameValid)}
                nativeInputAttributes={{ maxLength: 253 }}
                onChange={({ detail }) => setDisplayName(detail.value)}
                onKeyDown={({ detail }) => {
                  if (detail.keyCode === 13 && displayNameValid) {
                    onRename(node.node_id, displayName).then((saved) => {
                      if (saved) setEditingName(false);
                    });
                  }
                }}
              />
              <SpaceBetween direction="horizontal" size="xs">
                <Button
                  variant="primary"
                  iconName="check"
                  loading={renaming}
                  disabled={!displayNameValid}
                  onClick={() =>
                    onRename(node.node_id, displayName).then((saved) => {
                      if (saved) setEditingName(false);
                    })
                  }
                >
                  保存
                </Button>
                <Button
                  iconName="close"
                  disabled={renaming}
                  onClick={() => {
                    setDisplayName(node.display_name || node.hostname || "");
                    setEditingName(false);
                  }}
                >
                  キャンセル
                </Button>
                {node.display_name ? (
                  <Button
                    disabled={renaming}
                    onClick={() =>
                      onRename(node.node_id, null).then((saved) => {
                        if (saved) setEditingName(false);
                      })
                    }
                  >
                    OS名を使用
                  </Button>
                ) : null}
              </SpaceBetween>
            </SpaceBetween>
          </FormField>
        ) : null}
        <KeyValuePairs
          columns={3}
          items={[
            {
              label: "ノード名",
              value: (
                <SpaceBetween direction="horizontal" size="xs">
                  <Box>{nodeDisplayName(entry)}</Box>
                  <Button
                    variant="icon"
                    iconName="edit"
                    ariaLabel="ノード名を変更"
                    disabled={renaming}
                    onClick={() => setEditingName(true)}
                  />
                </SpaceBetween>
              ),
            },
            { label: "OSホスト名", value: node.hostname || "-" },
            { label: "ノードID", value: <Box variant="code">{node.node_id || "-"}</Box> },
            { label: "VPNアドレス", value: <Box variant="code">{node.vpn_ip || "-"}</Box> },
            {
              label: "グローバルIP",
              value: (entry?.public_ips || []).join(", ") || "-",
            },
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
            { label: "エージェントバージョン", value: build?.version || "未報告" },
            {
              label: "エージェントハッシュ",
              value: build ? <Box variant="code">{build.commit}</Box> : "未報告",
            },
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
