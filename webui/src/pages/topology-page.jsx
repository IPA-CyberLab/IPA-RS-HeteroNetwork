import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import ColumnLayout from "@cloudscape-design/components/column-layout";
import Container from "@cloudscape-design/components/container";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import KeyValuePairs from "@cloudscape-design/components/key-value-pairs";
import Select from "@cloudscape-design/components/select";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Tabs from "@cloudscape-design/components/tabs";
import { useEffect, useMemo, useState } from "react";
import {
  ErrorAlert,
  Loading,
  MermaidDiagram,
  ResourceTable,
  Status,
} from "../components.jsx";
import {
  copyText,
  formatDateTime,
  nodeDisplayName,
  pretty,
  shortId,
  topologyMermaid,
} from "../utils.js";

const degreeOptions = [
  { value: "4", label: "4ピア" },
  { value: "6", label: "6ピア" },
];

export function TopologyPage({
  topology,
  policy,
  loading,
  error,
  saving,
  onReload,
  onSaveSettings,
  onNotify,
}) {
  const [fanout, setFanout] = useState("4");
  const [maxDegree, setMaxDegree] = useState(degreeOptions[0]);
  const [shortcutLimit, setShortcutLimit] = useState("0");
  const [validationError, setValidationError] = useState(null);

  useEffect(() => {
    setFanout(String(policy?.overlay_block_size ?? topology?.fanout ?? 4));
    setMaxDegree(
      degreeOptions.find(
        (option) =>
          option.value === String(policy?.overlay_max_degree ?? topology?.max_degree ?? 4),
      ) || degreeOptions[0],
    );
    setShortcutLimit(
      String(
        policy?.overlay_direct_shortcut_limit ??
          topology?.direct_shortcut_limit ??
          0,
      ),
    );
  }, [policy, topology]);

  const mermaid = useMemo(
    () => (topology ? topologyMermaid(topology) : ""),
    [topology],
  );

  if (loading && !topology) return <Loading label="トポロジーを読み込んでいます" />;
  if (error && !topology) return <ErrorAlert error={error} onRetry={onReload} />;
  if (!topology) return null;

  const groups = topology.groups || [];
  const edges = topology.edges || [];
  const nodes = topology.nodes || [];
  const nodesById = new Map(nodes.map((node) => [node.node_id, node]));
  const nodeName = (nodeId) =>
    nodeDisplayName(nodesById.get(nodeId) || { node_id: nodeId });
  const save = async () => {
    const fanoutValue = Number(fanout);
    const shortcutValue = Number(shortcutLimit);
    if (!Number.isInteger(fanoutValue) || fanoutValue < 4 || fanoutValue > 64) {
      setValidationError(new Error("グループファンアウトは4から64の整数で指定してください。"));
      return;
    }
    if (!Number.isInteger(shortcutValue) || shortcutValue < 0 || shortcutValue > 64) {
      setValidationError(new Error("直接ショートカット数は0から64の整数で指定してください。"));
      return;
    }
    setValidationError(null);
    await onSaveSettings({
      overlay_block_size: fanoutValue,
      overlay_max_degree: Number(maxDegree.value),
      overlay_direct_shortcut_limit: shortcutValue,
    });
  };

  const groupColumns = [
    {
      id: "group",
      header: "グループ",
      cell: (group) => <Box variant="code">{shortId(group.group_id)}</Box>,
    },
    { id: "depth", header: "深さ", cell: (group) => group.depth ?? 0 },
    {
      id: "type",
      header: "種類",
      cell: (group) => (
        <Status value={group.leaf ? "active" : "info"}>
          {group.leaf ? "リーフ" : "中間"}
        </Status>
      ),
    },
    {
      id: "nodes",
      header: "ノード数",
      cell: (group) => (group.node_ids || []).length,
    },
    {
      id: "children",
      header: "子グループ",
      cell: (group) => (group.child_group_ids || []).length,
    },
    {
      id: "representatives",
      header: "代表",
      cell: (group) =>
        (group.representatives || [])
          .map((representative) => `${nodeName(representative.node_id)} (${representative.role})`)
          .join(", ") || "-",
    },
  ];
  const edgeColumns = [
    {
      id: "source",
      header: "送信元",
      cell: (edge) => nodeName(edge.source),
    },
    {
      id: "target",
      header: "宛先",
      cell: (edge) => nodeName(edge.target),
    },
    {
      id: "placement",
      header: "配置",
      cell: (edge) =>
        (edge.placements || []).map((placement) => pretty(placement.kind)).join(", ") || "-",
    },
    {
      id: "status",
      header: "観測状態",
      cell: (edge) => (
        <Status value={edge.observed_status || "unknown"}>
          {pretty(edge.observed_status)}
        </Status>
      ),
    },
    {
      id: "observed",
      header: "最終観測",
      cell: (edge) => formatDateTime(edge.last_observed_at),
    },
  ];

  return (
    <SpaceBetween size="l">
      <Header
        variant="h1"
        description="再帰グループ、代表ノード、転送リンクと実際の観測状態"
        actions={
          <Button iconName="refresh" loading={loading} onClick={onReload}>
            更新
          </Button>
        }
      >
        オーバーレイトポロジー
      </Header>
      <Container>
        <ColumnLayout columns={4} variant="text-grid">
          {[
            ["ノード", topology.node_count ?? nodes.length],
            ["グループ", topology.group_count ?? groups.length],
            ["階層数", topology.level_count ?? "-"],
            ["エッジ", topology.edge_count ?? edges.length],
            ["最大次数", topology.max_observed_degree ?? topology.max_degree ?? "-"],
            ["推定直径", topology.diameter_lower_bound ?? "-"],
            ["ファンアウト", topology.fanout ?? "-"],
            ["エポック", topology.topology_epoch ?? "-"],
          ].map(([label, value]) => (
            <div key={label}>
              <Box variant="awsui-key-label">{label}</Box>
              <Box variant="awsui-value-large">{String(value)}</Box>
            </div>
          ))}
        </ColumnLayout>
      </Container>

      <Container
        header={
          <Header
            variant="h2"
            description="ポリシー保存後に全ノードへ反映され、次のエポックで再構成されます。"
            actions={
              <Button variant="primary" loading={saving} onClick={save}>
                設定を保存
              </Button>
            }
          >
            階層設定
          </Header>
        }
      >
        <SpaceBetween size="m">
          {validationError ? <ErrorAlert error={validationError} /> : null}
          <ColumnLayout columns={3}>
            <FormField
              label="グループファンアウト"
              description="各グループに割り当てる子グループまたはノードの上限"
            >
              <Input
                type="number"
                value={fanout}
                onChange={({ detail }) => setFanout(detail.value)}
              />
            </FormField>
            <FormField
              label="最大ピア次数"
              description="各ノードが維持する階層近傍の上限"
            >
              <Select
                selectedOption={maxDegree}
                options={degreeOptions}
                onChange={({ detail }) => setMaxDegree(detail.selectedOption)}
              />
            </FormField>
            <FormField
              label="直接ショートカット数"
              description="階層外に追加する低遅延の直接接続"
            >
              <Input
                type="number"
                value={shortcutLimit}
                onChange={({ detail }) => setShortcutLimit(detail.value)}
              />
            </FormField>
          </ColumnLayout>
        </SpaceBetween>
      </Container>

      <Container
        header={
          <Header
            variant="h2"
            description={topology.algorithm || "階層型P2P"}
            actions={
              <Button
                iconName="copy"
                onClick={async () => {
                  await copyText(mermaid);
                  onNotify("Mermaidソースをコピーしました。", "success");
                }}
              >
                Mermaidをコピー
              </Button>
            }
          >
            グループ階層
          </Header>
        }
      >
        <MermaidDiagram source={mermaid} />
      </Container>

      <Tabs
        tabs={[
          {
            id: "groups",
            label: "グループ",
            content: (
              <ResourceTable
                items={groups}
                columns={groupColumns}
                trackBy="group_id"
                searchPlaceholder="グループまたは代表ノードを検索"
                searchText={(group) =>
                  [
                    group.group_id,
                    ...(group.node_ids || []),
                    ...(group.node_ids || []).map((nodeId) => nodeName(nodeId)),
                    ...(group.representatives || []).map((entry) => entry.node_id),
                    ...(group.representatives || []).map((entry) => nodeName(entry.node_id)),
                  ].join(" ")
                }
                emptyTitle="グループがありません"
              />
            ),
          },
          {
            id: "edges",
            label: "接続",
            content: (
              <ResourceTable
                items={edges}
                columns={edgeColumns}
                trackBy={(edge) => `${edge.source}/${edge.target}`}
                searchPlaceholder="ノードまたは配置を検索"
                searchText={(edge) =>
                  [
                    edge.source,
                    nodeName(edge.source),
                    edge.target,
                    nodeName(edge.target),
                    edge.observed_status,
                    ...(edge.placements || []).map((placement) => placement.kind),
                  ].join(" ")
                }
                emptyTitle="接続がありません"
              />
            ),
          },
          {
            id: "source",
            label: "Mermaidソース",
            content: <Box variant="pre">{mermaid}</Box>,
          },
        ]}
      />
    </SpaceBetween>
  );
}
