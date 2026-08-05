import Badge from "@cloudscape-design/components/badge";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import SpaceBetween from "@cloudscape-design/components/space-between";
import { ResourceTable, Status } from "../components.jsx";
import { nodeDisplayName, pretty } from "../utils.js";

export function RoutesPage({ overview, onOpenNode }) {
  const routes = (overview.nodes || []).flatMap((entry) =>
    (entry.node?.routes || []).map((route) => ({ entry, route })),
  );
  const columns = [
    {
      id: "id",
      header: "ルートID",
      cell: (item) => <Box variant="code">{item.route.id || "-"}</Box>,
      sortingComparator: (a, b) =>
        String(a.route.id).localeCompare(String(b.route.id)),
    },
    {
      id: "network",
      header: "ネットワーク",
      cell: (item) => <Box variant="code">{item.route.cidr || "-"}</Box>,
      sortingComparator: (a, b) =>
        String(a.route.cidr).localeCompare(String(b.route.cidr)),
    },
    {
      id: "owner",
      header: "広報元",
      cell: (item) => (
        <Button variant="inline-link" onClick={() => onOpenNode(item.entry)}>
          {nodeDisplayName(item.entry)}
        </Button>
      ),
    },
    {
      id: "role",
      header: "ロール",
      cell: (item) => <Badge>{pretty(item.entry.node?.role)}</Badge>,
    },
    {
      id: "tags",
      header: "タグ",
      cell: (item) => (
        <SpaceBetween direction="horizontal" size="xxs">
          {(item.entry.node?.tags || []).length
            ? item.entry.node.tags.map((tag) => <Badge key={tag}>{tag}</Badge>)
            : "-"}
        </SpaceBetween>
      ),
    },
    {
      id: "status",
      header: "状態",
      cell: () => <Status value="active">広報中</Status>,
    },
  ];

  return (
    <ResourceTable
      header="ネットワークルート"
      description="登録ノードがHeteroNetworkへ広報しているネットワーク"
      items={routes}
      columns={columns}
      trackBy={(item) => `${item.entry.node?.node_id}/${item.route.id}`}
      searchPlaceholder="ルートまたは広報元を検索"
      searchText={(item) =>
        [
          item.route.id,
          item.route.cidr,
          item.entry.node?.node_id,
          item.entry.node?.hostname,
          item.entry.node?.role,
          ...(item.entry.node?.tags || []),
        ].join(" ")
      }
      emptyTitle="広報ルートがありません"
      emptyDescription="登録ノードからルートを広報するとここに表示されます。"
    />
  );
}
