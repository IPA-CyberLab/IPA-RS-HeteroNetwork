import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Select from "@cloudscape-design/components/select";
import { useMemo, useState } from "react";
import { ResourceTable, Status } from "../components.jsx";
import { age, pathLabels, pathState, shortId } from "../utils.js";

const stateOptions = [
  { value: "all", label: "すべての状態" },
  { value: "direct", label: "直接接続" },
  { value: "relay", label: "リレー" },
  { value: "unreachable", label: "到達不可" },
];

export function PathsPage({ overview, onPin, pinningKey }) {
  const [selectedState, setSelectedState] = useState(stateOptions[0]);
  const paths = useMemo(
    () =>
      (overview.paths || []).filter((path) => {
        const state = pathState(path.selected_state);
        if (selectedState.value === "all") return true;
        if (selectedState.value === "direct") return state.startsWith("direct_");
        return state === selectedState.value;
      }),
    [overview.paths, selectedState],
  );

  const columns = [
    {
      id: "local",
      header: "ローカルノード",
      cell: (path) => <Box variant="code">{shortId(path.key?.local)}</Box>,
      sortingComparator: (a, b) =>
        String(a.key?.local).localeCompare(String(b.key?.local)),
    },
    {
      id: "remote",
      header: "リモートノード",
      cell: (path) => <Box variant="code">{shortId(path.key?.remote)}</Box>,
      sortingComparator: (a, b) =>
        String(a.key?.remote).localeCompare(String(b.key?.remote)),
    },
    {
      id: "state",
      header: "状態",
      cell: (path) => {
        const state = pathState(path.selected_state);
        return <Status value={state}>{pathLabels[state] || state}</Status>;
      },
    },
    {
      id: "endpoint",
      header: "エンドポイント",
      cell: (path) => (
        <Box variant="code">{path.selected_candidate?.addr || "-"}</Box>
      ),
    },
    {
      id: "relay",
      header: "リレー",
      cell: (path) => (
        <Box variant="code">
          {path.relay_node ? shortId(path.relay_node) : "-"}
        </Box>
      ),
    },
    {
      id: "score",
      header: "スコア",
      cell: (path) => path.score?.value ?? "-",
      sortingComparator: (a, b) => (a.score?.value || 0) - (b.score?.value || 0),
    },
    {
      id: "updated",
      header: "更新日時",
      cell: (path) => age(path.updated_at),
    },
    {
      id: "control",
      header: "操作",
      cell: (path) => {
        const key = `${path.key?.local}/${path.key?.remote}`;
        return (
          <Button
            iconName={path.pinned ? "unlocked" : "lock-private"}
            loading={pinningKey === key}
            onClick={() => onPin(path)}
          >
            {path.pinned ? "固定解除" : "固定"}
          </Button>
        );
      },
    },
  ];

  return (
    <ResourceTable
      header="接続"
      description="選択中エンドポイント、リレー、スコア、固定状態"
      actions={
        <Select
          selectedOption={selectedState}
          options={stateOptions}
          onChange={({ detail }) => setSelectedState(detail.selectedOption)}
          ariaLabel="接続状態で絞り込む"
        />
      }
      items={paths}
      columns={columns}
      trackBy={(path) => `${path.key?.local}/${path.key?.remote}`}
      searchPlaceholder="ノードまたはエンドポイントを検索"
      searchText={(path) =>
        [
          path.key?.local,
          path.key?.remote,
          path.selected_candidate?.addr,
          path.relay_node,
          pathState(path.selected_state),
        ].join(" ")
      }
      emptyTitle="接続がありません"
      emptyDescription="ノードが通信すると選択された経路が表示されます。"
    />
  );
}
