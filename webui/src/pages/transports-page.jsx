import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Select from "@cloudscape-design/components/select";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { ErrorAlert, ResourceTable } from "../components.jsx";
import { age, nodeDisplayName } from "../utils.js";

const reasons = {
  udp_probe_timeout: "UDP応答なし", remote_http_tunnel: "接続元がHTTPトンネルを選択",
  tcp_unavailable: "TCP接続失敗", tcp_tunnel_unavailable:"TCPトンネル切断",
  dns_unavailable: "名前解決失敗", dns_nonpublic: "公開アドレスなし",
  https_unavailable: "HTTPS接続失敗", http_unavailable: "HTTP接続失敗",
  http_tunnel_unavailable: "HTTPトンネル切断", authentication_failed: "認証失敗",
  tunnel_idle_or_closed: "通信停止・セッション終了", tunnel_stopped: "接続終了",
  send_queue_full: "送信キュー上限", backend_socket_failed: "内部転送失敗",
};
const bytes = (value) => value == null ? "未取得" : new Intl.NumberFormat("ja-JP", { maximumFractionDigits: 2 }).format(value / 1048576) + " MiB";
const phaseNames = { connected: "接続中", probing: "UDP確認中", reconnecting: "再接続中", failed: "接続失敗" };

export function TransportsPage({ overview }) {
  const [source, setSource] = useState({ value: "", label: "すべてのノード" });
  const [cursors, setCursors] = useState([""]);
  const cursor = cursors.at(-1);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const names = useMemo(() => new Map((overview.nodes || []).map(({ node }) => [node.node_id, nodeDisplayName(node)])), [overview.nodes]);
  const name = (id) => names.get(id) || id;
  const options = [{ value: "", label: "すべてのノード" }, ...[...names].map(([value, label]) => ({ value, label }))];
  const load = useCallback(async (signal) => {
    setBusy(true);
    try {
      const query = new URLSearchParams({ limit: "10" });
      if (source.value) query.set("node_id", source.value);
      if (cursor) query.set("after", cursor);
      const next = await api.request(`/v1/admin/transports?${query}`, { signal });
      if (!signal?.aborted) { setData(next); setError(null); }
    } catch (failure) { if (!signal?.aborted) setError(failure); }
    finally { if (!signal?.aborted) setBusy(false); }
  }, [source.value, cursor]);
  useEffect(() => {
    const controller = new AbortController();
    let timer;
    const refresh = async () => {
      await load(controller.signal);
      if (!controller.signal.aborted) timer = setTimeout(refresh, 5000);
    };
    setData(null);
    refresh();
    return () => { controller.abort(); clearTimeout(timer); };
  }, [load]);
  const rows = (data?.items || []).flatMap((node) => {
    const connections = node.snapshot?.connections || [];
    return (connections.length ? connections : [{ peer: "", phase: "unreported" }]).map((connection, index) => ({
      ...connection, source: node.node_id, observed_at: node.observed_at, id: `${node.node_id}/${index}`,
    }));
  });
  for (const node of data?.unreported || []) rows.push({ source: node, peer: "", phase: "unreported", id: node });
  const columns = [
    { id: "source", header: "報告ノード", cell: (r) => name(r.source) },
    { id: "peer", header: "接続先 / 方向", cell: (r) => r.peer ? `${name(r.peer)} / ${r.direction === "incoming" ? "受信" : "送信"}` : "接続の報告なし" },
    { id: "mode", header: "通信方式", cell: (r) => ({ udp: "UDP", tcp:"TCP", https: "HTTPS / TCP", http: "HTTP / TCP" })[r.transport] || "未報告" },
    { id: "phase", header: "状態", cell: (r) => {
      const stale = !r.updated_at || Date.now() - Date.parse(r.updated_at) > 90000 || Date.now() - Date.parse(r.observed_at) > 90000;
      return <StatusIndicator type={stale ? "warning" : r.phase === "connected" ? "success" : r.phase === "failed" ? "error" : "in-progress"}>{stale ? "未報告・更新停止" : phaseNames[r.phase] || r.phase}</StatusIndicator>;
    } },
    { id: "connection", header: "接続ID", cell: (r) => r.connection_id || "—" },
    { id: "endpoint", header: "接続先アドレス", cell: (r) => <Box variant="code">{r.endpoint || "未取得"}</Box> },
    { id: "resolved", header: "接続先IP", cell: (r) => <Box variant="code">{r.resolved_endpoint || "未取得"}</Box> },
    { id: "traffic", header: "送信 / 受信", cell: (r) => `${bytes(r.tx_bytes)} / ${bytes(r.rx_bytes)}` },
    { id: "switches", header: "切替 / 再接続", cell: (r) => `${r.switches ?? "未取得"} / ${r.reconnects ?? "未取得"}` },
    { id: "reason", header: "切替理由・最終エラー", cell: (r) => [r.fallback_reason, r.last_error].filter(Boolean).map((reason) => reasons[reason] || reason).join(" / ") || "—" },
    { id: "failures", header: "失敗履歴", cell: (r) => Object.entries(r.failures || {}).map(([reason, count]) => `${reasons[reason] || reason}: ${count}`).join(" / ") || "—" },
    { id: "updated", header: "通信更新 / 報告受信", cell: (r) => `${age(r.updated_at)} / ${age(r.observed_at)}` },
  ];
  return <SpaceBetween size="l">
    {error ? <ErrorAlert error={error} onRetry={() => load()} /> : null}
    <ResourceTable header="通信方式" description="UDPからTCP・HTTPS・HTTPへの切り替えを5秒ごとに確認します。通信量はこのプロセスの起動以降の値で、報告停止を通信量0として扱いません。"
      items={rows} columns={columns} trackBy="id" pageSize={20}
      actions={<SpaceBetween size="s" direction="horizontal"><Select selectedOption={source} options={options} ariaLabel="報告ノード" onChange={({ detail }) => { setSource(detail.selectedOption); setCursors([""]); }} /><Button loading={busy} onClick={() => load()}>更新</Button></SpaceBetween>}
      emptyTitle={busy ? "通信状態を取得しています" : "通信状態の報告がありません"} />
    <SpaceBetween size="s" direction="horizontal"><Button disabled={cursors.length === 1 || busy} onClick={() => setCursors((current) => current.slice(0, -1))}>前のノード</Button><Button disabled={!data?.next_cursor || busy} onClick={() => setCursors((current) => [...current, data.next_cursor])}>次のノード</Button></SpaceBetween>
  </SpaceBetween>;
}
