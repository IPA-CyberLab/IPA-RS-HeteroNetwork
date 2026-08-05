export function shortId(value) {
  const text = String(value || "");
  return text.length <= 20 ? text : `${text.slice(0, 9)}…${text.slice(-5)}`;
}

export function formatDateTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat("ja-JP", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

export function age(value) {
  if (!value) return "-";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分前`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}時間前`;
  return `${Math.floor(seconds / 86400)}日前`;
}

export function pretty(value) {
  return String(value || "不明")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function statusType(value) {
  const status = String(value || "").toLowerCase();
  if (["healthy", "active", "ready", "connected", "direct_public", "direct_ipv6", "direct_nat_traversal"].includes(status)) return "success";
  if (["degraded", "relay", "warming", "stale", "provisioning"].includes(status)) return "warning";
  if (["unreachable", "failed", "error", "unhealthy", "denied"].includes(status)) return "error";
  if (["pending", "checking"].includes(status)) return "pending";
  if (["disabled", "not_running", "not assigned"].includes(status)) return "stopped";
  return "info";
}

export function pathState(value) {
  const state = String(value || "unknown")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/[\s-]+/g, "_")
    .toLowerCase();
  if (state.includes("direct_public")) return "direct_public";
  if (state.includes("direct_ipv6")) return "direct_ipv6";
  if (state.includes("direct_nat")) return "direct_nat_traversal";
  if (state.includes("relay")) return "relay";
  if (state.includes("unreachable")) return "unreachable";
  return state;
}

export const pathLabels = {
  direct_public: "公開直接接続",
  direct_ipv6: "IPv6直接接続",
  direct_nat_traversal: "NATトラバーサル",
  relay: "リレー",
  unreachable: "到達不可",
  unknown: "不明",
};

export function connectivity(entry) {
  const discovery =
    entry?.nat_classification || entry?.nat_discovery || entry?.connectivity || {};
  const profile = String(
    discovery.connectivity_state ||
      discovery.connectivity ||
      discovery.profile ||
      entry?.connectivity_state ||
      "unknown",
  ).toLowerCase();
  if (profile.includes("public")) return { state: "healthy", label: "公開" };
  if (profile.includes("relay")) return { state: "degraded", label: "リレーのみ" };
  if (profile.includes("nat") || profile.includes("private")) return { state: "info", label: "プライベート" };
  const endpoint = entry?.observed_endpoint || discovery.observed_endpoint;
  if (endpoint) return { state: "info", label: "プライベート" };
  return { state: "pending", label: "未検出" };
}

export function csvValues(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export async function copyText(value) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(value);
  }
  const input = document.createElement("textarea");
  input.value = value;
  input.readOnly = true;
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  const copied = document.execCommand("copy");
  input.remove();
  if (!copied) throw new Error("コピーに失敗しました");
}

function mermaidText(value) {
  return String(value ?? "")
    .replaceAll("\\", "\\\\")
    .replaceAll('"', "'")
    .replace(/[\r\n]+/g, " ");
}

function mermaidId(prefix, value) {
  let hash = 2166136261;
  const input = String(value || "");
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `${prefix}_${(hash >>> 0).toString(36)}`;
}

export function topologyMermaid(topology) {
  const groups = Array.isArray(topology?.groups) ? topology.groups : [];
  const nodes = Array.isArray(topology?.nodes) ? topology.nodes : [];
  const edges = Array.isArray(topology?.edges) ? topology.edges : [];
  const lines = ["flowchart TB"];

  for (const group of groups) {
    const groupId = mermaidId("group", group.group_id);
    const role = group.leaf ? "リーフ" : `深さ ${group.depth ?? 0}`;
    lines.push(`${groupId}["${mermaidText(shortId(group.group_id))}<br/>${role}"]`);
    for (const childId of group.child_group_ids || []) {
      lines.push(`${groupId} --> ${mermaidId("group", childId)}`);
    }
  }

  for (const node of nodes) {
    const nodeId = mermaidId("node", node.node_id);
    lines.push(
      `${nodeId}(["${mermaidText(shortId(node.node_id))}<br/>${mermaidText(node.vpn_ip || "-")}"])`,
    );
    if (node.leaf_group_id) {
      lines.push(`${mermaidId("group", node.leaf_group_id)} -.-> ${nodeId}`);
    }
  }

  for (const edge of edges) {
    const placements = Array.isArray(edge.placements) ? edge.placements : [];
    const label = placements[0]?.kind
      ? pretty(placements[0].kind)
      : edge.observed_status || "peer";
    lines.push(
      `${mermaidId("node", edge.source)} ---|"${mermaidText(label)}"| ${mermaidId("node", edge.target)}`,
    );
  }

  lines.push("classDef group fill:#f2f8fd,stroke:#0972d3,color:#16191f");
  lines.push("classDef node fill:#ffffff,stroke:#687078,color:#16191f");
  if (groups.length) lines.push(`class ${groups.map((group) => mermaidId("group", group.group_id)).join(",")} group`);
  if (nodes.length) lines.push(`class ${nodes.map((node) => mermaidId("node", node.node_id)).join(",")} node`);
  return lines.join("\n");
}
