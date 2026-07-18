#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo_bin="${CARGO:-cargo}"

cd "$repo_root"
"$cargo_bin" test --locked -p ipars-control-plane-http \
  http_admin_overview_updates_for_three_node_nat_discovery -- --nocapture

echo "HeteroNetwork three-node NAT discovery overview smoke completed"
