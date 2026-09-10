#!/usr/bin/env bash
set -euo pipefail

# Use the existing authenticated Agent CP override; never modify identity/state.
expected_host=${1:?usage: recover-local-control-plane.sh HOST VPN_IP [--apply]}
vpn_ip=${2:?expected VPN IPv4 address required}
mode=${3:---check}
[[ "$mode" == --check || "$mode" == --apply ]] || exit 2
[[ $(hostname) == "$expected_host" ]] || { echo 'host mismatch' >&2; exit 1; }
[[ "$vpn_ip" =~ ^10\.250\.0\.[0-9]{1,3}$ ]] || exit 2
[[ $EUID == 0 ]] || { echo 'root required' >&2; exit 1; }
state_ip=$(curl --fail --silent --show-error --max-time 3 \
  http://127.0.0.1:9780/v1/status | jq -er .vpn_ip)
[[ "$state_ip" == "$vpn_ip" ]] || { echo 'VPN identity mismatch' >&2; exit 1; }
systemctl is-active --quiet heteronetwork-control-plane.service
# A 404 on this unprivileged path still confirms the local HTTP listener.
code=$(curl --silent --show-error --max-time 3 --output /dev/null \
  --write-out '%{http_code}' "http://$vpn_ip:19088/health")
[[ "$code" == 200 || "$code" == 404 ]] || exit 1
target=/etc/systemd/system/heteronetwork-agent.service.d/60-local-control-plane-recovery.conf
[[ ! -e "$target" && ! -L "$target" ]] || { echo 'override already exists; inspect before retrying' >&2; exit 1; }
echo "Checked $expected_host: local CP $vpn_ip:19088 responds; existing node authentication retained."
[[ "$mode" == --apply ]] || exit 0
install -d -m 0755 "$(dirname "$target")"
tmp=$(mktemp "${target}.XXXXXX")
trap 'rm -f "$tmp"' EXIT
printf '[Service]\nEnvironment="HETERONETWORK_AGENT_CONTROL_PLANE_URL=http://%s:19088"\n' "$vpn_ip" >"$tmp"
chmod 0644 "$tmp"
mv -T "$tmp" "$target"
systemctl daemon-reload
systemctl restart heteronetwork-agent.service
echo 'Agent restarted with local CP fallback. Verify fresh peer maps and handshakes.'
