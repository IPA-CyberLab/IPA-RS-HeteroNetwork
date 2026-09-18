#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin ]]; then
  echo "The privileged root-helper E2E runs only on macOS." >&2
  exit 1
fi
if [[ $# -ne 1 || ! -x "$1" ]]; then
  echo "usage: e2e.sh PATH_TO_ROOT_HELPER" >&2
  exit 1
fi

source_helper="$1"
installed_helper="/Library/PrivilegedHelperTools/heteronetwork-root-helper-e2e"
temporary_dir="$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-root-helper-e2e.XXXXXX")"
configuration="$temporary_dir/tunnel.json"
status_file="$temporary_dir/status.json"
interface_name=""

cleanup() {
  "$installed_helper" stop >/dev/null 2>&1 || true
  sudo /bin/rm -f "$installed_helper"
  /bin/rm -rf "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

sudo /usr/bin/install -d -o root -g wheel -m 0755 /Library/PrivilegedHelperTools
sudo /usr/bin/install -o root -g wheel -m 0755 "$source_helper" "$installed_helper"

write_configuration() {
  gateway_name="$1"
  cat >"$configuration" <<EOF
{"schema_version":1,"owner_uid":$(id -u),"private_key":"1111111111111111111111111111111111111111111111111111111111111111","client_address":"10.253.255.2/32","gateway_node_id":"$gateway_name","gateway_vpn_ip":"10.253.255.1","gateway_wireguard_public_key":"2222222222222222222222222222222222222222222222222222222222222222","gateway_endpoint":"203.0.113.8:51820","allowed_ips":["10.253.255.1/32"],"dns_server":"10.253.255.1","dns_domain":"heteronetwork.internal","mtu":1280}
EOF
  chmod 0600 "$configuration"
}

write_configuration e2e-gateway-one
sudo "$installed_helper" start "$configuration" >"$status_file"
test ! -e "$configuration"
interface_name="$(python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["ok"] and value["status"] == "connected" and value["gateway"] == "e2e-gateway-one"; print(value["interface"])' "$status_file")"
case "$interface_name" in
  utun[0-9]*) ;;
  *)
    echo "Unexpected tunnel interface: $interface_name" >&2
    exit 1
    ;;
esac
/sbin/ifconfig "$interface_name" | grep -F '10.253.255.2' >/dev/null
/sbin/route -n get -inet 10.253.255.1 \
  | grep -E "interface:[[:space:]]+$interface_name$" >/dev/null
printf 'show State:/Network/Service/jp.go.ipa.cyberlab.heteronetwork/DNS\nquit\n' \
  | /usr/sbin/scutil | grep -F '10.253.255.1' >/dev/null

write_configuration e2e-gateway-two
"$installed_helper" update "$configuration" >"$status_file"
test ! -e "$configuration"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["ok"] and value["status"] == "connected" and value["gateway"] == "e2e-gateway-two"' "$status_file"
daemon_pid="$(python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["pid"] > 1; print(value["pid"])' "$status_file")"

# SIGKILL bypasses every Go defer. The utun must close with the process, and
# scutil's temporary session must remove split DNS when its stdin owner dies.
sudo /bin/kill -KILL "$daemon_pid"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  interface_gone=0
  dns_gone=0
  if ! /sbin/ifconfig "$interface_name" >/dev/null 2>&1; then
    interface_gone=1
  fi
  if ! printf 'show State:/Network/Service/jp.go.ipa.cyberlab.heteronetwork/DNS\nquit\n' \
    | /usr/sbin/scutil | grep -F '10.253.255.1' >/dev/null; then
    dns_gone=1
  fi
  if [[ "$interface_gone" -eq 1 && "$dns_gone" -eq 1 ]]; then
    break
  fi
  sleep 1
done
if /sbin/ifconfig "$interface_name" >/dev/null 2>&1; then
  echo "Tunnel interface remained after an unclean daemon exit." >&2
  exit 1
fi
if printf 'show State:/Network/Service/jp.go.ipa.cyberlab.heteronetwork/DNS\nquit\n' \
  | /usr/sbin/scutil | grep -F '10.253.255.1' >/dev/null; then
  echo "Temporary split DNS remained after an unclean daemon exit." >&2
  exit 1
fi
"$installed_helper" status >"$status_file"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["ok"] and value["status"] == "disconnected"' "$status_file"

write_configuration e2e-gateway-three
sudo "$installed_helper" start "$configuration" >"$status_file"
test ! -e "$configuration"
interface_name="$(python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["ok"] and value["status"] == "connected" and value["gateway"] == "e2e-gateway-three"; print(value["interface"])' "$status_file")"

"$installed_helper" stop >"$status_file"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["ok"] and value["status"] == "disconnected"' "$status_file"
for _ in 1 2 3 4 5; do
  if ! /sbin/ifconfig "$interface_name" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
if /sbin/ifconfig "$interface_name" >/dev/null 2>&1; then
  echo "Tunnel interface remained after stop." >&2
  exit 1
fi
if printf 'show State:/Network/Service/jp.go.ipa.cyberlab.heteronetwork/DNS\nquit\n' \
  | /usr/sbin/scutil | grep -F '10.253.255.1' >/dev/null; then
  echo "Split DNS state remained after stop." >&2
  exit 1
fi
"$installed_helper" status >"$status_file"
python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value["ok"] and value["status"] == "disconnected"' "$status_file"

printf '%s\n' 'Privileged macOS root-helper E2E passed.'
