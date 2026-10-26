#!/bin/sh
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
test_dir=$(mktemp -d)
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
. "$script_dir/node-ports.sh"
node_ports_defaults
node_ports_validate
node_ports_write >"$test_dir/default.env"
chmod 0600 "$test_dir/default.env"

# Reload the actual serialized profile in a new process, as happens on restart.
node_wireguard_listen_port=30100
node_wireguard_public_port=40100
node_relay_listen_port=30101
node_relay_public_port=40101
node_stun_listen_port=30102
node_stun_public_port=40102
node_https_listen_port=8443
node_https_public_port=9443
node_ports_validate
node_ports_write >"$test_dir/custom.env"
chmod 0600 "$test_dir/custom.env"
sh -eu -c '
  . "$1"
  node_ports_defaults
  node_ports_load "$2" "$(id -u)"
  node_ports_validate
  [ "$node_relay_advertise_port" = 40101 ]
  [ "$node_stun_advertise_port" = 40102 ]
  [ "$node_https_advertise_port" = 9443 ]
  node_ports_wireguard_matches "[2001:db8::10]:40100"
  ! node_ports_wireguard_matches "203.0.113.10:40999"
  node_ports_write
' sh "$script_dir/node-ports.sh" "$test_dir/custom.env" >"$test_dir/reloaded.env"
cmp "$test_dir/custom.env" "$test_dir/reloaded.env"
node_wireguard_public_port=
! node_ports_wireguard_matches "203.0.113.10:40101"
! node_ports_wireguard_matches "[2001:db8::10]:40102"
node_ports_wireguard_matches "203.0.113.10:40100"

# Bad input is rejected as data, without ever executing shell expressions.
for invalid in 'RELAY_LISTEN_PORT=0' 'RELAY_LISTEN_PORT=65536' \
  'RELAY_LISTEN_PORT=-1' 'RELAY_LISTEN_PORT=00080' 'RELAY_LISTEN_PORT=3.5' \
  'RELAY_LISTEN_PORT= 30101' 'UNKNOWN_PORT=30101' \
  'RELAY_LISTEN_PORT=$(touch should-not-exist)' \
  'RELAY_LISTEN_PORT=30101; touch should-not-exist'; do
  printf '%s\n' "$invalid" >"$test_dir/invalid.env"
  chmod 0600 "$test_dir/invalid.env"
  if (node_ports_defaults; node_ports_load "$test_dir/invalid.env" "$(id -u)") 2>/dev/null; then
    echo "accepted invalid port configuration" >&2
    exit 1
  fi
done
[ ! -e should-not-exist ]
printf '%s\n' 'RELAY_LISTEN_PORT=30101' 'RELAY_LISTEN_PORT=30102' >"$test_dir/invalid.env"
! (node_ports_defaults; node_ports_load "$test_dir/invalid.env" "$(id -u)") 2>/dev/null
ln -s "$test_dir/custom.env" "$test_dir/linked.env"
! (node_ports_defaults; node_ports_load "$test_dir/linked.env" "$(id -u)") 2>/dev/null
chmod 0666 "$test_dir/invalid.env"
! (node_ports_defaults; node_ports_load "$test_dir/invalid.env" "$(id -u)") 2>/dev/null

for collision in WIREGUARD_LISTEN_PORT=18445 RELAY_LISTEN_PORT=19444 \
  STUN_LISTEN_PORT=51821 HTTPS_LISTEN_PORT=9780 RELAY_PUBLIC_PORT=19444; do
  ! (node_ports_defaults; node_ports_assign "${collision%%=*}" "${collision#*=}"; node_ports_validate) 2>/dev/null
done
printf '%s\n' 'node ports smoke: ok'
