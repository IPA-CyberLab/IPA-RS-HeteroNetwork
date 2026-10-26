#!/bin/sh
# Shared by enrollment and the public-service reconcilers. This file defines
# functions only; node-ports.env is parsed as data and is never sourced.

node_ports_defaults() {
  node_wireguard_listen_port=51820
  node_wireguard_public_port=
  node_relay_listen_port=18445
  node_relay_public_port=
  node_stun_listen_port=19444
  node_stun_public_port=
  node_https_listen_port=443
  node_https_public_port=
}

node_ports_number() {
  case "$1" in
    ''|*[!0-9]*|0|0*) return 1 ;;
  esac
  [ "${#1}" -le 5 ] && [ "$1" -le 65535 ]
}

node_ports_assign() {
  node_port_key=$1
  node_port_value=$2
  case "$node_port_key" in
    *_PUBLIC_PORT) [ -z "$node_port_value" ] || node_ports_number "$node_port_value" || return 1 ;;
    *) node_ports_number "$node_port_value" || return 1 ;;
  esac
  case "$node_port_key" in
    WIREGUARD_LISTEN_PORT) node_wireguard_listen_port=$node_port_value ;;
    WIREGUARD_PUBLIC_PORT) node_wireguard_public_port=$node_port_value ;;
    RELAY_LISTEN_PORT) node_relay_listen_port=$node_port_value ;;
    RELAY_PUBLIC_PORT) node_relay_public_port=$node_port_value ;;
    STUN_LISTEN_PORT) node_stun_listen_port=$node_port_value ;;
    STUN_PUBLIC_PORT) node_stun_public_port=$node_port_value ;;
    HTTPS_LISTEN_PORT) node_https_listen_port=$node_port_value ;;
    HTTPS_PUBLIC_PORT) node_https_public_port=$node_port_value ;;
    *) return 1 ;;
  esac
}

node_ports_load() {
  node_ports_path=$1
  if [ ! -e "$node_ports_path" ] && [ ! -L "$node_ports_path" ]; then
    return 0
  fi
  if [ ! -f "$node_ports_path" ] || [ -L "$node_ports_path" ] ||
    [ "$(stat -c %u "$node_ports_path")" != "${2:-0}" ]; then
    echo "Invalid HeteroNetwork port configuration file" >&2
    return 1
  fi
  case "$(stat -c %a "$node_ports_path")" in
    600|640|644|400|440|444) ;;
    *) echo "HeteroNetwork port configuration must not be writable by other users" >&2; return 1 ;;
  esac
  node_ports_seen=' '
  while IFS= read -r node_ports_line || [ -n "$node_ports_line" ]; do
    case "$node_ports_line" in
      ''|'#'*) continue ;;
      *=*) ;;
      *) echo "Invalid HeteroNetwork port configuration entry" >&2; return 1 ;;
    esac
    node_ports_key=${node_ports_line%%=*}
    node_ports_value=${node_ports_line#*=}
    case "$node_ports_seen" in
      *" $node_ports_key "*) echo "Duplicate HeteroNetwork port configuration entry" >&2; return 1 ;;
    esac
    if ! node_ports_assign "$node_ports_key" "$node_ports_value"; then
      echo "Invalid HeteroNetwork port configuration entry" >&2
      return 1
    fi
    node_ports_seen="$node_ports_seen$node_ports_key "
  done <"$node_ports_path"
}

node_ports_validate() {
  for node_port in "$node_wireguard_listen_port" "$node_relay_listen_port" \
    "$node_stun_listen_port" "$node_https_listen_port"; do
    node_ports_number "$node_port" || { echo "Ports must be integers from 1 to 65535" >&2; return 1; }
  done
  for node_port in "$node_wireguard_public_port" "$node_relay_public_port" \
    "$node_stun_public_port" "$node_https_public_port"; do
    [ -z "$node_port" ] || node_ports_number "$node_port" || {
      echo "Public ports must be integers from 1 to 65535" >&2; return 1;
    }
  done
  node_relay_advertise_port=${node_relay_public_port:-$node_relay_listen_port}
  node_stun_advertise_port=${node_stun_public_port:-$node_stun_listen_port}
  node_https_advertise_port=${node_https_public_port:-$node_https_listen_port}
  if [ "$node_wireguard_listen_port" = "$node_relay_listen_port" ] ||
    [ "$node_wireguard_listen_port" = "$node_stun_listen_port" ] ||
    [ "$node_relay_listen_port" = "$node_stun_listen_port" ] ||
    [ "$node_relay_advertise_port" = "$node_stun_advertise_port" ] ||
    { [ -n "$node_wireguard_public_port" ] &&
      { [ "$node_wireguard_public_port" = "$node_relay_advertise_port" ] ||
        [ "$node_wireguard_public_port" = "$node_stun_advertise_port" ]; }; }; then
    echo "WireGuard, Relay and STUN require distinct UDP ports" >&2
    return 1
  fi
  for node_port in "$node_wireguard_listen_port" "$node_relay_listen_port" "$node_stun_listen_port"; do
    case "$node_port" in
      53|51821|51822) echo "UDP port conflicts with an internal Agent listener" >&2; return 1 ;;
    esac
  done
  case "$node_https_listen_port" in
    80|9780|9781|18447|19088|19443|19446)
      echo "HTTPS port conflicts with an internal listener" >&2; return 1 ;;
  esac
}

node_ports_write() {
  cat <<EOF
WIREGUARD_LISTEN_PORT=$node_wireguard_listen_port
WIREGUARD_PUBLIC_PORT=$node_wireguard_public_port
RELAY_LISTEN_PORT=$node_relay_listen_port
RELAY_PUBLIC_PORT=$node_relay_public_port
STUN_LISTEN_PORT=$node_stun_listen_port
STUN_PUBLIC_PORT=$node_stun_public_port
HTTPS_LISTEN_PORT=$node_https_listen_port
HTTPS_PUBLIC_PORT=$node_https_public_port
EOF
}

node_ports_wireguard_matches() {
  node_wireguard_observed_port=${1##*:}
  [ "$node_wireguard_observed_port" != "$node_relay_advertise_port" ] &&
    [ "$node_wireguard_observed_port" != "$node_stun_advertise_port" ] &&
    { [ -z "$node_wireguard_public_port" ] || [ "$node_wireguard_observed_port" = "$node_wireguard_public_port" ]; }
}
