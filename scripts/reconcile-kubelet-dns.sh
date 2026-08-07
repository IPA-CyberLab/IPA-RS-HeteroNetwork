#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_SOURCE="/run/systemd/resolve/resolv.conf"
readonly DEFAULT_DESTINATION="/etc/kubernetes/resolv.conf"
readonly KUBELET_CONFIG="/var/lib/kubelet/config.yaml"

source_path="${HETERONETWORK_KUBELET_RESOLVER_SOURCE:-$DEFAULT_SOURCE}"
destination="${HETERONETWORK_KUBELET_RESOLVER_PATH:-$DEFAULT_DESTINATION}"

die() {
  printf 'kubelet-dns: error: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" == 0 ]] || die "run as root"
[[ -r "$source_path" ]] || die "resolver source is missing: $source_path"
[[ -f "$KUBELET_CONFIG" ]] || die "kubelet config is missing: $KUBELET_CONFIG"

temporary="$(mktemp)"
trap 'rm -f "$temporary" "$temporary.config"' EXIT

# Kubelet accepts at most three nameservers. Keep the active resolver order but
# remove loopback and duplicate entries so host DNS changes cannot reintroduce
# DNSConfigForming warnings for system pods.
awk '
  $1 == "nameserver" && $2 != "" && $2 != "127.0.0.53" && $2 != "::1" && !seen[$2]++ && count < 3 {
    print "nameserver " $2
    count++
  }
  END {
    if (count == 0) exit 1
  }
' "$source_path" >"$temporary" || die "no usable nameserver found in $source_path"

install -D -o root -g root -m 0644 "$temporary" "$destination"

config_temporary="${temporary}.config"
awk -v resolver="$destination" '
  BEGIN { replaced = 0 }
  /^[[:space:]]*resolvConf:[[:space:]]*/ {
    print "resolvConf: " resolver
    replaced = 1
    next
  }
  { print }
  END {
    if (!replaced) print "resolvConf: " resolver
  }
' "$KUBELET_CONFIG" >"$config_temporary"

if ! cmp -s "$config_temporary" "$KUBELET_CONFIG"; then
  install -o root -g root -m 0644 "$config_temporary" "$KUBELET_CONFIG"
  systemctl daemon-reload
  systemctl restart kubelet
fi

printf 'kubelet-dns: using %s with %s nameserver(s)\n' "$destination" "$(grep -c '^nameserver ' "$destination")"
