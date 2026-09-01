#!/usr/bin/env bash
set -euo pipefail

readonly archive="${1:-}"
readonly vpn_ip="${2:-}"
readonly archive_sha256="${HETERONETWORK_ROLLOUT_ARCHIVE_SHA256:-}"
readonly daemon_sha256="${HETERONETWORK_ROLLOUT_IPARSD_SHA256:-}"
readonly owner_email="${HETERONETWORK_OWNER_EMAIL:-}"
readonly install_root="${HETERONETWORK_INSTALL_ROOT:-/opt/heteronetwork}"

fail() {
  printf 'rollout-console-owner-update: %s\n' "$*" >&2
  exit 1
}

[[ "$(id -u)" == 0 ]] || fail "must run as root"
[[ -f "$archive" && ! -L "$archive" ]] || fail "release archive is unavailable"
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "release archive SHA-256 is required"
[[ "$daemon_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "iparsd SHA-256 is required"
[[ "$owner_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] \
  || fail "HETERONETWORK_OWNER_EMAIL is invalid"
[[ "$vpn_ip" =~ ^10\.250\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
  || fail "VPN address must be in the HeteroNetwork overlay"
command -v curl >/dev/null || fail "curl is required"
command -v sha256sum >/dev/null || fail "sha256sum is required"
command -v systemctl >/dev/null || fail "systemctl is required"

actual_archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
[[ "$actual_archive_sha256" == "$archive_sha256" ]] \
  || fail "release archive checksum mismatch"

stage="$(mktemp -d "$install_root/.console-owner-rollout.XXXXXX")"
trap 'rm -rf "$stage"' EXIT HUP INT TERM
tar -xzf "$archive" -C "$stage"

readonly daemon_source="$stage/target/release/iparsd"
readonly cli_source="$stage/target/release/ipars"
readonly autopilot_source="$stage/scripts/public-services-autopilot.sh"
readonly auth_reconciler_source="$stage/scripts/reconcile-owner-console-auth.sh"
readonly e2e_source="$stage/scripts/heteronetwork-console-e2e.sh"
readonly lighttpd_proxy_source="$stage/deploy/lighttpd/99-heteronetwork-console.conf"
readonly agent_proxy_drop_in_source="$stage/deploy/systemd/heteronetwork-agent-overlay-proxy.conf"
for source in \
  "$daemon_source" \
  "$cli_source" \
  "$autopilot_source" \
  "$auth_reconciler_source" \
  "$e2e_source" \
  "$lighttpd_proxy_source" \
  "$agent_proxy_drop_in_source"; do
  [[ -f "$source" && ! -L "$source" ]] || fail "archive is missing ${source#"$stage/"}"
done
[[ "$(sha256sum "$daemon_source" | awk '{print $1}')" == "$daemon_sha256" ]] \
  || fail "archive contains the wrong iparsd binary"

install_atomically() {
  local source="$1" target="$2" temporary
  temporary="${target}.new.$$"
  install -o root -g root -m 0755 "$source" "$temporary"
  mv -f "$temporary" "$target"
}

install -d -o root -g root -m 0755 "$install_root/bin" "$install_root/libexec"
install_atomically "$daemon_source" "$install_root/bin/iparsd"
install_atomically "$cli_source" "$install_root/bin/ipars"
install_atomically "$autopilot_source" "$install_root/libexec/public-services-autopilot.sh"
install_atomically "$auth_reconciler_source" "$install_root/libexec/reconcile-owner-console-auth.sh"
install_atomically "$e2e_source" "$install_root/libexec/heteronetwork-console-e2e.sh"

console_is_healthy() {
  curl --fail --silent --show-error --max-time 2 \
    --resolve "console.heteronetwork.internal:80:$vpn_ip" \
    http://console.heteronetwork.internal/v1/web-ui/healthz >/dev/null 2>&1
}

configure_lighttpd_proxy() {
  local lighttpd_config=/etc/lighttpd/conf-enabled/99-heteronetwork-console.conf
  local agent_drop_in=/etc/systemd/system/heteronetwork-agent.service.d/60-overlay-http-proxy.conf
  [[ "$(systemctl show lighttpd.service --property=LoadState --value 2>/dev/null)" == "loaded" ]] \
    || return 1
  systemctl is-active --quiet lighttpd.service || return 1
  curl --fail --silent --show-error --max-time 2 \
    http://127.0.0.1:9780/v1/web-ui/healthz >/dev/null 2>&1 || return 1

  install -d -o root -g root -m 0755 \
    /etc/lighttpd/conf-enabled \
    /etc/systemd/system/heteronetwork-agent.service.d
  install -o root -g root -m 0644 "$lighttpd_proxy_source" "$lighttpd_config"
  install -o root -g root -m 0644 "$agent_proxy_drop_in_source" "$agent_drop_in"
  if ! lighttpd -tt -f /etc/lighttpd/lighttpd.conf; then
    rm -f "$lighttpd_config" "$agent_drop_in"
    return 1
  fi
  systemctl daemon-reload
  systemctl restart heteronetwork-agent.service
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet heteronetwork-agent.service \
      && curl --fail --silent --show-error --max-time 2 \
        http://127.0.0.1:9780/v1/web-ui/healthz >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  systemctl restart lighttpd.service
}

systemctl restart heteronetwork-agent.service
for _ in $(seq 1 30); do
  systemctl is-active --quiet heteronetwork-agent.service && break
  sleep 1
done
systemctl is-active --quiet heteronetwork-agent.service \
  || fail "Agent did not recover after the binary update"

for _ in $(seq 1 10); do
  if curl --fail --silent --show-error --max-time 2 \
    http://127.0.0.1:9780/v1/web-ui/endpoints >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error --max-time 5 \
  http://127.0.0.1:9780/v1/web-ui/endpoints >/dev/null \
  || fail "Agent control API did not become ready"

HETERONETWORK_OWNER_EMAIL="${owner_email,,}" \
  "$install_root/libexec/reconcile-owner-console-auth.sh"

for _ in $(seq 1 10); do
  if console_is_healthy; then
    break
  fi
  sleep 1
done
if ! console_is_healthy; then
  configure_lighttpd_proxy \
    || fail "port 80 is occupied and no supported HTTP proxy could be configured"
fi
for _ in $(seq 1 20); do
  console_is_healthy && break
  sleep 1
done
console_is_healthy || fail "portless VPN console did not become healthy"
[[ "$(sha256sum "$install_root/bin/iparsd" | awk '{print $1}')" == "$daemon_sha256" ]] \
  || fail "installed iparsd checksum changed"

printf 'rollout-console-owner-update: %s (%s) updated\n' "$(hostname)" "$vpn_ip"
