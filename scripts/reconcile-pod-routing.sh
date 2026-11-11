#!/bin/sh
set -eu

pod_cidr=${1:?missing Pod CIDR}
priority=${2:?missing routing priority}

case "$priority" in
  *[!0-9]*|'') echo 'invalid routing priority' >&2; exit 2 ;;
esac

# The original oneshot service stays active if a network reconfiguration
# removes its rule. Only reinstall it when it is actually missing.
if /usr/sbin/ip -4 rule show | /usr/bin/awk -v priority="$priority:" -v cidr="$pod_cidr" '
  $1 == priority {
    for (i = 1; i < NF; i++) {
      if ($i == "to" && $(i + 1) == cidr && $(NF - 1) == "lookup" && $NF == "main") found = 1
    }
  }
  END { exit(found ? 0 : 1) }
'; then
  exit 0
fi

exec /opt/heteronetwork/libexec/kubernetes-pod-cidr-routing apply "$pod_cidr" "$priority"
