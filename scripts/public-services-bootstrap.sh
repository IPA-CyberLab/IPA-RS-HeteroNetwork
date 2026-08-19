#!/bin/sh
set -eu

umask 077

pending=${HETERONETWORK_PUBLIC_SERVICES_PROMOTION_PATH:-/var/lib/heteronetwork/public-services-promotion.sh}
bootstrap=${HETERONETWORK_PUBLIC_SERVICES_BOOTSTRAP_PATH:-/etc/heteronetwork/public-services/bootstrap.env}
generation=${HETERONETWORK_PUBLIC_SERVICES_GENERATION_PATH:-/etc/heteronetwork/public-services/bootstrap-generation}
expected_generation=${HETERONETWORK_PUBLIC_SERVICES_EXPECTED_GENERATION:-2}
required_uid=${HETERONETWORK_PUBLIC_SERVICES_REQUIRED_UID:-0}

[ -f "$pending" ] && [ ! -L "$pending" ] || exit 0
[ "$(id -u)" -eq "$required_uid" ] || exit 1

metadata=$(stat -c '%u %a %h %s' "$pending")
set -- $metadata
[ "$#" -eq 4 ] || exit 1
[ "$1" -eq "$required_uid" ] || exit 1
[ "$2" -eq 600 ] || exit 1
[ "$3" -eq 1 ] || exit 1
[ "$4" -gt 0 ] && [ "$4" -le $((16 * 1024 * 1024)) ] || exit 1

target_generation=
generation_marker=$(sed -n '2p' "$pending")
case "$generation_marker" in
  '# HETERONETWORK_PUBLIC_SERVICES_GENERATION='*)
    target_generation=${generation_marker#*=}
    ;;
esac
if [ -z "$target_generation" ]; then
  target_generation=$expected_generation
fi
case "$target_generation" in
  '' | *[!0-9]*)
    rm -f "$pending"
    exit 1
    ;;
esac

if [ -f "$bootstrap" ] && [ ! -L "$bootstrap" ] &&
  [ -f "$generation" ] && [ ! -L "$generation" ] &&
  [ "$(tr -d '\r\n' <"$generation")" = "$target_generation" ]; then
  rm -f "$pending"
  exit 0
fi

if ! sh "$pending" --promote-existing; then
  # A failed promotion script may contain a short-lived join token. Remove it
  # so the Agent can fetch a fresh, one-use script on the next retry.
  rm -f "$pending"
  exit 1
fi

if ! [ -f "$bootstrap" ] || [ -L "$bootstrap" ] ||
  ! [ -f "$generation" ] || [ -L "$generation" ] ||
  [ "$(tr -d '\r\n' <"$generation")" != "$target_generation" ]; then
  rm -f "$pending"
  exit 1
fi
rm -f "$pending"
