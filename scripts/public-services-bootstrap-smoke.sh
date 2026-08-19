#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bootstrap_executor=$script_dir/public-services-bootstrap.sh
test_root=$(mktemp -d "${TMPDIR:-/tmp}/heteronetwork-public-bootstrap-smoke.XXXXXX")
pending=$test_root/public-services-promotion.sh
bootstrap=$test_root/bootstrap.env
generation=$test_root/bootstrap-generation
invocations=$test_root/invocations

cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

fail() {
  printf '%s\n' "public-services bootstrap smoke: $*" >&2
  exit 1
}

export HETERONETWORK_PUBLIC_SERVICES_PROMOTION_PATH=$pending
export HETERONETWORK_PUBLIC_SERVICES_BOOTSTRAP_PATH=$bootstrap
export HETERONETWORK_PUBLIC_SERVICES_GENERATION_PATH=$generation
export HETERONETWORK_PUBLIC_SERVICES_EXPECTED_GENERATION=2
export HETERONETWORK_PUBLIC_SERVICES_REQUIRED_UID
HETERONETWORK_PUBLIC_SERVICES_REQUIRED_UID=$(id -u)
export HETERONETWORK_PUBLIC_SERVICES_SMOKE_INVOCATIONS=$invocations

write_pending() {
  cat >"$pending" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >>"$HETERONETWORK_PUBLIC_SERVICES_SMOKE_INVOCATIONS"
printf '%s\n' configured >"$HETERONETWORK_PUBLIC_SERVICES_BOOTSTRAP_PATH"
printf '%s\n' "$HETERONETWORK_PUBLIC_SERVICES_EXPECTED_GENERATION" \
  >"$HETERONETWORK_PUBLIC_SERVICES_GENERATION_PATH"
EOF
  chmod 0600 "$pending"
}

printf '%s\n' stale >"$bootstrap"
write_pending
"$bootstrap_executor"
[ "$(cat "$invocations")" = "--promote-existing" ] ||
  fail "a stale bootstrap was not promoted in place"
[ "$(cat "$generation")" = 2 ] || fail "promotion did not install the current generation"
[ ! -e "$pending" ] || fail "a successful promotion remained pending"

: >"$invocations"
write_pending
"$bootstrap_executor"
[ ! -s "$invocations" ] || fail "a current bootstrap was needlessly reinstalled"
[ ! -e "$pending" ] || fail "a redundant current-generation script was retained"

rm -f "$generation"
cat >"$pending" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 0600 "$pending"
if "$bootstrap_executor"; then
  fail "a failed promotion was accepted"
fi
[ ! -e "$pending" ] || fail "a failed short-lived promotion script was retained"

printf '%s\n' "public-services bootstrap smoke: passed"
