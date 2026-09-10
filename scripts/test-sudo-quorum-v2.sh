#!/usr/bin/env bash
# Disposable real CLI -> HTTP signer -> local daemon -> sudo E2E. Never uses host sudo.
# All stdout/stderr is public build/provenance/test output; fixture secrets stay in
# the runtime container's writable layer and are deleted with that container.
set -Eeuo pipefail
umask 077

local_rlimits=0
if [[ $# == 1 && $1 == --local-rlimits ]]; then
    [[ -z ${CI:-} && -z ${GITHUB_ACTIONS:-} ]] || { printf 'Local rlimit mode is forbidden in CI\n' >&2; exit 2; }
    local_rlimits=1
elif [[ $# -ne 0 ]]; then
    printf 'Usage: %s [--local-rlimits]\nDefault: full cgroup bounds. Local-only fallback: PID cap, affinity and hard rlimits.\n' "$0" >&2
    exit 2
fi
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
[[ $(uname -s) == Linux ]] || fail 'Linux is required'
for tool in cargo docker python3 ip timeout sha256sum mktemp cp rm date mkdir dirname; do
    command -v "$tool" >/dev/null || fail "missing required tool: $tool"
done
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$repo"
lifecycle=prototypes/sudo-quorum/lifecycle

# Refuse a remote daemon: this script must never create resources on production.
if [[ -n ${DOCKER_HOST:-} && -z ${DOCKER_CONTEXT:-} ]]; then
    endpoint=$DOCKER_HOST
else
    endpoint=$(docker context inspect --format '{{.Endpoints.docker.Host}}')
fi
[[ $endpoint == unix://* ]] || fail 'a local Unix-socket Docker daemon is required'
[[ $(docker info --format '{{.OSType}}') == linux ]] || fail 'Linux Docker engine required'
case "$(uname -m):$(docker info --format '{{.Architecture}}')" in
    x86_64:x86_64|x86_64:amd64|aarch64:aarch64|aarch64:arm64) ;;
    *) fail 'host and Docker architecture must match' ;;
esac

# Reject existing Docker or directly routed overlaps, rather than disturbing them.
network_listing=$(docker network ls -q)
networks_json='[]'
if [[ -n $network_listing ]]; then
    mapfile -t existing_networks <<< "$network_listing"
    networks_json=$(docker network inspect "${existing_networks[@]}")
fi
python3 -c '
import ipaddress, json, sys
target = ipaddress.ip_network("172.30.99.0/24")
for network in json.load(sys.stdin):
    for config in network.get("IPAM", {}).get("Config") or []:
        subnet = config.get("Subnet")
        if subnet and ipaddress.ip_network(subnet).overlaps(target):
            raise SystemExit("existing Docker subnet overlaps the fixture subnet")
' <<< "$networks_json"
routes_json=$(ip -j -4 route show table all)
python3 -c '
import ipaddress, json, sys
target = ipaddress.ip_network("172.30.99.0/24")
for route in json.load(sys.stdin):
    dest = route.get("dst", "default")
    if dest == "default":
        continue
    subnet = ipaddress.ip_network(dest, strict=False)
    if subnet.prefixlen and subnet.overlaps(target):
        raise SystemExit("existing host route overlaps the fixture subnet")
' <<< "$routes_json"

stage=$(mktemp -d "${TMPDIR:-/tmp}/ipars-sudo-v2.XXXXXXXX")
run_id=${stage##*/}
base_tag="ipars-sudo-v2-base:$run_id"
image_tag="ipars-sudo-v2-full:$run_id"
network_name="$run_id-network"
header_name="$run_id-header"
container_name="$run_id-test"
network_id=''
header_id=''
container_id=''
base_id=''
image_id=''
base_build_started=0
full_build_started=0

owned() {
    local kind=$1 object=$2
    [[ $(docker "$kind" inspect --format '{{index .Config.Labels "ipars.sudo-v2.run"}}' "$object" 2>/dev/null) == "$run_id" ]]
}
cleanup() {
    local result=$? object tag candidate cleanup_failed=0
    trap - EXIT INT TERM
    set +e
    # Creation can succeed in Docker before an interrupted command assigns its ID.
    # Resolve only this run's exact names, then require the ownership label below.
    if [[ -z $container_id ]]; then
        container_id=$(docker container ls -aq --filter "name=^/${container_name}$") || cleanup_failed=1
    fi
    if [[ -z $header_id ]]; then
        header_id=$(docker container ls -aq --filter "name=^/${header_name}$") || cleanup_failed=1
    fi
    if [[ -z $network_id ]]; then
        candidate=$(docker network ls -q --filter "name=^${network_name}$") || cleanup_failed=1
        network_id=$candidate
    fi
    for object in "$container_id" "$header_id"; do
        [[ -n $object ]] || continue
        if ! owned container "$object"; then
            printf 'Refusing cleanup of container with missing ownership label: %s\n' "$object" >&2
            cleanup_failed=1
            continue
        fi
        if [[ $(docker container inspect --format '{{.State.Running}}' "$object") == true ]]; then
            docker container stop --time 10 "$object" || cleanup_failed=1
        fi
        docker container rm "$object" || cleanup_failed=1
    done
    if [[ -n $network_id ]]; then
        if [[ $(docker network inspect --format '{{index .Labels "ipars.sudo-v2.run"}}' "$network_id") == "$run_id" ]]; then
            docker network rm "$network_id" || cleanup_failed=1
        else
            printf 'Refusing cleanup of network with missing ownership label\n' >&2
            cleanup_failed=1
        fi
    fi
    # Remove only our unique tags, without force; never delete a shared base tag.
    for tag in "$image_tag" "$base_tag"; do
        [[ $tag != "$image_tag" || $full_build_started == 1 ]] || continue
        [[ $tag != "$base_tag" || $base_build_started == 1 ]] || continue
        if docker image inspect "$tag" >/dev/null 2>&1; then
            if owned image "$tag"; then
                docker image rm "$tag" || cleanup_failed=1
            else
                printf 'Refusing cleanup of image with missing ownership label: %s\n' "$tag" >&2
                cleanup_failed=1
            fi
        fi
    done
    rm -r -- "$stage" || cleanup_failed=1
    if (( cleanup_failed )); then
        printf 'ERROR: incomplete cleanup; inspect the owned IDs printed above\n' >&2
        [[ $result -ne 0 ]] || result=1
    else
        printf 'Cleanup complete: %s (no fixture keys exported)\n' "$run_id"
    fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for name in "$header_name" "$container_name"; do
    if docker container inspect "$name" >/dev/null 2>&1; then
        fail "container name already exists: $name"
    fi
done
for tag in "$base_tag" "$image_tag"; do
    if docker image inspect "$tag" >/dev/null 2>&1; then
        fail "image tag already exists: $tag"
    fi
done
if docker network inspect "$network_name" >/dev/null 2>&1; then
    fail "network name already exists: $network_name"
fi

printf 'Run: %s\nStarted UTC: %s\n' "$run_id" "$(date -u +%FT%TZ)"
source_inputs=(
    scripts/test-sudo-quorum-v2.sh Cargo.toml Cargo.lock
    crates/ipars-cli/src/quorum.rs crates/ipars-cli/src/quorum/sudo.rs
    crates/ipars-cli/src/quorum/sudo/local.rs
    crates/ipars-quorum/src/sudo.rs crates/ipars-quorum/src/sudo/local.rs
    crates/ipars-control-plane-http/src/quorum/sudo.rs
    crates/ipars-control-plane-http/examples/sudo_v2_fixture.rs
    prototypes/sudo-quorum/Cargo.toml prototypes/sudo-quorum/Cargo.lock
    prototypes/sudo-quorum/src/local_v2.rs prototypes/sudo-quorum/src/privilege_v2.rs
    "$lifecycle/Dockerfile" "$lifecycle/Dockerfile.full-v2"
    "$lifecycle/privilege_gate.c" "$lifecycle/privilege_v2_gate.c"
    "$lifecycle/privilege_v2_ack_test.c" "$lifecycle/full_v2_e2e.py"
    "$lifecycle/deny_gate.c" "$lifecycle/witness.c" "$lifecycle/command.c"
    "$lifecycle/gate_test.c" "$lifecycle/test.py"
)
printf '\nSource SHA256 before build:\n'
sha256sum "${source_inputs[@]}" > "$stage/source.sha256"
while IFS= read -r line; do printf '%s\n' "$line"; done < "$stage/source.sha256"

timeout --signal=TERM --kill-after=20s 1800s cargo build --locked -j2 \
    --message-format=json-render-diagnostics \
    -p ipars-cli --bin ipars -p ipars-control-plane-http --example sudo_v2_fixture \
    > "$stage/workspace-build.jsonl"
timeout --signal=TERM --kill-after=20s 1800s cargo build --locked -j2 \
    --message-format=json-render-diagnostics \
    --manifest-path prototypes/sudo-quorum/Cargo.toml --bin local-sudo-v2 \
    > "$stage/prototype-build.jsonl"
# Use this build's reported executables, not possibly stale target/debug files.
artifact_paths=$(python3 - "$stage/workspace-build.jsonl" "$stage/prototype-build.jsonl" <<'PY'
import json, sys
found = {}
for path in sys.argv[1:]:
    with open(path) as stream:
        for line in stream:
            event = json.loads(line)
            if event.get("reason") == "compiler-artifact" and event.get("executable"):
                found.setdefault(event["target"]["name"], set()).add(event["executable"])
for name in ("ipars", "sudo_v2_fixture", "local-sudo-v2"):
    paths = found.get(name, set())
    if len(paths) != 1:
        raise SystemExit("missing or ambiguous artifact: " + name)
    print(next(iter(paths)))
PY
)
mapfile -t artifacts <<< "$artifact_paths"
for artifact in "${artifacts[@]}"; do
    [[ -f $artifact && -x $artifact ]] || fail "missing executable artifact: $artifact"
done
mkdir "$stage/base" "$stage/full"
# Minimal contexts, no repository-wide COPY, configuration mounts or private inputs.
cp "$lifecycle/"{Dockerfile,deny_gate.c,witness.c,command.c,gate_test.c,test.py} "$stage/base/"
cp "${artifacts[@]}" "$stage/full/"
cp "$lifecycle/"{Dockerfile.full-v2,privilege_gate.c,privilege_v2_gate.c,privilege_v2_ack_test.c,full_v2_e2e.py} "$stage/full/"
printf '\nConfirm source snapshot unchanged after build/staging:\n'
sha256sum --check "$stage/source.sha256"

base_build_started=1
timeout --signal=TERM --kill-after=20s 900s docker build \
    --label "ipars.sudo-v2.run=$run_id" --tag "$base_tag" "$stage/base"
base_id=$(docker image inspect --format '{{.Id}}' "$base_tag")
printf 'Base image: %s %s\n' "$base_tag" "$base_id"
header_id=$(docker container create --name "$header_name" --label "ipars.sudo-v2.run=$run_id" \
    --network none --entrypoint /bin/true "$base_id")
printf 'Header extraction container (never started): %s\n' "$header_id"
docker cp "$header_id:/usr/local/include/sudo_plugin.h" "$stage/full/sudo_plugin.h"

printf '\nStaged public artifact SHA256:\n'
sha256sum "$stage/full/"*
full_build_started=1
timeout --signal=TERM --kill-after=20s 900s docker build \
    --label "ipars.sudo-v2.run=$run_id" --build-arg "BASE_IMAGE=$base_tag" \
    --tag "$image_tag" --file "$stage/full/Dockerfile.full-v2" "$stage/full"
image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
docker image inspect --format 'Full image: {{.Id}} built {{.Created}}' "$image_id"

network_id=$(docker network create --internal --subnet 172.30.99.0/24 \
    --label "ipars.sudo-v2.run=$run_id" "$network_name")
printf 'Internal network: %s\n' "$network_id"
limits=(--cpus 2 --memory 2g --memory-swap 2g --pids-limit 256)
entrypoint=()
command=()
if (( local_rlimits )); then
    # This explicit local mode retains kernel PID limits. 32 tasks * 256 MiB AS
    # bounds total address space to at most 8 GiB (threads share address spaces).
    # CPU affinity and wall timeout bound aggregate CPU; hard limits are inherited
    # across sudo exec. Docker's default capabilities omit CAP_SYS_RESOURCE.
    printf 'LOCAL BOUNDS: 32 tasks, 256 MiB AS/task (8 GiB aggregate ceiling), 2-CPU affinity, 120 CPU seconds/process, 600s wall\n'
    limits=(--pids-limit 32 --ulimit cpu=120:120 --ulimit data=268435456:268435456
        --ulimit core=0:0 --ulimit fsize=33554432:33554432
        --env MALLOC_ARENA_MAX=2 --env IPARS_SUDO_V2_LOCAL_RLIMITS=1)
    entrypoint=(--entrypoint /bin/sh)
    command=(-ec 'ulimit -v 262144; exec python3 /opt/full-v2/full_v2_e2e.py')
fi
container_id=$(docker container create --name "$container_name" --label "ipars.sudo-v2.run=$run_id" \
    --network "$network_id" --ip 172.30.99.2 "${limits[@]}" \
    --ulimit nofile=1024:1024 --env TOKIO_WORKER_THREADS=2 \
    --log-driver local --log-opt max-size=10m --log-opt max-file=1 --log-opt compress=false \
    "${entrypoint[@]}" "$image_id" "${command[@]}")
printf 'Bounded runtime container: %s\n' "$container_id"
# Public compiled plugin only; never copy the running container's key/config paths.
docker cp "$container_id:/opt/full-v2/privilege_v2_gate.so" "$stage/privilege_v2_gate.so"
sha256sum "$stage/privilege_v2_gate.so"
timeout --signal=TERM --kill-after=20s 600s docker container start --attach "$container_id"
status=$(docker container inspect --format '{{.State.ExitCode}}' "$container_id")
[[ $status == 0 ]] || fail "E2E exited with status $status"
printf 'PASS full sudo-v2 E2E; finished UTC: %s\n' "$(date -u +%FT%TZ)"
