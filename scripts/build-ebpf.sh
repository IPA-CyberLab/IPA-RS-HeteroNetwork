#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"
TOOLCHAIN="${IPARS_EBPF_TOOLCHAIN:-nightly-2026-07-05}"
BPF_LINKER_VERSION="${IPARS_EBPF_BPF_LINKER_VERSION:-0.10.3}"
TARGET="${IPARS_EBPF_TARGET:-bpfel-unknown-none}"
PROFILE="${IPARS_EBPF_PROFILE:-release}"
MANIFEST="$ROOT_DIR/ebpf/ipars-packet-flow/Cargo.toml"
OUT_DIR="$ROOT_DIR/target/ebpf"
ARTIFACT_BASENAME="libipars_packet_flow_ebpf.so"
BUILD_ARGS=()

if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "missing bpf-linker; install with: cargo install bpf-linker --version ${BPF_LINKER_VERSION} --locked" >&2
  exit 1
fi
actual_bpf_linker_version="$(bpf-linker --version)"
if [[ "${actual_bpf_linker_version}" != "bpf-linker ${BPF_LINKER_VERSION}" ]]; then
  echo "bpf-linker version mismatch: expected ${BPF_LINKER_VERSION}, got ${actual_bpf_linker_version}" >&2
  exit 1
fi
if [[ ! -x "${CARGO_BIN}" ]]; then
  echo "CARGO must point to an executable cargo binary: ${CARGO_BIN}" >&2
  exit 1
fi

if [[ -n "$TOOLCHAIN" ]]; then
  BUILD_ARGS+=("+$TOOLCHAIN")
fi
BUILD_ARGS+=(build -Z build-std=core --manifest-path "$MANIFEST" --target "$TARGET")

case "$PROFILE" in
  release)
    "$CARGO_BIN" "${BUILD_ARGS[@]}" --release
    SOURCE="$ROOT_DIR/ebpf/ipars-packet-flow/target/$TARGET/release/$ARTIFACT_BASENAME"
    ;;
  debug)
    "$CARGO_BIN" "${BUILD_ARGS[@]}"
    SOURCE="$ROOT_DIR/ebpf/ipars-packet-flow/target/$TARGET/debug/$ARTIFACT_BASENAME"
    ;;
  *)
    echo "IPARS_EBPF_PROFILE must be 'release' or 'debug', got '${PROFILE}'" >&2
    exit 1
    ;;
esac

if [[ ! -s "$SOURCE" ]]; then
  echo "eBPF build did not produce a non-empty object: ${SOURCE}" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
install -m 0644 "$SOURCE" "$OUT_DIR/ipars-packet-flow.bpf.o"
echo "$OUT_DIR/ipars-packet-flow.bpf.o"
