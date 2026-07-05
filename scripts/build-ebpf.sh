#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/.cargo/bin:$PATH"
CARGO_BIN="${CARGO:-$HOME/.cargo/bin/cargo}"
TOOLCHAIN="${IPARS_EBPF_TOOLCHAIN:-nightly}"
TARGET="${IPARS_EBPF_TARGET:-bpfel-unknown-none}"
PROFILE="${IPARS_EBPF_PROFILE:-release}"
MANIFEST="$ROOT_DIR/ebpf/ipars-packet-flow/Cargo.toml"
OUT_DIR="$ROOT_DIR/target/ebpf"
ARTIFACT_BASENAME="libipars_packet_flow_ebpf.so"
BUILD_ARGS=()

if ! command -v bpf-linker >/dev/null 2>&1; then
  echo "missing bpf-linker; install with: cargo install bpf-linker" >&2
  exit 1
fi

if [[ -n "$TOOLCHAIN" ]]; then
  BUILD_ARGS+=("+$TOOLCHAIN")
fi
BUILD_ARGS+=(build -Z build-std=core --manifest-path "$MANIFEST" --target "$TARGET")

if [[ "$PROFILE" == "release" ]]; then
  "$CARGO_BIN" "${BUILD_ARGS[@]}" --release
  SOURCE="$ROOT_DIR/ebpf/ipars-packet-flow/target/$TARGET/release/$ARTIFACT_BASENAME"
else
  "$CARGO_BIN" "${BUILD_ARGS[@]}"
  SOURCE="$ROOT_DIR/ebpf/ipars-packet-flow/target/$TARGET/debug/$ARTIFACT_BASENAME"
fi

mkdir -p "$OUT_DIR"
cp "$SOURCE" "$OUT_DIR/ipars-packet-flow.bpf.o"
echo "$OUT_DIR/ipars-packet-flow.bpf.o"
