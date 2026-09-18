#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
helper_dir="$project_dir/RootHelper"
default_output="$project_dir/.build/root-helper/heteronetwork-root-helper"
output_path="${1:-$default_output}"

go_binary="$(command -v go 2>/dev/null || true)"
if [[ -z "$go_binary" ]]; then
  for candidate in /usr/local/go/bin/go /opt/homebrew/bin/go /usr/local/bin/go; do
    if [[ -x "$candidate" ]]; then
      go_binary="$candidate"
      break
    fi
  done
fi
if [[ -z "$go_binary" ]]; then
  echo "Go 1.20.14 or later is required to build the macOS root helper." >&2
  exit 1
fi

build_arch="${CURRENT_ARCH:-${NATIVE_ARCH_ACTUAL:-$(uname -m)}}"
if [[ "$build_arch" == undefined_arch ]]; then
  build_arch="$(uname -m)"
fi
case "$build_arch" in
  arm64|aarch64)
    go_arch=arm64
    ;;
  x86_64|x64|amd64)
    go_arch=amd64
    ;;
  *)
    echo "Unsupported macOS build architecture: $build_arch" >&2
    exit 1
    ;;
esac

build_version="${HETERONETWORK_HELPER_BUILD_VERSION:-}"
if [[ -z "$build_version" ]]; then
  build_version="$(git -C "$project_dir" rev-parse --verify HEAD 2>/dev/null || printf development)"
fi
case "$build_version" in
  *[!A-Za-z0-9._-]*)
    echo "Invalid root helper build version: $build_version" >&2
    exit 1
    ;;
esac

mkdir -p "$(dirname "$output_path")"
temporary_output="$output_path.tmp.$$"
trap 'rm -f "$temporary_output"' EXIT
(
  cd "$helper_dir"
  CGO_ENABLED=1 GOOS=darwin GOARCH="$go_arch" \
    "$go_binary" build -mod=readonly -trimpath \
      -ldflags "-s -w -X main.buildVersion=$build_version" \
      -o "$temporary_output" .
)
/usr/bin/install -m 0755 "$temporary_output" "$output_path"
