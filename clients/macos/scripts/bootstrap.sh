#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
checkout_dir="$project_dir/.build/wireguard-apple"
repository_url="https://git.zx2c4.com/wireguard-apple"
revision="2fec12a6e1f6e3460b6ee483aa00ad29cddadab1"

if [[ ! -d "$checkout_dir/.git" ]]; then
  rm -rf "$checkout_dir"
  mkdir -p "$(dirname "$checkout_dir")"
  git init --quiet "$checkout_dir"
  git -C "$checkout_dir" remote add origin "$repository_url"
  git -C "$checkout_dir" fetch --quiet --depth 1 origin "$revision"
  git -C "$checkout_dir" checkout --quiet --detach FETCH_HEAD
fi

actual_revision="$(git -C "$checkout_dir" rev-parse HEAD)"
if [[ "$actual_revision" != "$revision" ]]; then
  printf 'WireGuardKit checkout is at %s, expected %s\n' "$actual_revision" "$revision" >&2
  exit 1
fi

if ! git -C "$checkout_dir" diff --quiet -- . \
  ':(exclude)Package.swift' \
  ':(exclude)Sources/WireGuardKitC/WireGuardKitC.h' \
  ':(exclude)Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift'; then
  echo "WireGuardKit checkout contains unexpected local changes" >&2
  exit 1
fi

# The pinned upstream manifest declares tools 5.3 while using platform values
# introduced in PackageDescription 5.5. Preserve the source and fix that header.
git -C "$checkout_dir" show "$revision:Package.swift" \
  | sed '1s/swift-tools-version:5.3/swift-tools-version:5.5/' \
  > "$checkout_dir/Package.swift"

# Xcode 16 requires modular headers to import BSD aliases explicitly. Keep the
# original spellings so Clang sees the same definitions as sys/kern_control.h.
git -C "$checkout_dir" show "$revision:Sources/WireGuardKitC/WireGuardKitC.h" \
  | sed '/#include "x25519.h"/a\
#include <sys/types.h>' \
  > "$checkout_dir/Sources/WireGuardKitC/WireGuardKitC.h"

git -C "$checkout_dir" show \
  "$revision:Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift" \
  > "$checkout_dir/Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift"
git -C "$checkout_dir" apply "$project_dir/patches/wireguardkit-split-dns.patch"

cd "$project_dir"
xcodegen generate
