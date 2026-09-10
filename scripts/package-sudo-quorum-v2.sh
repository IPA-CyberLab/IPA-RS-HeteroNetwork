#!/usr/bin/env bash
# Builds an optional, disabled artifact. Does not install or activate sudo policy.
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/sudo-quorum-v2-artifact.py" build "$@"
