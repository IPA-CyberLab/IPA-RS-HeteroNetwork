#!/usr/bin/env bash
# Copies verified public files into a NEW inactive directory only.
set -euo pipefail
exec python3 "$(dirname -- "${BASH_SOURCE[0]}")/sudo-quorum-v2-artifact.py" install "$@"
