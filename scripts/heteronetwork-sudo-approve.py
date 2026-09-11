#!/usr/bin/env python3
"""Submit one pinned majority approval for an already pending sudo invocation."""

import argparse
import os
from pathlib import Path
import re
import sys


IPARS = "/opt/heteronetwork/sudo-v2/runtime/current/bin/ipars"
POLICY = "/etc/heteronetwork/sudo-quorum/policy.json"
REQUESTER_KEY = Path.home() / ".config/heteronetwork/sudo/requester.key"
OWNER_TOKEN = Path.home() / ".config/heteronetwork/sudo/owner.token"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handle")
    args = parser.parse_args()
    if os.getuid() == 0 or os.getuid() != os.geteuid():
        raise SystemExit("run as the original non-root user")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.handle) or int(args.handle, 16) == 0:
        raise SystemExit("handle must be 64 nonzero hexadecimal characters")
    os.execv(IPARS, [
        IPARS, "quorum", "sudo-approve",
        "--handle", args.handle.lower(),
        "--policy", POLICY,
        "--requester-key", str(REQUESTER_KEY),
        "--oidc-token", str(OWNER_TOKEN),
        "--vpn-cidr", "10.251.0.0/24",
    ])


if __name__ == "__main__":
    main()
