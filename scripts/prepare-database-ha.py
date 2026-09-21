#!/usr/bin/env python3
"""Render private Ansible inputs for the declared database HA topology."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/prepare-console-release.py"
SPEC = importlib.util.spec_from_file_location("heteronetwork_console_release", SOURCE)
CONSOLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CONSOLE)


def prepare(work_dir, ssh_key):
    CONSOLE.require(ssh_key.is_file() and not ssh_key.is_symlink(),
                    "SSH key must be a regular file")
    CONSOLE.require(stat.S_IMODE(ssh_key.stat().st_mode) & 0o077 == 0,
                    "SSH key permissions are too broad")
    CONSOLE.private_directory(work_dir)
    CONSOLE.write_private(work_dir / "known_hosts", CONSOLE.known_hosts_lines())
    rendered = CONSOLE.inventory(ROOT, work_dir, ssh_key.resolve(), {})
    groups = rendered["all"]["children"]
    members = groups["postgres_members"]["hosts"]
    voters = groups["postgres_dcs_only"]["hosts"]
    CONSOLE.require(
        {(value["postgres_name"], value["tailscale_ip"]) for value in members.values()}
        == {("db-b", "100.96.127.54"), ("db-e", "100.111.33.52")},
        "Database member inventory does not match the recovered topology",
    )
    CONSOLE.require(
        {(value["postgres_name"], value["tailscale_ip"]) for value in voters.values()}
        == {("db-g", "100.94.130.38")},
        "DCS voter inventory does not match the recovered topology",
    )
    CONSOLE.write_private(
        work_dir / "inventory.json",
        (json.dumps(rendered, separators=(",", ":")) + "\n").encode(),
    )
    return {
        "result": "prepared",
        "postgres_members": sorted(members),
        "postgres_dcs_only": sorted(voters),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.work_dir, args.ssh_key), separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print("Database HA input preparation failed; no host was changed.", file=sys.stderr)
        sys.exit(1)
