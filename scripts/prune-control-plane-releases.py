#!/usr/bin/env python3
"""Remove unreferenced, old control-plane binaries while preserving the pinned release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time


DIGEST = re.compile(r"^[0-9a-f]{64}$")


def safe_root(root):
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("release root is not a protected directory")


def references(root):
    """Protect binaries referenced by processes or any systemd unit/drop-in."""
    pattern = re.compile(re.escape(str(root)) + r"/([0-9a-f]{64})/")
    protected = set()
    for unit_root in (Path("/etc/systemd/system"), Path("/run/systemd/system"), Path("/usr/lib/systemd/system")):
        if not unit_root.exists():
            continue
        for path in unit_root.rglob("*"):
            if path.suffix not in (".service", ".conf") or not path.is_file():
                continue
            if path.stat().st_size > 2_000_000:
                raise ValueError("unexpectedly large systemd unit")
            protected.update(pattern.findall(path.read_text(errors="replace")))
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            executable = os.readlink(process / "exe")
            protected.update(pattern.findall(executable))
            command = (process / "cmdline").read_bytes().decode(errors="replace")
            protected.update(pattern.findall(command))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return protected


def candidates(root, active, protected, now):
    if not DIGEST.fullmatch(active):
        raise ValueError("invalid pinned digest")
    safe_root(root)
    active_file = root / active / "iparsd"
    if not active_file.is_file() or active_file.is_symlink():
        raise ValueError("pinned control-plane executable is missing")
    with active_file.open("rb") as source:
        if hashlib.file_digest(source, "sha256").hexdigest() != active:
            raise ValueError("pinned control-plane executable digest mismatch")
    result = []
    for directory in root.iterdir():
        if not DIGEST.fullmatch(directory.name) or directory.name in protected or directory.name == active:
            continue
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            continue
        if now - info.st_mtime < 86400:
            continue
        entries = list(directory.iterdir())
        if len(entries) != 1 or entries[0].name != "iparsd":
            continue
        binary = entries[0].lstat()
        if stat.S_ISREG(binary.st_mode) and binary.st_uid == 0 and not binary.st_mode & 0o022:
            result.append(directory.name)
    return sorted(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/opt/heteronetwork/control-plane-releases"))
    parser.add_argument("--active-digest", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.root
    before = candidates(root, args.active_digest, references(root), time.time())
    removed = []
    if args.apply:
        # Re-evaluate references before each unlink; a newly deployed binary is
        # protected by the minimum age and the pinned digest remains untouched.
        for digest in before:
            if digest not in candidates(root, args.active_digest, references(root), time.time()):
                continue
            binary = root / digest / "iparsd"
            binary.unlink()
            binary.parent.rmdir()
            removed.append(digest)
    print(json.dumps({"eligible": len(before), "removed": len(removed), "applied": args.apply}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"release cleanup failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
