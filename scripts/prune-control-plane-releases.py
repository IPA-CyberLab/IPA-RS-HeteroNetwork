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
BACKUP = re.compile(r"^iparsd\.[0-9]+\.[0-9]{4}-[0-9]{2}-[0-9]{2}@[0-9]{2}:[0-9]{2}:[0-9]{2}~$")


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


def backup_references(root, unit_roots=None, process_root=Path("/proc")):
    """Protect backup files referenced by services, processes or local symlinks."""
    pattern = re.compile(re.escape(str(root)) + r"/(iparsd\.[0-9]+\.[0-9]{4}-[0-9]{2}-[0-9]{2}@[0-9]{2}:[0-9]{2}:[0-9]{2}~)")
    protected = set()
    for path in root.iterdir():
        if path.is_symlink():
            resolved = path.resolve()
            if resolved.parent == root and BACKUP.fullmatch(resolved.name):
                protected.add(resolved.name)
    if unit_roots is None:
        unit_roots = (Path("/etc/systemd/system"), Path("/run/systemd/system"), Path("/usr/lib/systemd/system"))
    for unit_root in unit_roots:
        if not unit_root.exists():
            continue
        for path in unit_root.rglob("*"):
            if path.suffix not in (".service", ".conf") or not path.is_file():
                continue
            if path.stat().st_size > 2_000_000:
                raise ValueError("unexpectedly large systemd unit")
            protected.update(pattern.findall(path.read_text(errors="replace")))
    for process in process_root.iterdir():
        if not process.name.isdigit():
            continue
        try:
            protected.update(pattern.findall(os.readlink(process / "exe")))
            protected.update(pattern.findall((process / "cmdline").read_bytes().decode(errors="replace")))
            for descriptor in (process / "fd").iterdir():
                try:
                    protected.update(pattern.findall(os.readlink(descriptor)))
                except (FileNotFoundError, ProcessLookupError):
                    continue
        except (FileNotFoundError, ProcessLookupError):
            continue
    return protected


def backup_candidates(root, protected, now):
    safe_root(root)
    result = []
    for path in root.iterdir():
        if not BACKUP.fullmatch(path.name) or path.name in protected:
            continue
        info = path.lstat()
        if (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and info.st_nlink == 1 and now - info.st_mtime >= 86400):
            result.append(path.name)
    return sorted(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/opt/heteronetwork/control-plane-releases"))
    parser.add_argument("--bin-root", type=Path, default=Path("/opt/heteronetwork/bin"))
    parser.add_argument("--active-digest", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.root
    before = candidates(root, args.active_digest, references(root), time.time())
    backups = backup_candidates(args.bin_root, backup_references(args.bin_root), time.time())
    removed = []
    removed_backups = []
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
        for name in backups:
            if name not in backup_candidates(args.bin_root, backup_references(args.bin_root), time.time()):
                continue
            (args.bin_root / name).unlink()
            removed_backups.append(name)
    print(json.dumps({"eligible": len(before) + len(backups), "removed": len(removed) + len(removed_backups),
                      "backups_removed": len(removed_backups), "applied": args.apply}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        print(f"release cleanup failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
