#!/usr/bin/env python3
"""Grow an existing root LV online using only free extents in its current VG."""
import argparse
from decimal import Decimal
import json
import os
from pathlib import Path
import socket
import subprocess

GIB = 1024 ** 3


def plan(policy, state):
    if state["filesystem"] != policy["filesystem"] or policy["filesystem"] != "ext4":
        raise ValueError("Root filesystem does not match the declared ext4 filesystem")
    if state["logical_volume"] != policy["logical_volume"]:
        raise ValueError("Root mount does not use the declared existing logical volume")
    target = policy["size_gib"] * GIB
    if target < state["lv_bytes"]:
        raise ValueError("Shrinking root storage is prohibited")
    delta = target - state["lv_bytes"]
    if delta > state["vg_free_bytes"]:
        raise ValueError("The existing volume group has insufficient unused extents")
    return {"target_bytes": target, "grow_bytes": delta, "filesystem_resize": state["filesystem_bytes"] < target * 0.95}


def output(command):
    result = subprocess.run(command, check=True, text=True, capture_output=True, timeout=120)
    return result.stdout


def inspect(logical_volume):
    mount = json.loads(output(["findmnt", "-J", "-o", "SOURCE,FSTYPE", "/"]))["filesystems"][0]
    if Path(mount["source"]).resolve() != Path(logical_volume).resolve():
        raise ValueError("Declared volume is not the mounted root filesystem")
    lv = json.loads(output(["lvs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "lv_size,vg_name", logical_volume]))["report"][0]["lv"][0]
    vg = json.loads(output(["vgs", "--reportformat", "json", "--units", "b", "--nosuffix", "-o", "vg_free", lv["vg_name"]]))["report"][0]["vg"][0]
    filesystem = os.statvfs("/")
    return {"logical_volume": logical_volume, "filesystem": mount["fstype"], "lv_bytes": int(Decimal(lv["lv_size"])), "vg_free_bytes": int(Decimal(vg["vg_free"])), "filesystem_bytes": filesystem.f_blocks * filesystem.f_frsize, "available_bytes": filesystem.f_bavail * filesystem.f_frsize}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if socket.gethostname().split(".")[0] != args.node:
        raise ValueError("Requested node does not match the local host")
    policy = json.loads(args.policy.read_text())["nodes"].get(args.node)
    if policy is None:
        print(json.dumps({"node": args.node, "changed": False, "managed": False}))
        return
    before = inspect(policy["logical_volume"])
    change = plan(policy, before)
    changed = False
    if args.apply:
        if change["grow_bytes"]:
            output(["lvextend", "-L", str(change["target_bytes"]) + "B", policy["logical_volume"]])
            changed = True
        if change["grow_bytes"] or change["filesystem_resize"]:
            output(["resize2fs", policy["logical_volume"]])
            changed = True
    after = inspect(policy["logical_volume"]) if args.apply else before
    if args.apply:
        assert after["lv_bytes"] == change["target_bytes"]
        assert not plan(policy, after)["filesystem_resize"]
    print(json.dumps({"node": args.node, "changed": changed, "apply": args.apply, "before": before, "plan": change, "after": after}))


if __name__ == "__main__":
    main()
