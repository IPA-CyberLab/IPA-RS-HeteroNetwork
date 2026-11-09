#!/usr/bin/env python3
"""Set RPS on one verified NIC, without resetting it or changing IRQ affinity."""
import argparse
import json
from pathlib import Path
import re
import socket


def mask_value(value):
    if not re.fullmatch(r"[0-9a-fA-F]{1,8}(?:,[0-9a-fA-F]{8})*", value):
        raise ValueError("invalid CPU mask")
    return int(value.replace(",", ""), 16)


def cpus(value):
    result = set()
    for item in value.split(","):
        match = re.fullmatch(r"(\d+)(?:-(\d+))?", item)
        if not match:
            raise ValueError("invalid online CPU list")
        first = int(match.group(1))
        last = int(match.group(2) or first)
        if first > last or last > 4095:
            raise ValueError("invalid online CPU range")
        result.update(range(first, last + 1))
    return result


def reconcile(config, sysfs=Path("/sys"), hostname=None):
    if set(config) != {"node", "interface", "driver", "online_cpus", "queues", "rps_cpus"}:
        raise ValueError("invalid receive-steering configuration")
    for key in ("node", "interface", "driver"):
        if not isinstance(config[key], str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,63}", config[key]):
            raise ValueError("invalid host or interface identity")
    if (hostname or socket.gethostname()) != config["node"]:
        raise ValueError("host identity does not match")
    if not isinstance(config["queues"], int) or isinstance(config["queues"], bool) or not 1 <= config["queues"] <= 128:
        raise ValueError("invalid queue count")
    root = Path(sysfs)
    online = (root / "devices/system/cpu/online").read_text().strip()
    if online != config["online_cpus"]:
        raise ValueError("online CPU topology changed")
    available = cpus(online)
    desired = mask_value(config["rps_cpus"])
    if not desired or any((desired >> cpu) & 1 and cpu not in available for cpu in range(desired.bit_length())):
        raise ValueError("CPU mask includes no CPUs or offline CPUs")
    interface = root / "class/net" / config["interface"]
    if (interface / "device/driver").resolve(strict=True).name != config["driver"]:
        raise ValueError("NIC driver does not match")
    queues = sorted((interface / "queues").glob("rx-*/rps_cpus"))
    if len(queues) != config["queues"]:
        raise ValueError("receive queue count changed")
    previous = [path.read_text().strip() for path in queues]
    # Refuse to silently replace a different administrator's RPS policy.
    if any(mask_value(value) not in (0, desired) for value in previous):
        raise ValueError("an unrelated receive-steering policy is already installed")
    changed = [i for i, value in enumerate(previous) if mask_value(value) != desired]
    written = []
    try:
        for index in changed:
            written.append(index)
            queues[index].write_text(config["rps_cpus"])
        if any(mask_value(path.read_text().strip()) != desired for path in queues):
            raise RuntimeError("receive-steering verification failed")
    except BaseException:
        for index in reversed(written):
            queues[index].write_text(previous[index])
        raise
    return {"changed": bool(changed), "interface": config["interface"], "queues": len(queues),
            "rps_cpus": config["rps_cpus"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(reconcile(json.loads(args.config.read_text()))))


if __name__ == "__main__":
    main()
