#!/usr/bin/env python3
"""Explicit identity-foundation apply, guarded by the observed dedicated dev cluster."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path("/opt/heteronetwork-dev-identity")
UID = "a39281cb-d273-4c5f-b7a7-fca722fb417b"
FILES = {"operator": "operator.json", "storage": "storage.yaml",
         "network": "network-policy.yaml", "database": "postgres.yaml"}
KUBE = ["/usr/bin/kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "--request-timeout=30s"]


def require(condition):
    if not condition:
        raise ValueError("DEV identity apply prerequisite failed")


def run(arguments, data=None):
    process = subprocess.Popen([*KUBE, *arguments], stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
                               env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    output, pending = bytearray(), memoryview(data or b"")
    deadline = time.monotonic() + 120
    try:
        with selectors.DefaultSelector() as selector:
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            if process.stdin is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            while selector.get_map():
                left = deadline - time.monotonic()
                require(left > 0)
                for key, _ in selector.select(left):
                    if key.fileobj is process.stdout:
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(chunk)
                            require(len(output) <= 2 * 1024 * 1024)
                    else:
                        pending = pending[os.write(key.fd, pending[:4096]):]
                        if not pending:
                            selector.unregister(key.fileobj)
                            process.stdin.close()
            require(process.wait(timeout=max(0.001, deadline - time.monotonic())) == 0)
        return bytes(output)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        process.stdout.close()
        if process.stdin is not None:
            process.stdin.close()


def trusted_file(path, maximum):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o022 and info.st_size <= maximum)
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum)
    return raw


def guard():
    require(os.getuid() == 0 and os.geteuid() == 0 and socket.gethostname() == "hetero-dev-1")
    require(Path("/etc/machine-id").read_text().strip() == "381d1ae16f555c59b738d8d01dd14c94")
    namespace = json.loads(run(["get", "namespace", "kube-system", "-o", "json"]))
    require(namespace["metadata"]["uid"] == UID)
    nodes = json.loads(run(["get", "nodes", "-o", "json"]))["items"]
    require(len(nodes) == 3 and {n["metadata"]["name"] for n in nodes} ==
            {f"hetero-dev-{i}" for i in range(1, 4)})
    for node in nodes:
        number = int(node["metadata"]["name"][-1])
        require([a["address"] for a in node["status"]["addresses"] if a["type"] == "InternalIP"] ==
                [f"10.251.0.{number}"])
        require(any(c["type"] == "Ready" and c["status"] == "True" for c in node["status"]["conditions"]))
    service = json.loads(run(["get", "service", "kubernetes", "-n", "default", "-o", "json"]))
    require(service["spec"]["clusterIP"] == "172.30.0.1")
    slices = json.loads(run(["get", "endpointslices", "-n", "default", "-l",
                            "kubernetes.io/service-name=kubernetes", "-o", "json"]))["items"]
    require({address for item in slices for endpoint in item["endpoints"] for address in endpoint["addresses"]}
            == {f"10.251.0.{i}" for i in range(1, 4)})
    require(bool(slices) and all(item["ports"] for item in slices))
    require(all(port["port"] == 6443 and port["protocol"] == "TCP" for item in slices for port in item["ports"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=tuple(FILES))
    args = parser.parse_args()
    try:
        guard()
        lock = json.loads(trusted_file(ROOT / "delivery.json", 4096))
        require(set(lock) == set(FILES.values()))
        raw = trusted_file(ROOT / FILES[args.phase], 4 * 1024 * 1024)
        require(hashlib.sha256(raw).hexdigest() == lock[FILES[args.phase]])
        command = ["apply", "--server-side", "--field-manager=hetero-dev-identity"]
        if args.phase in ("operator", "storage"):
            document = json.loads(raw)
            namespaces = [item for item in document["items"] if item["kind"] == "Namespace"]
            require(len(namespaces) == 1 and namespaces[0]["metadata"]["name"] ==
                    ("cnpg-system" if args.phase == "operator" else "hetero-dev-identity"))
            # Server dry-run of namespaced objects needs their namespace to exist.
            namespace = json.dumps(namespaces[0]).encode()
            run([*command, "--dry-run=server", "-f", "-"], namespace)
            run([*command, "-f", "-"], namespace)
        run([*command, "--dry-run=server", "-f", "-"], raw)
        output = run([*command, "-f", "-"], raw)
        print(json.dumps({"cluster_uid": UID, "phase": args.phase, "applied": True,
                          "resources": output.decode().splitlines(), "readiness_verified": False}))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("DEV identity apply stopped; inspect cluster events and preserve existing resources", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
