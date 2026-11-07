#!/usr/bin/env python3
"""Create the shared Flash SSH host key once without placing it in Git or state."""
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile

NAMESPACE = "heterocloud"
NAME = "heterocloud-flash-ssh-host"


def kubectl(*args, data=None):
    return subprocess.run(["kubectl", *args], input=data, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)


def read_existing():
    result = kubectl("-n", NAMESPACE, "get", "secret", NAME, "-o", "json", "--ignore-not-found")
    if result.returncode:
        raise RuntimeError("Unable to inspect the Flash SSH host-key Secret")
    if not result.stdout.strip():
        return None
    value = json.loads(result.stdout)
    try:
        key = base64.b64decode(value["data"]["host-key"], validate=True)
    except (KeyError, ValueError) as error:
        raise RuntimeError("The existing Flash SSH host-key Secret is invalid; refusing to replace it") from error
    if not key.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n") or len(key) > 16384:
        raise RuntimeError("The existing Flash SSH host-key Secret is invalid; refusing to replace it")
    return key


def main():
    namespace = kubectl("get", "namespace", NAMESPACE, "-o", "name", "--ignore-not-found")
    if namespace.returncode:
        raise RuntimeError("Unable to inspect the HeteroCloud namespace")
    if not namespace.stdout.strip():
        created = kubectl("create", "namespace", NAMESPACE)
        if created.returncode:
            current = kubectl("get", "namespace", NAMESPACE, "-o", "name", "--ignore-not-found")
            if current.returncode or not current.stdout.strip():
                raise RuntimeError("Unable to create the HeteroCloud namespace")
    existing = read_existing()
    with tempfile.TemporaryDirectory(prefix="heterocloud-ssh-host-") as directory:
        key_path = Path(directory) / "host-key"
        if existing is None:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            existing = key_path.read_bytes()
            secret = {"apiVersion":"v1", "kind":"Secret", "metadata":{"name":NAME,"namespace":NAMESPACE},
                      "type":"Opaque", "data":{"host-key":base64.b64encode(existing).decode("ascii")}}
            created = kubectl("create", "-f", "-", data=json.dumps(secret).encode())
            if created.returncode:
                # A concurrent creator may have won. Never overwrite its key.
                existing = read_existing()
                if existing is None:
                    raise RuntimeError("Unable to create the Flash SSH host-key Secret")
        key_path.write_bytes(existing)
        os.chmod(key_path, 0o600)
        public = subprocess.run(["ssh-keygen", "-y", "-f", str(key_path)], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=True).stdout
        if not public.startswith(b"ssh-ed25519 "):
            raise RuntimeError("The existing Flash SSH host key is not Ed25519; refusing to replace it")
        fingerprint = subprocess.run(["ssh-keygen", "-lf", "-", "-E", "sha256"], input=public,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout.decode().split()[1]
    print(json.dumps({"namespace":NAMESPACE,"name":NAME,"fingerprint":fingerprint}))


if __name__ == "__main__":
    main()
