#!/usr/bin/env python3
"""Install an external S3 destination from an owned 0600 file, without logging secrets.

Only paths are accepted as arguments. Credentials and the catalog key do not
enter Terraform state or process arguments. The existing key is never rotated
implicitly because committed recovery catalogs depend on it.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import urllib.parse


def configuration(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Destination configuration requires an owned regular 0600 file")
    value = json.loads(path.read_text())
    if set(value) - {"endpoint", "bucket", "region", "access_key", "secret_key"}:
        raise ValueError("Unexpected destination configuration fields")
    endpoint = urllib.parse.urlsplit(value["endpoint"])
    if endpoint.scheme != "https" or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment or endpoint.path not in ("", "/") or not endpoint.hostname:
        raise ValueError("Destination requires an HTTPS S3 origin")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value["bucket"]):
        raise ValueError("Invalid destination bucket")
    for name in ("access_key", "secret_key"):
        if not isinstance(value.get(name), str) or not 8 <= len(value[name]) <= 512:
            raise ValueError("Destination credential is missing or invalid")
    value.setdefault("region", "auto")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-file", type=Path, required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--kubectl", default="kubectl")
    parser.add_argument("--recovery-key-file", type=Path, required=True)
    parser.add_argument("--namespace", default="heterocloud-flash")
    args = parser.parse_args()
    config = configuration(args.config_file)
    command = [args.kubectl, "--kubeconfig="+args.kubeconfig, "-n", args.namespace]

    def kube(*parts, body=None):
        response = subprocess.run(command+list(parts), input=json.dumps(body) if body else None,
                                  capture_output=True, text=True, timeout=30)
        if response.returncode:
            raise RuntimeError("Protected Kubernetes configuration operation failed")
        return json.loads(response.stdout) if response.stdout.strip() else None

    source = kube("get", "secret", "flash-backup-export-source", "-o", "json")
    primary = json.loads(base64.b64decode(source["data"]["config.json"]))
    if (primary["endpoint"].rstrip('/'), primary["bucket"]) == (config["endpoint"].rstrip('/'), config["bucket"]):
        raise ValueError("Destination must be independent of the primary backup bucket")
    current = kube("get", "secret", "flash-backup-offsite", "--ignore-not-found=true", "-o", "json")
    key = base64.b64decode(current["data"]["catalog.key"]) if current else secrets.token_bytes(32)
    if len(key) < 32:
        raise ValueError("Existing catalog signing key is invalid")
    # Write the recovery key BEFORE publishing the Secret. Refuse to overwrite
    # a mismatched recovery file or follow symlinks.
    if args.recovery_key_file.exists():
        info = args.recovery_key_file.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or args.recovery_key_file.read_bytes() != key:
            raise ValueError("Existing protected recovery key differs")
    else:
        descriptor = os.open(args.recovery_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(key)
            output.flush()
            os.fsync(output.fileno())
    kube("apply", "--server-side", "--field-manager=flash-offsite-iac", "-f", "-", "-o", "json",
         body={"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
               "metadata": {"name": "flash-backup-offsite", "namespace": args.namespace},
               "data": {"config.json": base64.b64encode(json.dumps(config).encode()).decode(),
                        "catalog.key": base64.b64encode(key).decode()}})
    print(json.dumps({"configured": True, "catalog_key_preserved": True,
                      "credentials_in_state_or_arguments": False}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError):
        raise SystemExit("External backup configuration failed; check the protected files and Kubernetes access") from None
