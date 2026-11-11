#!/usr/bin/env python3
"""Remove one network registration using a short-lived, loopback-only admin API.

The database credential stays in its existing protected file; a random operator
token exists only in a private temporary directory for the lifetime of the
temporary daemon. The operator API performs the registration and path cleanup.
"""

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


NODE_ID = re.compile(r"node-[0-9a-f]{32}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_systemd_environment(path):
    values = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw = line.partition("=")
        require(separator and re.fullmatch(r"[A-Z][A-Z0-9_]*", key), "invalid service environment")
        words = shlex.split(raw, comments=True)
        require(len(words) <= 1, "invalid service environment value")
        if key.startswith("HETERONETWORK_"):
            values[key] = words[0] if words else ""
    return values


def request_json(base, token, method, path):
    request = urllib.request.Request(base + path, method=method,
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=10) as response:
        data = response.read(4 * 1024 * 1024 + 1)
    require(len(data) <= 4 * 1024 * 1024, "operator response is too large")
    return json.loads(data)


def retire(base, token, expected, apply, call=request_json):
    node_id = expected["node_id"]
    require(NODE_ID.fullmatch(node_id), "invalid node identity")
    nodes = call(base, token, "GET", "/v1/admin/nodes")
    require(isinstance(nodes, list), "unexpected node listing")
    records = [entry["node"] for entry in nodes]
    matches = [entry for entry in records if entry.get("node_id") == node_id]
    conflicting = [entry for entry in records if entry.get("node_id") != node_id and
                   (entry.get("hostname") == expected["hostname"] or
                    entry.get("vpn_ip") == expected["vpn_ip"])]
    require(not conflicting, "hostname or VPN address belongs to a different node")
    if not matches:
        return {"result": "already_absent", "node_id": node_id}
    require(len(matches) == 1, "node identity is ambiguous")
    target = matches[0]
    require(all(target.get(key) == expected[key] for key in ("hostname", "vpn_ip", "cluster_id")),
            "node identity does not match the approved inventory")
    if not apply:
        return {"result": "ready", "node_id": node_id}
    response = call(base, token, "DELETE", "/v1/admin/nodes/" + urllib.parse.quote(node_id, safe=""))
    require(response.get("node", {}).get("node_id") == node_id, "removed node identity mismatch")
    remaining = call(base, token, "GET", "/v1/admin/nodes")
    require(all(entry["node"].get("node_id") != node_id for entry in remaining),
            "node remains registered")
    return {"result": "removed", "node_id": node_id,
            "removed_path_count": response.get("removed_path_count", 0)}


def temporary_control_plane(binary, service_env, database_url_path, expected, apply):
    require(os.geteuid() == 0, "temporary operator requires root")
    require(binary.is_file() and os.access(binary, os.X_OK), "control-plane binary unavailable")
    info = database_url_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077,
            "database credential must be a root-owned private regular file")
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    env.update(read_systemd_environment(service_env))
    require(env.get("HETERONETWORK_CLUSTER_ID") == expected["cluster_id"], "cluster identity mismatch")
    with tempfile.TemporaryDirectory(prefix="hnn-node-retirement-") as directory:
        os.chmod(directory, 0o700)
        token = secrets.token_urlsafe(48)
        token_path = Path(directory) / "operator.token"
        token_path.write_text(token + "\n")
        token_path.chmod(0o600)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        env.update({
            "HETERONETWORK_LISTEN": f"127.0.0.1:{port}",
            "HETERONETWORK_DATABASE_URL_PATH": str(database_url_path),
            "HETERONETWORK_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN_PATH": str(token_path),
            "HETERONETWORK_WEB_UI_ENABLED": "false",
            "HETERONETWORK_NODE_ENROLLMENT_ENABLED": "false",
            "HETERONETWORK_DYNAMIC_WEB_GATEWAY_ENABLED": "false",
            "HETERONETWORK_SERVICE_INSTANCE_ID": "retire-" + secrets.token_hex(8),
        })
        env.pop("HETERONETWORK_DATABASE_URL", None)
        env.pop("HETERONETWORK_CONTROL_PLANE_OPERATOR_API_BEARER_TOKEN", None)
        base = f"http://127.0.0.1:{port}"
        process = subprocess.Popen([str(binary), "control-plane"], env=env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                require(process.poll() is None, "temporary control plane failed to start")
                try:
                    with urllib.request.urlopen(base + "/healthz", timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.2)
            else:
                raise ValueError("temporary control plane did not become ready")
            return retire(base, token, expected, apply)
        finally:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--vpn-ip", required=True)
    parser.add_argument("--cluster-id", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--service-env", type=Path, default=Path("/etc/heteronetwork/public-services/services.env"))
    parser.add_argument("--database-url-path", type=Path,
                        default=Path("/etc/heteronetwork/public-services/database-url"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    expected = {"node_id": args.node_id, "hostname": args.hostname,
                "vpn_ip": args.vpn_ip, "cluster_id": args.cluster_id}
    print(json.dumps(temporary_control_plane(args.binary, args.service_env, args.database_url_path,
                                             expected, args.apply), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError,
            urllib.error.URLError) as error:
        # Do not include request headers, credentials, or daemon environment.
        raise SystemExit(f"Network registration retirement failed: {type(error).__name__}")
