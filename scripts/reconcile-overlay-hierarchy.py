#!/usr/bin/env python3
"""Reconcile the declared hierarchy setting through the authenticated API."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("management endpoint redirected; refusing to forward credentials")


def endpoint_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise ValueError("management endpoint must be an HTTPS origin or a loopback HTTP origin")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1"):
        raise ValueError("cleartext management requests must use an SSH tunnel to loopback")
    return value.rstrip("/") + "/v1/admin/policy"


def read_token(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, encoding="utf-8") as token_file:
        info = os.fstat(token_file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("management token must be a private regular file owned by this user")
        token = token_file.read(16385).strip()
    if not token or len(token) > 16384 or any(c.isspace() for c in token):
        raise ValueError("management token is invalid")
    return token


def load_localities(config_path, roster_path):
    """Resolve explicitly managed hostnames; omitted nodes are left unchanged."""
    data = json.loads(Path(config_path).read_text(encoding="utf-8"))
    roster = json.loads(Path(roster_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"nodes", "remove"}:
        raise ValueError("localities must contain only nodes and remove")
    nodes, removed = data["nodes"], data["remove"]
    hosts = roster.get("hosts") if isinstance(roster, dict) else None
    if not isinstance(nodes, dict) or not isinstance(removed, list) or not isinstance(hosts, dict):
        raise ValueError("invalid localities or overlay roster")
    if any(not isinstance(name, str) or name not in hosts for name in list(nodes) + removed):
        raise ValueError("locality host is not in the declared overlay roster")
    if len(set(removed)) != len(removed) or set(removed) & set(nodes):
        raise ValueError("locality removals must be unique and separate from nodes")
    if (any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value)
            for value in hosts.values()) or len(set(hosts.values())) != len(hosts)):
        raise ValueError("invalid or duplicate node ID in overlay roster")
    desired = {}
    for name, locality in nodes.items():
        if not isinstance(locality, dict) or set(locality) != {"region", "zone"}:
            raise ValueError("each managed locality requires a region and zone")
        if any(not isinstance(value, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value)
               for value in locality.values()):
            raise ValueError("locality labels must be lowercase DNS labels of at most 63 characters")
        desired[hosts[name]] = locality
    return desired, {hosts[name] for name in removed}


def reconcile(config, endpoint, token, check=False, localities=None, removed=()):
    if set(config) != {"overlay_strict_hierarchy"} or not isinstance(config["overlay_strict_hierarchy"], bool):
        raise ValueError("hierarchy policy must contain only a boolean overlay_strict_hierarchy")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())

    def request(method, body=None):
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(endpoint_url(endpoint), data=body, headers=headers, method=method)
        try:
            with opener.open(req, timeout=15) as response:
                data = response.read(4 * 1024 * 1024 + 1)
                if len(data) > 4 * 1024 * 1024:
                    raise RuntimeError("management API response exceeds the size limit")
                return json.loads(data)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"management API returned HTTP {error.code}; no authorization bypass was attempted") from None
        except urllib.error.URLError:
            raise RuntimeError("management API could not be reached") from None

    response = request("GET")
    policy = response.get("cluster_policy") if isinstance(response, dict) else None
    if not isinstance(policy, dict):
        raise RuntimeError("management API returned an invalid policy")
    desired = config["overlay_strict_hierarchy"]
    existing = policy.get("overlay_node_localities", {})
    if not isinstance(existing, dict):
        raise RuntimeError("management API returned invalid node localities")
    merged = dict(existing)
    merged.update(localities or {})
    for node_id in removed:
        merged.pop(node_id, None)
    if policy.get("overlay_strict_hierarchy", False) == desired and merged == existing:
        return 0
    if check:
        return 2
    policy["overlay_strict_hierarchy"] = desired
    if merged != existing:
        policy["overlay_node_localities"] = merged
    response = request("PUT", json.dumps({"cluster_policy": policy}, separators=(",", ":")).encode())
    updated = response.get("cluster_policy") if isinstance(response, dict) else None
    if (not isinstance(updated, dict) or updated.get("overlay_strict_hierarchy", False) != desired
            or updated.get("overlay_node_localities", {}) != merged):
        raise RuntimeError("management API did not confirm the requested policy; inspect before retrying")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--localities")
    parser.add_argument("--roster")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--endpoint", default=os.environ.get("HNN_HIERARCHY_API_URL", "http://127.0.0.1:19088"))
    parser.add_argument("--token-file", default=os.environ.get("HNN_HIERARCHY_TOKEN_FILE"))
    args = parser.parse_args()
    if not args.token_file:
        parser.error("HNN_HIERARCHY_TOKEN_FILE must name a private owner OIDC token file")
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        if bool(args.localities) != bool(args.roster):
            raise ValueError("localities and roster must be supplied together")
        localities, removed = load_localities(args.localities, args.roster) if args.localities else ({}, set())
        code = reconcile(config, args.endpoint, read_token(args.token_file), args.check, localities, removed)
        print("hierarchy policy " + ("differs" if code == 2 else "matches"))
        return code
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"hierarchy policy: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
