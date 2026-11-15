#!/usr/bin/env python3
"""Reconcile the declared hierarchy setting through the authenticated API."""
import argparse
import json
import os
from pathlib import Path
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


def reconcile(config, endpoint, token, check=False):
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
    if policy.get("overlay_strict_hierarchy", False) == desired:
        return 0
    if check:
        return 2
    policy["overlay_strict_hierarchy"] = desired
    response = request("PUT", json.dumps({"cluster_policy": policy}, separators=(",", ":")).encode())
    updated = response.get("cluster_policy") if isinstance(response, dict) else None
    if not isinstance(updated, dict) or updated.get("overlay_strict_hierarchy", False) != desired:
        raise RuntimeError("management API did not confirm the requested policy; inspect before retrying")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--endpoint", default=os.environ.get("HNN_HIERARCHY_API_URL", "http://127.0.0.1:19088"))
    parser.add_argument("--token-file", default=os.environ.get("HNN_HIERARCHY_TOKEN_FILE"))
    args = parser.parse_args()
    if not args.token_file:
        parser.error("HNN_HIERARCHY_TOKEN_FILE must name a private owner OIDC token file")
    try:
        config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        code = reconcile(config, args.endpoint, read_token(args.token_file), args.check)
        print("hierarchy policy " + ("differs" if code == 2 else "matches"))
        return code
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"hierarchy policy: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
