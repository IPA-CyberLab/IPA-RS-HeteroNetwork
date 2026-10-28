#!/usr/bin/env python3
"""Manage HTTP-only Cloudflare VPN members without secrets in URLs or argv."""
import argparse
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "ready", "stop"])
    parser.add_argument("name")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args()
    origin = urllib.parse.urlsplit(args.origin)
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.query or origin.fragment or origin.path not in ("", "/")
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", args.name)):
        parser.error("Provide an HTTPS origin and a valid instance name")
    try:
        with args.token_file.open() as source:
            value = source.read(65537)
        if len(value) > 65536:
            raise ValueError()
        token = json.loads(value)["MANAGEMENT_TOKEN"] if value.lstrip().startswith("{") else value.strip()
        if not isinstance(token, str) or len(token) < 32 or "\n" in token or "\r" in token:
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        parser.error("Token file must contain a management token or a Wrangler secrets JSON object")
    method = {"start": "PUT", "ready": "GET", "stop": "DELETE"}[args.action]
    request = urllib.request.Request(args.origin.rstrip("/") + "/nodes/" + args.name, method=method,
                                     headers={"Authorization": "Bearer " + token,
                                              "User-Agent": "HeteroNetwork-Cloudflare-Management/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            status = response.status
            response.read(4096)
    except urllib.error.HTTPError as error:
        status = error.code
    except (OSError, urllib.error.URLError):
        print(json.dumps({"name": args.name, "action": args.action, "error": "connection_failed"}))
        return 1
    print(json.dumps({"name": args.name, "action": args.action, "status": status}))
    return 0 if status == 204 else 1


if __name__ == "__main__":
    raise SystemExit(main())
