#!/usr/bin/env python3
"""Verify a short-lived private-realm owner token without exposing its value."""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


BOOTSTRAP = Path("/etc/heteronetwork/public-services/bootstrap.env")
PREFIX = "HETERONETWORK_PUBLIC_SERVICES_"
MAX_RESPONSE = 4 * 1024 * 1024


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise RuntimeError("identity endpoint redirected")


def read_regular(path, uid, *, mode_mask, max_size):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_mode & mode_mask or not 0 < info.st_size <= max_size):
            raise ValueError("unsafe proof or bootstrap file")
        return stream.read()


def bootstrap_values(raw):
    wanted = {"VPN_POOL", "OIDC_REQUIRED_EMAIL"}
    result = {}
    for line in raw.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        for name in wanted:
            if key == PREFIX + name + "_B64":
                if name in result:
                    raise ValueError("duplicate bootstrap identity field")
                result[name] = base64.b64decode(value, validate=True).decode("utf-8").strip()
    if set(result) != wanted:
        raise ValueError("bootstrap identity fields are missing")
    pool = ipaddress.ip_network(result["VPN_POOL"], strict=False)
    email = result["OIDC_REQUIRED_EMAIL"].lower()
    if pool.version != 4 or not re.fullmatch(r"[^\s@,]+@[^\s@,]+", email):
        raise ValueError("bootstrap identity fields are invalid")
    return pool, email


def read_proof(path, expected_uid, *, check_location=True):
    path = Path(path)
    if check_location:
        if (path.name != "token" or path.parent.parent != Path("/tmp")
                or not re.fullmatch(r"hnn-private-owner-[A-Za-z0-9_-]+", path.parent.name)):
            raise ValueError("proof path is not an isolated temporary file")
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != expected_uid
                or parent.st_mode & 0o077):
            raise ValueError("unsafe proof directory")
    token = read_regular(path, expected_uid, mode_mask=0o077, max_size=16384).decode("utf-8").strip()
    if not token or any(character.isspace() for character in token):
        raise ValueError("invalid proof token")
    return token


def validate_claims(token, expected_issuer, now=None):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("owner proof is not a JWT")
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("owner proof has invalid claims") from error
    now = time.time() if now is None else now
    if (not isinstance(payload, dict) or payload.get("iss") != expected_issuer
            or payload.get("azp") != "ipars-web" or not isinstance(payload.get("sub"), str)
            or not payload["sub"] or not isinstance(payload.get("exp"), (int, float))
            or payload["exp"] <= now + 30):
        raise ValueError("owner proof has the wrong issuer, client, subject or lifetime")
    return payload


def identity_origin(value):
    origin = urlsplit(value)
    if (origin.scheme not in ("http", "https") or not origin.hostname
            or not origin.hostname.endswith(".heteronetwork.internal") or origin.port is None
            or origin.username is not None or origin.password is not None
            or origin.path not in ("", "/") or origin.query or origin.fragment):
        raise ValueError("identity origin must be the managed private issuer")
    return value.rstrip("/")


def request_json(opener, url, token, host=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    if host:
        headers["Host"] = host
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=10) as response:
            raw = response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        raise RuntimeError("private authentication returned HTTP " + str(error.code)) from None
    except urllib.error.URLError:
        raise RuntimeError("private authentication endpoint is unavailable") from None
    if len(raw) > MAX_RESPONSE:
        raise ValueError("private authentication response is too large")
    return json.loads(raw)


def verify(token, expected_issuer, email, pool, control_planes=(), *, opener=None):
    claims = validate_claims(token, expected_issuer)
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirects())
    issuer = urlsplit(expected_issuer)
    userinfo = request_json(opener,
        f"http://127.0.0.1:{issuer.port}/realms/heteronetwork/protocol/openid-connect/userinfo",
        token, issuer.netloc)
    if (userinfo.get("sub") != claims["sub"]
            or (userinfo.get("email") or "").lower() != email):
        raise ValueError("private proof does not belong to the configured owner")
    for raw in control_planes:
        address = ipaddress.ip_address(raw)
        if address.version != 4 or address not in pool:
            raise ValueError("control-plane proof target must be a VPN address")
        response = request_json(opener, f"http://{address}:19088/v1/admin/policy", token)
        if not isinstance(response, dict) or not isinstance(response.get("cluster_policy"), dict):
            raise RuntimeError("control plane did not confirm owner authorization")
    return len(control_planes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--identity-origin", required=True)
    parser.add_argument("--proof-owner", default=os.environ.get("HNN_IAC_SSH_USER", "mizuame"))
    parser.add_argument("--control-plane", action="append", default=[])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("must run as root")
    try:
        origin = identity_origin(args.identity_origin)
        uid = pwd.getpwnam(args.proof_owner).pw_uid
        token = read_proof(args.token_file, uid)
        pool, email = bootstrap_values(read_regular(BOOTSTRAP, 0, mode_mask=0o077, max_size=131072))
        count = verify(token, origin + "/realms/heteronetwork", email, pool, args.control_plane)
        print(json.dumps({"verified": True, "control_planes": count}))
        return 0
    except (OSError, KeyError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print("private owner proof failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
