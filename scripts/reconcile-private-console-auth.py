#!/usr/bin/env python3
"""Reconcile the HeteroNetwork owner console onto its private OIDC realm."""

import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from urllib.parse import urlsplit


PREFIX = "HETERONETWORK_PUBLIC_SERVICES_"
BOOTSTRAP = Path("/etc/heteronetwork/public-services/bootstrap.env")
REALM_PATH = "/realms/heteronetwork"
FIELDS = (
    "VPN_POOL", "OIDC_CLIENT_ID", "OIDC_ISSUER_URL", "OIDC_REQUIRED_EMAIL",
    "OIDC_AUTH_BASE_URL", "OIDC_BACKCHANNEL_BASE_URL", "OIDC_BACKCHANNEL_FALLBACK_BASE_URLS",
    "OIDC_DEVICE_VERIFICATION_ORIGIN",
)


def decode(value):
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid managed authentication value") from error


def parse(content):
    try:
        text = content.decode("utf-8")
    except UnicodeError as error:
        raise ValueError("bootstrap configuration is not UTF-8") from error
    found = {}
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        for field in FIELDS:
            if separator and key == PREFIX + field + "_B64":
                if field in found:
                    raise ValueError("duplicate managed authentication field")
                found[field] = decode(value)
    return text, found


def private_origin(value):
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid private identity origin") from error
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or not parsed.hostname.endswith(".heteronetwork.internal")
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or port is None or port == 0):
        raise ValueError("identity origin must be an internal HeteroNetwork origin with a port")
    return value.rstrip("/")


def desired_content(content, identity_origin, fallback_ips):
    text, fields = parse(content)
    identity_origin = private_origin(identity_origin)
    if fields.get("OIDC_CLIENT_ID") != "ipars-web" or not fields.get("OIDC_REQUIRED_EMAIL"):
        raise ValueError("existing owner and HeteroNetwork client must be configured")
    try:
        pool = ipaddress.ip_network(fields["VPN_POOL"], strict=False)
    except (KeyError, ValueError) as error:
        raise ValueError("configured VPN pool is invalid") from error
    if pool.version != 4:
        raise ValueError("configured VPN pool must be IPv4")
    addresses = []
    for raw in fallback_ips:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as error:
            raise ValueError("identity fallback is not an IP address") from error
        if address.version != 4 or address not in pool or str(address) in addresses:
            raise ValueError("identity fallbacks must be unique VPN addresses")
        addresses.append(str(address))
    if not addresses:
        raise ValueError("at least one identity fallback is required")
    desired_issuer = identity_origin + REALM_PATH
    current = fields.get("OIDC_ISSUER_URL", "")
    parsed = urlsplit(current)
    if current != desired_issuer and not (
        parsed.scheme == "https" and parsed.hostname and parsed.username is None
        and parsed.password is None and not parsed.query and not parsed.fragment
        and parsed.path.rstrip("/").endswith("/realms/heterocloud")
    ):
        raise ValueError("refusing to replace an unrecognized owner issuer")
    port = urlsplit(identity_origin).port
    desired = {
        "OIDC_ISSUER_URL": desired_issuer,
        "OIDC_AUTH_BASE_URL": desired_issuer,
        "OIDC_BACKCHANNEL_BASE_URL": f"http://127.0.0.1:{port}{REALM_PATH}",
        "OIDC_BACKCHANNEL_FALLBACK_BASE_URLS": ",".join(
            f"http://{address}:{port}{REALM_PATH}" for address in addresses),
        "OIDC_DEVICE_VERIFICATION_ORIGIN": identity_origin,
    }
    encoded = {PREFIX + key + "_B64": base64.b64encode(value.encode()).decode()
               for key, value in desired.items()}
    lines, seen = [], set()
    for line in text.splitlines(keepends=True):
        key, separator, _ = line.partition("=")
        if separator and key in encoded:
            ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            lines.append(key + "=" + encoded[key] + ending)
            seen.add(key)
        else:
            lines.append(line)
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += "\n"
    lines.extend(key + "=" + value + "\n" for key, value in encoded.items() if key not in seen)
    return "".join(lines).encode("utf-8")


def read_private(path, *, expected_uid=0):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_nlink != 1
                or info.st_mode & 0o077 or not 0 < info.st_size <= 131072):
            raise ValueError("unsafe bootstrap configuration")
        return stream.read(), info


def reconcile(path, identity_origin, fallback_ips, *, check=False, expected_uid=0):
    original, info = read_private(path, expected_uid=expected_uid)
    updated = desired_content(original, identity_origin, fallback_ips)
    if updated == original:
        return False
    if check:
        return True
    descriptor, temporary = tempfile.mkstemp(prefix=".private-console-auth-", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, info.st_uid, info.st_gid)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        current, _ = read_private(path, expected_uid=expected_uid)
        if current != original:
            raise RuntimeError("bootstrap configuration changed concurrently")
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-origin", required=True)
    parser.add_argument("--fallback", action="append", default=[])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("must run as root")
    try:
        changed = reconcile(BOOTSTRAP, args.identity_origin, args.fallback, check=args.check)
        print(json.dumps({"changed": changed}))
        return 2 if changed and args.check else 0
    except (OSError, ValueError, RuntimeError) as error:
        print("private console authentication setup failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
