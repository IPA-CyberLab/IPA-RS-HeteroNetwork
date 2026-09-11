#!/usr/bin/env python3
"""Obtain a short-lived owner token through the pinned Keycloak device flow."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


ISSUER = "https://heterocloud.mizuame.app/id/realms/heterocloud"
CLIENT_ID = "ipars-web"
OWNER_SUBJECT = "4daa569e-635c-49ed-bb17-5fe0a07581b2"
OWNER_EMAIL = "fasutotesuto@gmail.com"
MAX_RESPONSE = 1024 * 1024
PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")
USER_AGENT = "HeteroNetwork-Sudo-Owner/0.1"


def require(value, reason):
    if not value:
        raise ValueError(reason)


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def request(opener, url, data=None, token=None):
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if data is not None:
        data = urllib.parse.urlencode(data).encode("ascii")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    response = opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=15)
    require(response.status == 200, "unexpected_http_status")
    length = response.headers.get("Content-Length")
    require(length is None or int(length) <= MAX_RESPONSE, "response_too_large")
    raw = response.read(MAX_RESPONSE + 1)
    require(len(raw) <= MAX_RESPONSE, "response_too_large")
    return decode(raw)


def endpoint(value, issuer, name):
    require(isinstance(value, str) and value.startswith(issuer + "/"), "invalid_" + name)
    parsed = urllib.parse.urlsplit(value)
    expected = urllib.parse.urlsplit(issuer)
    require(parsed.scheme == "https" and parsed.netloc == expected.netloc
            and not parsed.username and not parsed.password and not parsed.fragment,
            "invalid_" + name)
    return value


def pkce_challenge(verifier):
    require(isinstance(verifier, str) and PKCE_VERIFIER.fullmatch(verifier),
            "invalid_pkce_verifier")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def new_pkce_pair():
    verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    return verifier, pkce_challenge(verifier)


def publish(path, raw):
    path = Path(path)
    require(path.is_absolute() and path.parent.is_dir(), "invalid_output_path")
    parent = path.parent.lstat()
    require(parent.st_uid == os.geteuid() and not parent.st_mode & 0o077,
            "unsafe_output_directory")
    if os.path.lexists(path):
        current = path.lstat()
        require(current.st_uid == os.geteuid() and current.st_nlink == 1
                and current.st_mode & 0o170000 == 0o100000
                and current.st_mode & 0o777 == 0o600, "unsafe_existing_token")
    temporary = path.parent / f".{path.name}.{os.getpid()}"
    require(not os.path.lexists(temporary), "stale_token_staging_file")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fchmod(output.fileno(), 0o600)
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def login(output):
    require(os.getuid() != 0 and os.getuid() == os.geteuid(), "run_as_nonroot_owner")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    discovery = request(opener, ISSUER + "/.well-known/openid-configuration")
    require(discovery.get("issuer") == ISSUER, "issuer_mismatch")
    device_url = endpoint(discovery.get("device_authorization_endpoint"), ISSUER, "device_endpoint")
    token_url = endpoint(discovery.get("token_endpoint"), ISSUER, "token_endpoint")
    userinfo_url = endpoint(discovery.get("userinfo_endpoint"), ISSUER, "userinfo_endpoint")
    code_verifier, code_challenge = new_pkce_pair()
    authorization = request(opener, device_url, {
        "client_id": CLIENT_ID,
        "scope": "openid profile email",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    })
    device_code = authorization.get("device_code")
    user_code = authorization.get("user_code")
    verification = authorization.get("verification_uri_complete") or authorization.get("verification_uri")
    require(isinstance(device_code, str) and 32 <= len(device_code) <= 4096,
            "invalid_device_code")
    require(isinstance(user_code, str) and 3 <= len(user_code) <= 128,
            "invalid_user_code")
    verification = endpoint(verification, ISSUER, "verification_uri")
    expires = int(authorization.get("expires_in", 0))
    interval = max(2, min(15, int(authorization.get("interval", 5))))
    require(30 <= expires <= 1800, "invalid_device_expiry")
    print(json.dumps({"verification_uri": verification, "user_code": user_code,
                      "expires_in": expires}, sort_keys=True), flush=True)
    deadline = time.monotonic() + expires
    token = None
    while time.monotonic() < deadline:
        time.sleep(interval)
        try:
            response = request(opener, token_url, {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": CLIENT_ID,
                "code_verifier": code_verifier,
            })
            token = response.get("access_token")
            require(isinstance(token, str) and 32 <= len(token) <= 65536,
                    "invalid_access_token")
            break
        except urllib.error.HTTPError as error:
            raw = error.read(MAX_RESPONSE + 1)
            require(len(raw) <= MAX_RESPONSE, "response_too_large")
            body = decode(raw)
            code = body.get("error")
            if code == "authorization_pending":
                continue
            if code == "slow_down":
                interval = min(20, interval + 5)
                continue
            raise ValueError("device_authorization_rejected") from None
    require(token is not None, "device_authorization_expired")
    identity = request(opener, userinfo_url, token=token)
    require(identity.get("sub") == OWNER_SUBJECT
            and str(identity.get("email", "")).lower() == OWNER_EMAIL
            and identity.get("email_verified") is True,
            "authenticated_identity_is_not_pinned_owner")
    publish(output, token.encode("utf-8"))
    print(json.dumps({"status": "owner_token_written", "path": str(output)}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=Path.home() / ".config/heteronetwork/sudo/owner.token")
    args = parser.parse_args()
    require(re.fullmatch(r"[A-Za-z0-9._/-]+", str(args.output)), "invalid_output_path")
    login(args.output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError,
            urllib.error.URLError, ssl.SSLError) as error:
        print(f"sudo owner login failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
