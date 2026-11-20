#!/usr/bin/env python3
"""Sign in through the private realm and retain a short-lived local proof."""

import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlsplit
import urllib.error
import urllib.request


def helpers():
    path = Path(__file__).with_name("verify-private-owner-proof.py")
    spec = importlib.util.spec_from_file_location("private_owner_proof", path)
    if not spec or not spec.loader:
        raise RuntimeError("private proof verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gateway_origin(value):
    parsed = urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as error:
        raise ValueError("identity gateway must be a private IP origin") from error
    if (parsed.scheme != "http" or address.version != 4 or not (address.is_private or address.is_loopback)
            or port is None or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("identity gateway must be a private IP origin")
    return value.rstrip("/")


def validate_start(data, issuer):
    expected = issuer + "/device"
    if (not isinstance(data, dict) or data.get("verification_uri") != expected
            or not isinstance(data.get("device_code"), str) or not 32 <= len(data["device_code"]) <= 16384
            or not isinstance(data.get("user_code"), str)
            or not re.fullmatch(r"[A-Z0-9-]{3,128}", data["user_code"])
            or not isinstance(data.get("expires_in"), int) or not 30 <= data["expires_in"] <= 600
            or not isinstance(data.get("interval"), int) or not 1 <= data["interval"] <= 30):
        raise ValueError("private identity provider returned invalid device authorization")
    complete = urlsplit(data.get("verification_uri_complete") or "")
    verification = urlsplit(expected)
    if (complete.scheme, complete.netloc, complete.path) != (verification.scheme, verification.netloc, verification.path):
        raise ValueError("private identity provider returned an unexpected verification URL")
    if complete.fragment or parse_qs(complete.query, strict_parsing=True) != {"user_code": [data["user_code"]]}:
        raise ValueError("private identity provider returned an invalid verification code")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", required=True)
    parser.add_argument("--identity-origin", required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run as the unprivileged operator account")
    try:
        proof = helpers()
        origin = proof.identity_origin(args.identity_origin)
        gateway = gateway_origin(args.gateway)
        issuer = origin + "/realms/heteronetwork"
        base = gateway + "/realms/heteronetwork"
        host = urlsplit(origin).netloc
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), proof.NoRedirects())
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode().rstrip("=")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")

        def post(path, fields):
            request = urllib.request.Request(base + path, data=urlencode(fields).encode(),
                headers={"Host": host, "Content-Type": "application/x-www-form-urlencoded"})
            with opener.open(request, timeout=10) as response:
                raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError("private identity response is too large")
            return json.loads(raw)

        authorization = post("/protocol/openid-connect/auth/device", {
            "client_id": "ipars-web", "scope": "openid profile email", "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        validate_start(authorization, issuer)
        print(json.dumps({key: authorization[key] for key in
                          ("verification_uri", "verification_uri_complete", "user_code", "expires_in")}), flush=True)
        deadline = time.monotonic() + authorization["expires_in"]
        interval = max(5, authorization["interval"])
        while time.monotonic() < deadline:
            time.sleep(interval)
            try:
                result = post("/protocol/openid-connect/token", {
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "client_id": "ipars-web",
                    "device_code": authorization["device_code"], "code_verifier": verifier,
                })
            except urllib.error.HTTPError as error:
                try:
                    code = json.load(error).get("error")
                except (ValueError, UnicodeError):
                    code = None
                if code == "authorization_pending":
                    continue
                if code == "slow_down":
                    interval += 5
                    continue
                raise RuntimeError("private device authorization was not completed") from None
            token = result.get("access_token")
            if not isinstance(token, str) or not token or len(token) > 16384 or any(c.isspace() for c in token):
                raise ValueError("private identity provider returned an invalid token")
            proof.validate_claims(token, issuer)
            directory = Path(tempfile.mkdtemp(prefix="hnn-private-owner-", dir="/tmp"))
            path = directory / "token"
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as output:
                    output.write(token)
            except BaseException:
                if path.exists():
                    path.unlink()
                directory.rmdir()
                raise
            print(json.dumps({"proof_file": str(path), "expires_at": proof.validate_claims(token, issuer)["exp"]}), flush=True)
            return 0
        raise RuntimeError("private device authorization expired")
    except (OSError, ValueError, RuntimeError, urllib.error.URLError, json.JSONDecodeError) as error:
        print("private device sign-in failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
