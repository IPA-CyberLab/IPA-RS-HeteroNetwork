#!/usr/bin/env python3
"""Sponsor and verify the release-installed macOS overlay client without logging secrets."""

import argparse
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import sys
import time
import urllib.request
from urllib.parse import parse_qs, urlsplit


CONSOLE_URL = "http://console.heteronetwork.internal:9781"
REMOTE_SPONSOR = r"""
import json
import subprocess
import sys

payload = json.load(sys.stdin)
result = subprocess.run(
    [
        "sudo", "-S", "-p", "", "--",
        "/opt/heteronetwork/bin/ipars", "client", "register", payload["request"],
    ],
    input=payload["password"] + "\n",
    capture_output=True,
    text=True,
    timeout=40,
)
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
raise SystemExit(result.returncode)
""".strip()


class LiveE2EError(RuntimeError):
    pass


def read_private(path, maximum_bytes):
    path = Path(path).expanduser()
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
        or metadata.st_size < 1
        or metadata.st_size > maximum_bytes
    ):
        raise LiveE2EError("private input failed type, ownership, mode, link, or size checks")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise LiveE2EError("private input changed while it was being opened")
        chunks = []
        remaining = maximum_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != metadata.st_size:
            raise LiveE2EError("private input changed while it was being read")
        return data
    finally:
        os.close(descriptor)


def write_private(path, data):
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    path.chmod(0o600)


def validate_registration_uri(value):
    parsed = urlsplit(value)
    query = parse_qs(parsed.query, strict_parsing=True)
    if (
        parsed.scheme != "heteronetwork"
        or parsed.netloc != "register"
        or parsed.path not in ("", "/")
        or parsed.fragment
        or set(query) != {"request"}
        or len(query["request"]) != 1
    ):
        raise LiveE2EError("registration request file did not contain one valid URI")


def validate_import_uri(value):
    parsed = urlsplit(value)
    query = parse_qs(parsed.query, strict_parsing=True)
    if (
        parsed.scheme != "heteronetwork"
        or parsed.netloc != "import"
        or parsed.path not in ("", "/")
        or parsed.fragment
        or set(query) != {"profile"}
        or len(query["profile"]) != 1
    ):
        raise LiveE2EError("sponsor did not return one valid import profile")


def sanitized_failure(stderr, secrets):
    message = stderr.strip()[-1000:]
    for secret in secrets:
        if secret:
            message = message.replace(secret, "[redacted]")
    if "heteronetwork://" in message:
        message = "remote sponsorship failed without exposing its enrollment URI"
    return message or "remote sponsorship failed without diagnostic output"


def sponsor(args):
    request_uri = read_private(args.request_file, 256 * 1024).decode("utf-8").strip()
    password = read_private(args.sudo_password_file, 16 * 1024).decode("utf-8").rstrip("\r\n")
    read_private(args.ssh_key_file, 64 * 1024)
    read_private(args.known_hosts_file, 64 * 1024)
    validate_registration_uri(request_uri)
    if not password:
        raise LiveE2EError("the sponsor sudo password file is empty")

    remote_command = "python3 -c " + shlex.quote(REMOTE_SPONSOR)
    command = [
        "ssh",
        "-i", str(Path(args.ssh_key_file).expanduser()),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=" + str(Path(args.known_hosts_file).expanduser()),
        "-o", "ConnectTimeout=10",
        f"{args.user}@{args.host}",
        remote_command,
    ]
    payload = json.dumps({"password": password, "request": request_uri}) + "\n"
    result = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        text=True,
        timeout=60,
        env={
            "HOME": os.environ.get("HOME", ""),
            "LANG": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin",
        },
    )
    payload = ""
    if result.returncode:
        raise LiveE2EError(sanitized_failure(result.stderr, (password, request_uri)))
    profiles = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("heteronetwork://import?")
    ]
    if len(profiles) != 1:
        raise LiveE2EError("remote sponsorship returned an unexpected response")
    validate_import_uri(profiles[0])
    write_private(args.profile_file, (profiles[0] + "\n").encode("utf-8"))
    print(json.dumps({"profile_received": True, "sponsorship_completed": True}, sort_keys=True))


def helper_is_connected(helper):
    result = subprocess.run(
        [helper, "status"], capture_output=True, text=True, timeout=10, check=True
    )
    try:
        status = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LiveE2EError("the installed helper returned invalid status JSON") from error
    return (
        status.get("ok") is True
        and status.get("status") == "connected"
        and isinstance(status.get("interface"), str)
        and bool(status["interface"])
    )


def timed_open(opener, path, accept, timeout):
    request = urllib.request.Request(
        CONSOLE_URL + path,
        headers={"Accept": accept, "User-Agent": "HeteroNetwork-macOS-live-E2E/1"},
    )
    started = time.monotonic()
    with opener.open(request, timeout=timeout) as response:
        body = response.read(1024 * 1024 + 1)
        status_code = response.status
    elapsed = time.monotonic() - started
    if elapsed >= timeout or len(body) > 1024 * 1024:
        raise LiveE2EError("the console response exceeded its time or size budget")
    return status_code, body, round(elapsed * 1000)


def console_probe(max_open_seconds):
    started = time.monotonic()
    addresses = socket.getaddrinfo(
        "console.heteronetwork.internal", 9781, type=socket.SOCK_STREAM
    )
    dns_milliseconds = round((time.monotonic() - started) * 1000)
    if not addresses or dns_milliseconds >= max_open_seconds * 1000:
        raise LiveE2EError("split DNS did not resolve within the console time budget")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    status_code, document, open_milliseconds = timed_open(
        opener, "/ui/", "text/html", max_open_seconds
    )
    if (
        status_code != 200
        or b'<div id="root"></div>' not in document
        or b'<script src="/ui/app.js" async></script>' not in document
    ):
        raise LiveE2EError("the console UI did not return the expected application shell")
    config_status, config_body, config_milliseconds = timed_open(
        opener, "/ui/config", "application/json", max_open_seconds
    )
    try:
        config = json.loads(config_body)
    except json.JSONDecodeError as error:
        raise LiveE2EError("the console configuration was not valid JSON") from error
    if (
        config_status != 200
        or config.get("auth_enabled") is not True
        or config.get("provider") != "keycloak"
    ):
        raise LiveE2EError("the console did not expose the protected Keycloak configuration")
    return {
        "console_config_ms": config_milliseconds,
        "console_http_status": status_code,
        "console_open_ms": open_milliseconds,
        "dns_ms": dns_milliseconds,
    }


def verify(args):
    deadline = time.monotonic() + args.deadline_seconds
    last_error = None
    stable = 0
    report = None
    while time.monotonic() < deadline:
        try:
            if not helper_is_connected(args.helper):
                raise LiveE2EError("the installed root helper is not connected")
            report = console_probe(args.max_open_seconds)
            stable += 1
            if stable == 2:
                break
        except Exception as error:  # retry convergence without exposing endpoint details
            last_error = error
            stable = 0
        time.sleep(0.5)
    else:
        detail = str(last_error)[:500] if last_error else "no successful probe"
        raise LiveE2EError("the macOS VPN and console did not converge: " + detail)
    report.update(
        {
            "console_keycloak_protected": True,
            "console_under_limit": True,
            "joined": True,
            "result": "passed",
            "split_dns": True,
            "vpn_connected": True,
        }
    )
    encoded = (json.dumps(report, sort_keys=True) + "\n").encode("utf-8")
    write_private(args.output, encoded)
    print(encoded.decode("utf-8"), end="")


def wipe(paths):
    for value in paths:
        path = Path(value).expanduser()
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_nlink != 1:
            path.unlink(missing_ok=True)
            continue
        try:
            with path.open("r+b", buffering=0) as private_file:
                remaining = metadata.st_size
                zeroes = b"\0" * min(64 * 1024, max(remaining, 1))
                while remaining > 0:
                    written = private_file.write(zeroes[:remaining])
                    remaining -= written
                private_file.flush()
                os.fsync(private_file.fileno())
        finally:
            path.unlink(missing_ok=True)


def build_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    sponsor_parser = subparsers.add_parser("sponsor")
    sponsor_parser.add_argument("--request-file", required=True)
    sponsor_parser.add_argument("--profile-file", required=True)
    sponsor_parser.add_argument("--ssh-key-file", required=True)
    sponsor_parser.add_argument("--known-hosts-file", required=True)
    sponsor_parser.add_argument("--sudo-password-file", required=True)
    sponsor_parser.add_argument("--host", required=True)
    sponsor_parser.add_argument("--user", required=True)
    sponsor_parser.set_defaults(handler=sponsor)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--helper", required=True)
    verify_parser.add_argument("--output", required=True)
    verify_parser.add_argument("--deadline-seconds", type=float, default=90)
    verify_parser.add_argument("--max-open-seconds", type=float, default=3)
    verify_parser.set_defaults(handler=verify)

    wipe_parser = subparsers.add_parser("wipe")
    wipe_parser.add_argument("paths", nargs="+")
    wipe_parser.set_defaults(handler=lambda args: wipe(args.paths))
    return parser


def main():
    args = build_parser().parse_args()
    try:
        args.handler(args)
    except Exception as error:
        print(f"macOS live E2E failed: {str(error)[:1000]}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
