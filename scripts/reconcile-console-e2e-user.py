#!/usr/bin/env python3
"""Reconcile the dedicated console E2E identity from a private JSON record.

This program is streamed over SSH and runs as root on the Keycloak host. It
reads one JSON line from stdin. Credential values are never accepted in argv,
written to disk, or included in output.
"""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


EXPECTED_EMAIL = "heteronetwork-console-e2e@heteronetwork.invalid"
EXPECTED_USERNAME = EXPECTED_EMAIL
MANAGED_FIRST_NAME = "HeteroNetwork Console"
MANAGED_LAST_NAME = "E2E"
REALM = "heterocloud"
SERVER = "http://127.0.0.1:18080"
KCADM = "/opt/heteronetwork/keycloak/bin/kcadm.sh"
ADMIN_PASSWORD = Path("/etc/heteronetwork/keycloak/bootstrap-admin.password")
MAX_INPUT_BYTES = 8192


def fail(message):
    raise RuntimeError(message)


def private_regular_file(path):
    metadata = path.lstat()
    return (stat.S_ISREG(metadata.st_mode) and not path.is_symlink()
            and metadata.st_nlink == 1 and 0 < metadata.st_size <= 4096
            and metadata.st_mode & 0o007 == 0)


def run_kcadm(config, environment, *arguments, input_data=None):
    result = subprocess.run(
        [KCADM, *arguments, "--config", str(config)],
        input=input_data, capture_output=True, text=True, timeout=30,
        env=environment,
    )
    if result.returncode:
        operation = " ".join(arguments[:2])
        fail(f"Keycloak administration command failed during {operation}")
    return result.stdout


def read_credentials():
    raw = sys.stdin.buffer.readline(MAX_INPUT_BYTES + 1)
    if not raw or len(raw) > MAX_INPUT_BYTES or not raw.endswith(b"\n"):
        fail("E2E credential record is missing or oversized")
    if sys.stdin.buffer.read(1):
        fail("E2E credential input contains trailing data")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("E2E credential record is invalid")
    if set(value) != {"username", "email", "password"}:
        fail("E2E credential record has an invalid schema")
    if value["username"] != EXPECTED_USERNAME or value["email"] != EXPECTED_EMAIL:
        fail("E2E credential identity does not match the managed account")
    password = value["password"]
    if (not isinstance(password, str) or not 32 <= len(password) <= 128
            or not password.isascii() or not password.isprintable()
            or any(character.isspace() for character in password)):
        fail("E2E account password does not satisfy the private credential policy")
    return value


def securely_remove(path):
    try:
        size = path.stat().st_size
        with path.open("r+b", buffering=0) as output:
            output.write(os.urandom(size))
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def main():
    if os.geteuid() != 0:
        fail("console E2E identity reconciliation requires root")
    if not Path(KCADM).is_file() or not os.access(KCADM, os.X_OK):
        fail("Keycloak administration client is unavailable")
    if not private_regular_file(ADMIN_PASSWORD):
        fail("Keycloak bootstrap credential is unavailable or unsafe")
    credential = read_credentials()
    descriptor, config_name = tempfile.mkstemp(prefix="heteronetwork-e2e-kcadm-", dir="/tmp")
    os.close(descriptor)
    config = Path(config_name)
    config.chmod(0o600)
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "KC_CLI_PASSWORD": ADMIN_PASSWORD.read_text().rstrip("\r\n"),
    }
    try:
        run_kcadm(
            config, environment, "config", "credentials", "--server", SERVER,
            "--realm", "master", "--user", "admin")
        environment.pop("KC_CLI_PASSWORD", None)
        users = json.loads(run_kcadm(
            config, environment, "get", "users", "-r", REALM,
            "-q", f"username={EXPECTED_USERNAME}", "-q", "exact=true", "-q", "max=2"))
        if len(users) > 1:
            fail("multiple users match the managed E2E identity")
        created = not users
        if created:
            run_kcadm(
                config, environment, "create", "users", "-r", REALM,
                "-s", f"username={EXPECTED_USERNAME}",
                "-s", f"email={EXPECTED_EMAIL}",
                "-s", f"firstName={MANAGED_FIRST_NAME}",
                "-s", f"lastName={MANAGED_LAST_NAME}",
                "-s", "enabled=true", "-s", "emailVerified=true",
            )
            users = json.loads(run_kcadm(
                config, environment, "get", "users", "-r", REALM,
                "-q", f"username={EXPECTED_USERNAME}", "-q", "exact=true", "-q", "max=2"))
            if len(users) != 1:
                fail("managed E2E identity was not created uniquely")
        else:
            if (users[0].get("firstName") != MANAGED_FIRST_NAME
                    or users[0].get("lastName") != MANAGED_LAST_NAME):
                fail("refusing to take over an unmanaged Keycloak identity")
        user_id = users[0]["id"]
        run_kcadm(
            config, environment, "update", f"users/{user_id}", "-r", REALM,
            "-s", f"username={EXPECTED_USERNAME}",
            "-s", f"email={EXPECTED_EMAIL}",
            "-s", f"firstName={MANAGED_FIRST_NAME}",
            "-s", f"lastName={MANAGED_LAST_NAME}",
            "-s", "enabled=true", "-s", "emailVerified=true",
        )
        run_kcadm(
            config, environment, "update", f"users/{user_id}/reset-password",
            "-r", REALM, "-n", "-f", "-",
            input_data=json.dumps({
                "type": "password", "value": credential["password"], "temporary": False,
            }))
        verified = json.loads(run_kcadm(
            config, environment, "get", f"users/{user_id}", "-r", REALM))
        if (verified.get("username") != EXPECTED_USERNAME
                or verified.get("email") != EXPECTED_EMAIL
                or verified.get("firstName") != MANAGED_FIRST_NAME
                or verified.get("lastName") != MANAGED_LAST_NAME
                or verified.get("enabled") is not True
                or verified.get("emailVerified") is not True):
            fail("managed E2E identity verification failed")
        password_credentials = json.loads(run_kcadm(
            config, environment, "get", f"users/{user_id}/credentials", "-r", REALM))
        if sum(item.get("type") == "password" for item in password_credentials) != 1:
            fail("managed E2E identity does not have one password credential")
        print(json.dumps({"result": "reconciled", "created": created}))
    finally:
        environment.clear()
        credential.clear()
        securely_remove(config)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"console E2E identity reconciliation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
