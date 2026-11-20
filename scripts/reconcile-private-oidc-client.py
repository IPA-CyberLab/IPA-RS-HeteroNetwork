#!/usr/bin/env python3
"""Prepare the existing private owner OIDC client without changing public SSO."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


REALM = "heteronetwork"
CLIENT_ID = "ipars-web"
KCADM = "/opt/heteronetwork/keycloak/bin/kcadm.sh"
ADMIN_PASSWORD = Path("/etc/heteronetwork/keycloak/bootstrap-admin.password")
BOOTSTRAP = Path("/etc/heteronetwork/public-services/bootstrap.env")
OWNER_KEY = "HETERONETWORK_PUBLIC_SERVICES_OIDC_REQUIRED_EMAIL_B64"


def private_file(path, *, world_only=False):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        forbidden = 0o007 if world_only else 0o077
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & forbidden or not 0 < info.st_size <= 131072):
            raise ValueError("unsafe private configuration file")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            return stream.read()
    finally:
        if fd >= 0:
            os.close(fd)


def owner_email(bootstrap):
    values = [line.partition("=")[2] for line in bootstrap.splitlines()
              if line.partition("=")[0] == OWNER_KEY]
    if len(values) != 1:
        raise ValueError("owner identity must be declared exactly once")
    try:
        value = base64.b64decode(values[0], validate=True).decode("utf-8").strip().lower()
    except (ValueError, UnicodeError) as error:
        raise ValueError("owner identity is invalid") from error
    if not re.fullmatch(r"[^\s@,]+@[^\s@,]+", value) or len(value) > 254:
        raise ValueError("owner identity is invalid")
    return value


def console_origin(value):
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid console origin") from error
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or not parsed.hostname.endswith(".heteronetwork.internal")
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or port == 0):
        raise ValueError("console origin must be an internal HeteroNetwork origin")
    return value.rstrip("/")


def desired_client(client, origins):
    if (client.get("clientId") != CLIENT_ID or client.get("enabled") is not True
            or client.get("publicClient") is not True
            or client.get("standardFlowEnabled") is not True):
        raise ValueError("private client is not an enabled public OIDC client")
    attributes = client.get("attributes") or {}
    if (attributes.get("oauth2.device.authorization.grant.enabled") != "true"
            or attributes.get("pkce.code.challenge.method") != "S256"):
        raise ValueError("private client must require PKCE and allow device login")
    old_redirects = client.get("redirectUris") or []
    old_origins = client.get("webOrigins") or []
    if (not isinstance(old_redirects, list) or not isinstance(old_origins, list)
            or not all(isinstance(value, str) for value in old_redirects + old_origins)):
        raise ValueError("private client has invalid redirect settings")
    redirects, web_origins = list(old_redirects), list(old_origins)
    for value in origins:
        origin = console_origin(value)
        if origin + "/ui/callback" not in redirects:
            redirects.append(origin + "/ui/callback")
        if origin not in web_origins:
            web_origins.append(origin)
    updates = {}
    if redirects != old_redirects:
        updates["redirectUris"] = redirects
    if web_origins != old_origins:
        updates["webOrigins"] = web_origins
    return updates


def prepare(kc, email, origins, *, check=False):
    realm = kc.get("realms/" + REALM)
    if realm.get("enabled") is not True or realm.get("registrationAllowed") is not False:
        raise ValueError("private realm must be enabled with self-registration disabled")
    clients = kc.get("clients", realm=REALM, query={"clientId": CLIENT_ID})
    if not isinstance(clients, list) or len(clients) != 1:
        raise ValueError("private client must exist exactly once")
    client = clients[0]
    client_uuid = client.get("id", "")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", client_uuid):
        raise ValueError("private client identity is invalid")
    users = kc.get("users", realm=REALM, query={"email": email, "exact": "true", "max": "2"})
    if not isinstance(users, list):
        raise ValueError("private realm returned invalid owner records")
    users = [user for user in users if (user.get("email") or "").lower() == email]
    if len(users) != 1 or users[0].get("enabled") is not True:
        raise ValueError("the existing owner must be enabled in the private realm")
    owner = users[0]
    user_uuid = owner.get("id", "")
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", user_uuid):
        raise ValueError("owner identity is invalid")
    links = kc.get("users/" + user_uuid + "/federated-identity", realm=REALM)
    providers = kc.get("identity-provider/instances", realm=REALM)
    credentials = kc.get("users/" + user_uuid + "/credentials", realm=REALM)
    if any(not isinstance(items, list) for items in (links, providers, credentials)):
        raise ValueError("private realm returned invalid authentication settings")
    secure_providers = {
        provider.get("alias") for provider in providers
        if provider.get("enabled") is True and provider.get("trustEmail") is False
        and provider.get("firstBrokerLoginFlowAlias") == "github-deny-unlinked"
    }
    linked = any(link.get("identityProvider") in secure_providers for link in links)
    has_password = any(item.get("type") == "password" for item in credentials)
    if not linked and not has_password:
        raise ValueError("private owner has no usable existing sign-in method")
    updates = desired_client(client, origins)
    if updates and not check:
        kc.update_client(client_uuid, updates)
        refreshed = kc.get("clients", realm=REALM, query={"clientId": CLIENT_ID})
        if len(refreshed) != 1 or desired_client(refreshed[0], origins):
            raise RuntimeError("private client update was not confirmed")
    return bool(updates)


class Keycloak:
    def __init__(self, server, directory, password):
        self.server, self.config = server, str(Path(directory) / "kcadm.config")
        env = os.environ.copy()
        env["KC_CLI_PASSWORD"] = password
        self.run(["config", "credentials", "--server", server, "--realm", "master",
                  "--user", "admin"], env=env)

    def run(self, arguments, *, env=None):
        result = subprocess.run([KCADM, *arguments, "--config", self.config],
                                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=45)
        if result.returncode:
            raise RuntimeError("private identity provider request failed")
        return result.stdout

    def get(self, path, *, realm=None, query=None):
        command = ["get", path]
        if realm:
            command += ["-r", realm]
        for key, value in (query or {}).items():
            command += ["-q", key + "=" + value]
        return json.loads(self.run(command))

    def update_client(self, client_uuid, updates):
        command = ["update", "clients/" + client_uuid, "-r", REALM]
        for key, value in updates.items():
            command += ["-s", key + "=" + json.dumps(value, separators=(",", ":"))]
        self.run(command)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--console-origin", action="append", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("must run as root")
    try:
        origins = [console_origin(value) for value in args.console_origin]
        email = owner_email(private_file(BOOTSTRAP))
        password = private_file(ADMIN_PASSWORD, world_only=True).strip()
        with tempfile.TemporaryDirectory(prefix="hnn-private-oidc-", dir="/run") as directory:
            kc = Keycloak("http://127.0.0.1:18080", directory, password)
            del password
            changed = prepare(kc, email, origins, check=args.check)
        print(json.dumps({"changed": changed, "realm": REALM, "client": CLIENT_ID}))
        return 2 if changed and args.check else 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("private identity setup failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
