#!/usr/bin/env python3
"""Link the existing cloud owner to the private network owner via OIDC.

Credentials never appear in arguments, output, or Terraform state. Unlinked
identities are denied, and the only upstream callback is the VPN origin.
"""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from uuid import UUID


PRIVATE_REALM = "heteronetwork"
CLOUD_REALM = "heterocloud"
CLIENT_ID = "heteronetwork-owner-broker"
PROVIDER_ALIAS = "heterocloud"
DENY_FLOW = "github-deny-unlinked"
MANAGED_KEY = "heteronetwork.private-owner-broker"
MANAGED_VALUE = "v1"
LOOPBACK = "http://127.0.0.1:18080/realms/heterocloud/protocol/openid-connect"
MAX_USERS = 500


def helpers():
    path = Path(__file__).with_name("reconcile-private-oidc-client.py")
    spec = importlib.util.spec_from_file_location("private_identity_client", path)
    if not spec or not spec.loader:
        raise RuntimeError("private identity helper is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cloud_issuer(value):
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid cloud issuer") from error
    if (parsed.scheme != "https" or not parsed.hostname or port == 0
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or not parsed.path.endswith("/realms/heterocloud")
            or "//" in parsed.path or "/../" in parsed.path):
        raise ValueError("cloud issuer must be the HTTPS HeteroCloud realm")
    return value.rstrip("/")


def private_origin(value):
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid private identity origin") from error
    if (parsed.scheme != "http" or not parsed.hostname
            or not parsed.hostname.endswith(".heteronetwork.internal") or not port
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise ValueError("broker callback must use a private HeteroNetwork origin")
    return value.rstrip("/")


def identifier(value):
    if not isinstance(value, str):
        raise ValueError("identity identifier is missing")
    try:
        if str(UUID(value)) != value.lower():
            raise ValueError
    except ValueError as error:
        raise ValueError("identity identifier is invalid") from error
    return value


def client_representation(origin, *, enabled):
    return {
        "clientId": CLIENT_ID, "name": "HeteroNetwork private owner broker",
        "enabled": enabled, "protocol": "openid-connect", "publicClient": False,
        "clientAuthenticatorType": "client-secret", "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False, "implicitFlowEnabled": False,
        "serviceAccountsEnabled": False,
        "redirectUris": [origin + "/realms/heteronetwork/broker/heterocloud/endpoint"],
        "webOrigins": [],
        "attributes": {MANAGED_KEY: MANAGED_VALUE, "pkce.code.challenge.method": "S256"},
    }


def provider_representation(issuer, secret, *, enabled):
    return {
        "alias": PROVIDER_ALIAS, "displayName": "HeteroCloud", "providerId": "oidc",
        "enabled": enabled, "trustEmail": False, "storeToken": False,
        "addReadTokenRoleOnCreate": False, "authenticateByDefault": False,
        "linkOnly": False, "firstBrokerLoginFlowAlias": DENY_FLOW,
        "config": {
            MANAGED_KEY: MANAGED_VALUE,
            "heteronetwork.secretFingerprint": hashlib.sha256(secret.encode()).hexdigest(),
            "clientId": CLIENT_ID, "clientSecret": secret,
            "clientAuthMethod": "client_secret_post", "authorizationUrl": issuer + "/protocol/openid-connect/auth",
            "tokenUrl": LOOPBACK + "/token", "userInfoUrl": LOOPBACK + "/userinfo",
            "issuer": issuer, "validateSignature": "true", "useJwksUrl": "true",
            "jwksUrl": LOOPBACK + "/certs", "defaultScope": "openid profile email",
            "pkceEnabled": "true", "pkceMethod": "S256", "syncMode": "IMPORT",
            "hideOnLoginPage": "false",
        },
    }


def matches(actual, expected, *, ignore_secret=False):
    if not isinstance(actual, dict):
        return False
    for key, value in expected.items():
        if ignore_secret and key == "clientSecret":
            continue
        # Keycloak omits this default-valued field from its REST representation.
        if key == "hideOnLoginPage" and value == "false" and key not in actual:
            continue
        if isinstance(value, dict):
            if not matches(actual.get(key), value, ignore_secret=ignore_secret):
                return False
        elif actual.get(key) != value:
            return False
    return True


def mismatched_fields(actual, expected, *, prefix="", ignore_secret=False):
    if not isinstance(actual, dict):
        return [prefix.rstrip(".") or "representation"]
    fields = []
    for key, value in expected.items():
        if ignore_secret and key == "clientSecret":
            continue
        if key == "hideOnLoginPage" and value == "false" and key not in actual:
            continue
        name = prefix + key
        if isinstance(value, dict):
            fields.extend(mismatched_fields(actual.get(key), value, prefix=name + ".", ignore_secret=ignore_secret))
        elif actual.get(key) != value:
            fields.append(name)
    return fields


def unique_owner(kc, realm, email, *, verified=False):
    users = kc.get("users", realm=realm, query={"email": email, "exact": "true", "max": "2"})
    if not isinstance(users, list):
        raise ValueError("owner lookup returned an invalid response")
    users = [user for user in users if (user.get("email") or "").lower() == email]
    if (len(users) != 1 or users[0].get("enabled") is not True
            or (verified and users[0].get("emailVerified") is not True)):
        raise ValueError("the existing owner must be unique, enabled and verified")
    identifier(users[0].get("id"))
    name = users[0].get("username")
    if not isinstance(name, str) or not name or len(name) > 255 or any(ord(c) < 32 for c in name):
        raise ValueError("owner username is invalid")
    return users[0]


def verify_deny_flow(kc):
    realm = kc.get("realms/" + PRIVATE_REALM)
    if realm.get("enabled") is not True or realm.get("registrationAllowed") is not False:
        raise ValueError("the private realm must be enabled with registration disabled")
    flows = kc.get("authentication/flows", realm=PRIVATE_REALM)
    if not isinstance(flows, list):
        raise ValueError("private authentication flows are unavailable")
    owned = [flow for flow in flows if flow.get("alias") == DENY_FLOW]
    if len(owned) != 1 or owned[0].get("topLevel") is not True:
        raise ValueError("private authentication deny flow is unavailable")
    executions = kc.get("authentication/flows/" + DENY_FLOW + "/executions", realm=PRIVATE_REALM)
    if (not isinstance(executions, list) or len(executions) != 1
            or executions[0].get("providerId") != "deny-access-authenticator"
            or executions[0].get("requirement") != "REQUIRED"):
        raise ValueError("unlinked identities are not rejected")


def verify_no_other_links(kc, owner_id):
    users = kc.get("users", realm=PRIVATE_REALM, query={"max": str(MAX_USERS + 1), "briefRepresentation": "true"})
    if not isinstance(users, list) or len(users) > MAX_USERS:
        raise ValueError("private owner link audit is incomplete")
    found = []
    for user in users:
        user_id = identifier(user.get("id"))
        links = kc.get("users/" + user_id + "/federated-identity", realm=PRIVATE_REALM)
        if not isinstance(links, list):
            raise ValueError("private owner links are unavailable")
        for link in links:
            if link.get("identityProvider") == PROVIDER_ALIAS:
                if user_id != owner_id:
                    raise ValueError("cloud identity is linked to an unexpected private user")
                found.append(link)
    if len(found) > 1:
        raise ValueError("cloud identity link is ambiguous")
    return found[0] if found else None


def reconcile(kc, email, issuer, origin):
    issuer, origin = cloud_issuer(issuer), private_origin(origin)
    verify_deny_flow(kc)
    private = unique_owner(kc, PRIVATE_REALM, email)
    cloud = unique_owner(kc, CLOUD_REALM, email, verified=True)
    private_id, cloud_id = private["id"], cloud["id"]
    existing_link = verify_no_other_links(kc, private_id)
    if existing_link and existing_link.get("userId") != cloud_id:
        raise ValueError("cloud identity link does not match the existing owner")

    clients = kc.get("clients", realm=CLOUD_REALM, query={"clientId": CLIENT_ID})
    if not isinstance(clients, list) or len(clients) > 1:
        raise ValueError("cloud broker client is ambiguous")
    providers = kc.get("identity-provider/instances", realm=PRIVATE_REALM)
    if not isinstance(providers, list):
        raise ValueError("private identity providers are unavailable")
    providers = [provider for provider in providers if provider.get("alias") == PROVIDER_ALIAS]
    if len(providers) > 1:
        raise ValueError("cloud identity provider is ambiguous")
    if providers and (providers[0].get("providerId") != "oidc" or
                      (providers[0].get("config") or {}).get(MANAGED_KEY) != MANAGED_VALUE):
        raise ValueError("refusing to change an unmanaged identity provider")
    if clients and ((clients[0].get("attributes") or {}).get(MANAGED_KEY) != MANAGED_VALUE
                    or clients[0].get("clientId") != CLIENT_ID):
        raise ValueError("refusing to change an unmanaged cloud client")

    changed = False
    desired_client = client_representation(origin, enabled=True)
    if not clients:
        kc.mutate("create", "clients", realm=CLOUD_REALM,
                  body=client_representation(origin, enabled=False))
        clients = kc.get("clients", realm=CLOUD_REALM, query={"clientId": CLIENT_ID})
        if not isinstance(clients, list) or len(clients) != 1:
            raise RuntimeError("cloud broker client creation was not confirmed")
        changed = True
    client = clients[0]
    client_id = identifier(client.get("id"))
    if (client.get("attributes") or {}).get(MANAGED_KEY) != MANAGED_VALUE:
        raise ValueError("cloud broker client is not managed")
    secret = kc.get("clients/" + client_id + "/client-secret", realm=CLOUD_REALM).get("value")
    if not isinstance(secret, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{16,512}", secret):
        raise ValueError("cloud broker credential is unavailable")
    desired_provider = provider_representation(issuer, secret, enabled=True)
    if not providers:
        kc.mutate("create", "identity-provider/instances", realm=PRIVATE_REALM,
                  body=provider_representation(issuer, secret, enabled=False))
        providers = kc.get("identity-provider/instances", realm=PRIVATE_REALM)
        providers = [provider for provider in providers if provider.get("alias") == PROVIDER_ALIAS]
        if len(providers) != 1:
            raise RuntimeError("private identity provider creation was not confirmed")
        changed = True
    provider = providers[0]
    if (provider.get("config") or {}).get(MANAGED_KEY) != MANAGED_VALUE:
        raise ValueError("private identity provider is not managed")
    if not existing_link:
        kc.mutate("create", "users/" + private_id + "/federated-identity/" + PROVIDER_ALIAS,
                  realm=PRIVATE_REALM,
                  body={"identityProvider": PROVIDER_ALIAS, "userId": cloud_id, "userName": cloud["username"]})
        existing_link = verify_no_other_links(kc, private_id)
        if not existing_link or existing_link.get("userId") != cloud_id:
            raise RuntimeError("private owner identity link was not confirmed")
        changed = True
    if not matches(client, desired_client):
        updated = dict(client)
        updated.update(desired_client)
        updated["attributes"] = {**(client.get("attributes") or {}), **desired_client["attributes"]}
        updated.pop("secret", None)
        kc.mutate("update", "clients/" + client_id, realm=CLOUD_REALM, body=updated)
        verified = kc.get("clients", realm=CLOUD_REALM, query={"clientId": CLIENT_ID})
        if len(verified) != 1 or not matches(verified[0], desired_client):
            raise RuntimeError("cloud broker client update was not confirmed")
        changed = True
    if not matches(provider, desired_provider, ignore_secret=True):
        updated = dict(provider)
        updated.update(desired_provider)
        updated["config"] = {**(provider.get("config") or {}), **desired_provider["config"]}
        kc.mutate("update", "identity-provider/instances/" + PROVIDER_ALIAS,
                  realm=PRIVATE_REALM, body=updated)
        verified = kc.get("identity-provider/instances", realm=PRIVATE_REALM)
        verified = [item for item in verified if item.get("alias") == PROVIDER_ALIAS]
        if len(verified) != 1:
            raise RuntimeError("private identity provider update was not confirmed")
        differences = mismatched_fields(verified[0], desired_provider, ignore_secret=True)
        if differences:
            raise RuntimeError("private identity provider has unexpected fields: " + ", ".join(differences))
        changed = True
    return changed


def keycloak_client(module):
    class Keycloak(module.Keycloak):
        def mutate(self, method, path, *, realm=None, body, no_merge=False):
            command = [module.KCADM, method, path]
            if realm:
                command += ["-r", realm]
            if no_merge:
                command.append("-n")
            command += ["-f", "-", "--config", self.config]
            result = subprocess.run(command, input=json.dumps(body).encode(),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
            if result.returncode:
                raise RuntimeError("identity provider administration failed")
    return Keycloak


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cloud-issuer", required=True)
    parser.add_argument("--private-origin", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("must run as root")
    try:
        module = helpers()

        owner = module.owner_email(module.private_file(module.BOOTSTRAP))
        password = module.private_file(module.ADMIN_PASSWORD, world_only=True).strip()
        with tempfile.TemporaryDirectory(prefix="hnn-cloud-owner-broker-", dir="/run") as directory:
            kc = keycloak_client(module)("http://127.0.0.1:18080", directory, password)
            del password
            changed = reconcile(kc, owner, args.cloud_issuer, args.private_origin)
        print(json.dumps({"changed": changed}))
        return 0
    except (OSError, KeyError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print("private cloud owner broker setup failed: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
