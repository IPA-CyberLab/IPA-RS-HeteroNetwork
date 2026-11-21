#!/usr/bin/env python3
"""Exercise the broker reconciler against an isolated real Keycloak instance."""

from html.parser import HTMLParser
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
import urllib.request
from http.cookiejar import CookieJar


PATH = Path(__file__).with_name("reconcile-heterocloud-owner-broker.py")
spec = importlib.util.spec_from_file_location("cloud_owner_broker", PATH)
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

ISSUER = "https://cloud.example.test/id/realms/heterocloud"
ORIGIN = "http://console.heteronetwork.internal:18079"
EMAIL = "owner@example.test"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class IdentityLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and values.get("id", "").startswith("social-"):
            self.links[values["id"]] = values.get("href")


def run():
    module = broker.helpers()
    module.KCADM = os.environ["KEYCLOAK_TEST_KCADM"]
    password = os.environ["KEYCLOAK_TEST_ADMIN_PASSWORD"]
    with tempfile.TemporaryDirectory(prefix="keycloak-broker-e2e-") as directory:
        kc = broker.keycloak_client(module)("http://127.0.0.1:18080", directory, password)
        for realm in (broker.CLOUD_REALM, broker.PRIVATE_REALM):
            config = {"realm": realm, "enabled": True, "registrationAllowed": False,
                      "sslRequired": "none"}
            if realm == broker.PRIVATE_REALM:
                config["attributes"] = {"frontendUrl": ORIGIN}
            kc.mutate("create", "realms", body=config)
        for realm, username, verified in ((broker.CLOUD_REALM, EMAIL, True),
                                          (broker.PRIVATE_REALM, "private-owner", False)):
            kc.mutate("create", "users", realm=realm,
                      body={"username": username, "email": EMAIL, "enabled": True,
                            "emailVerified": verified})
        kc.mutate("create", "authentication/flows", realm=broker.PRIVATE_REALM,
                  body={"alias": broker.DENY_FLOW, "providerId": "basic-flow",
                        "topLevel": True, "builtIn": False})
        kc.mutate("create", "authentication/flows/" + broker.DENY_FLOW + "/executions/execution",
                  realm=broker.PRIVATE_REALM, body={"provider": "deny-access-authenticator"})
        executions = kc.get("authentication/flows/" + broker.DENY_FLOW + "/executions",
                            realm=broker.PRIVATE_REALM)
        if len(executions) != 1:
            raise RuntimeError("test deny flow was not created")
        kc.mutate("update", "authentication/flows/" + broker.DENY_FLOW + "/executions",
                  realm=broker.PRIVATE_REALM, no_merge=True,
                  body={"id": executions[0]["id"], "requirement": "REQUIRED"})
        kc.mutate("create", "clients", realm=broker.PRIVATE_REALM,
                  body={"clientId": "ipars-web", "enabled": True, "protocol": "openid-connect",
                        "publicClient": True, "standardFlowEnabled": True,
                        "redirectUris": ["http://console.heteronetwork.internal/ui/callback"],
                        "attributes": {"pkce.code.challenge.method": "S256"}})

        if not broker.reconcile(kc, EMAIL, ISSUER, ORIGIN):
            raise RuntimeError("real identity broker was not created")
        if broker.reconcile(kc, EMAIL, ISSUER, ORIGIN):
            raise RuntimeError("real identity broker was not idempotent")

        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        params = urlencode({"client_id": "ipars-web", "response_type": "code", "scope": "openid",
                            "redirect_uri": "http://console.heteronetwork.internal/ui/callback",
                            "state": secrets.token_urlsafe(32), "code_challenge": challenge,
                            "code_challenge_method": "S256"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirects())
        request = urllib.request.Request("http://127.0.0.1:18080/realms/heteronetwork/protocol/openid-connect/auth?" + params,
                                        headers={"Host": "console.heteronetwork.internal:18079"})
        with opener.open(request, timeout=15) as response:
            page = response.read(1048577)
        if len(page) > 1048576:
            raise RuntimeError("test login page is too large")
        parser = IdentityLinks()
        parser.feed(page.decode("utf-8"))
        link = parser.links.get("social-heterocloud")
        if not link:
            raise RuntimeError("real private login does not offer HeteroCloud")
        parsed = urlsplit(link)
        request = urllib.request.Request("http://127.0.0.1:18080" + parsed.path + "?" + parsed.query,
                                        headers={"Host": "console.heteronetwork.internal:18079"})
        try:
            opener.open(request, timeout=15)
        except HTTPError as error:
            if error.code not in (302, 303):
                raise
            destination = error.headers.get("Location", "")
        else:
            raise RuntimeError("real broker did not redirect to HeteroCloud")
        parsed = urlsplit(destination)
        params = parse_qs(parsed.query)
        if (parsed.scheme + "://" + parsed.netloc + parsed.path != ISSUER + "/protocol/openid-connect/auth"
                or params.get("client_id") != [broker.CLIENT_ID]
                or params.get("redirect_uri") != [ORIGIN + "/realms/heteronetwork/broker/heterocloud/endpoint"]
                or params.get("code_challenge_method") != ["S256"] or not params.get("code_challenge")):
            raise RuntimeError("real broker redirected to an unsafe or unexpected authorization endpoint")
        print("isolated Keycloak E2E: owner linked, unlinked denied, VPN callback and PKCE verified")


if __name__ == "__main__":
    run()
