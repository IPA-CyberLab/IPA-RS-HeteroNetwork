#!/usr/bin/env python3
"""Exercise the broker reconciler against an isolated real Keycloak instance."""

from html.parser import HTMLParser
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import tempfile
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit
import urllib.request
from http.cookiejar import CookieJar


PATH = Path(__file__).with_name("reconcile-heterocloud-owner-broker.py")
spec = importlib.util.spec_from_file_location("cloud_owner_broker", PATH)
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

ISSUER = "https://cloud.example.test:18443/id/realms/heterocloud"
ORIGIN = "http://console.heteronetwork.internal:18079"
EMAIL = "owner@example.test"
OTHER = "other@example.test"
TEST_PASSWORD = "isolated-test-password-only-53!"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class IdentityLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = {}
        self.form_action = None
        self.in_login_form = False
        self.hidden = {}

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and values.get("id", "").startswith("social-"):
            self.links[values["id"]] = values.get("href")
        if tag == "form" and values.get("id") == "kc-form-login":
            self.in_login_form = True
            self.form_action = values.get("action")
        if tag == "input" and self.in_login_form and values.get("type") == "hidden" and values.get("name"):
            self.hidden[values["name"]] = values.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_login_form = False


def fetch(opener, url, *, fields=None, headers=None):
    data = urlencode(fields).encode() if fields is not None else None
    request = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with opener.open(request, timeout=20) as response:
            body = response.read(1048577)
            status, location = response.status, response.headers.get("Location")
    except HTTPError as error:
        body = error.read(1048577)
        status, location = error.code, error.headers.get("Location")
    if len(body) > 1048576:
        raise RuntimeError("test response is too large")
    return status, location, body


def login(username):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(32)
    callback = "http://console.heteronetwork.internal/ui/callback"
    params = urlencode({"client_id": "ipars-web", "response_type": "code", "scope": "openid profile email",
                        "redirect_uri": callback, "state": state, "code_challenge": challenge,
                        "code_challenge_method": "S256"})
    context = ssl.create_default_context(cafile=os.environ["KEYCLOAK_TEST_CA"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context),
                urllib.request.HTTPCookieProcessor(CookieJar()), NoRedirects())
    status, _, body = fetch(opener, ORIGIN + "/realms/heteronetwork/protocol/openid-connect/auth?" + params)
    if status != 200:
        raise RuntimeError("real private login page was unavailable")
    parser = IdentityLinks()
    parser.feed(body.decode("utf-8"))
    link = parser.links.get("social-heterocloud")
    if not link:
        raise RuntimeError("real private login does not offer HeteroCloud")
    status, destination, _ = fetch(opener, urljoin(ORIGIN, link))
    if status not in (302, 303) or not destination:
        raise RuntimeError("real broker did not redirect to HeteroCloud")
    parsed = urlsplit(destination)
    params = parse_qs(parsed.query)
    if (parsed.scheme + "://" + parsed.netloc + parsed.path != ISSUER + "/protocol/openid-connect/auth"
            or params.get("client_id") != [broker.CLIENT_ID]
            or params.get("redirect_uri") != [ORIGIN + "/realms/heteronetwork/broker/heterocloud/endpoint"]
            or params.get("code_challenge_method") != ["S256"] or not params.get("code_challenge")):
        raise RuntimeError("real broker redirected to an unsafe or unexpected authorization endpoint")
    status, _, body = fetch(opener, destination)
    if status != 200:
        raise RuntimeError("real HeteroCloud login rejected the private callback")
    parser = IdentityLinks()
    parser.feed(body.decode("utf-8"))
    if not parser.form_action:
        raise RuntimeError("real HeteroCloud login form is unavailable")
    action = urljoin(destination, parser.form_action)
    if urlsplit(action).scheme != "https" or urlsplit(action).netloc != "cloud.example.test:18443":
        raise RuntimeError("test cloud credentials would be sent to an unexpected origin")
    fields = {**parser.hidden, "username": username, "password": TEST_PASSWORD, "login": "Sign In"}
    status, location, body = fetch(opener, action, fields=fields,
        headers={"Origin": "https://cloud.example.test:18443", "Referer": destination})
    trace = [{"stage": "cloud_login_submit", "status": status}]
    for _ in range(10):
        if status not in (302, 303) or not location:
            return opener, verifier, state, callback, None, status, trace
        location = urljoin(action, location)
        target = urlsplit(location)
        entry = {"status": status, "origin": target.scheme + "://" + target.netloc, "path": target.path}
        execution = parse_qs(target.query).get("execution", [""])[0]
        if re.fullmatch(r"[A-Z_]{3,64}", execution):
            entry["required_action"] = execution
        trace.append(entry)
        if target.scheme == "http" and target.netloc == "console.heteronetwork.internal" and target.path == "/ui/callback":
            return opener, verifier, state, callback, parse_qs(target.query), status, trace
        if not ((target.scheme == "http" and target.netloc == "console.heteronetwork.internal:18079")
                or (target.scheme == "https" and target.netloc == "cloud.example.test:18443")):
            raise RuntimeError("test authentication redirected to an unexpected origin")
        action = location
        status, location, body = fetch(opener, action)
    raise RuntimeError("test authentication redirected too many times")


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
            else:
                config["attributes"] = {"frontendUrl": "https://cloud.example.test:18443/id"}
            kc.mutate("create", "realms", body=config)
        for realm, username, verified in ((broker.CLOUD_REALM, EMAIL, True),
                                          (broker.PRIVATE_REALM, "private-owner", False)):
            kc.mutate("create", "users", realm=realm,
                      body={"username": username, "email": EMAIL, "enabled": True,
                            "emailVerified": verified, "firstName": "Test", "lastName": "Owner",
                            "credentials": [{"type": "password", "value": TEST_PASSWORD, "temporary": False}]
                                           if realm == broker.CLOUD_REALM else []})
        kc.mutate("create", "users", realm=broker.CLOUD_REALM,
                  body={"username": OTHER, "email": OTHER, "enabled": True, "emailVerified": True,
                        "firstName": "Test", "lastName": "Other",
                        "credentials": [{"type": "password", "value": TEST_PASSWORD, "temporary": False}]})
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

        opener, verifier, state, callback, result, status, trace = login(EMAIL)
        if not result or result.get("state") != [state] or len(result.get("code", [])) != 1:
            raise RuntimeError("existing cloud owner did not complete private authentication: " + json.dumps(trace))
        status, _, raw = fetch(opener, ORIGIN + "/realms/heteronetwork/protocol/openid-connect/token",
                               fields={"grant_type": "authorization_code", "client_id": "ipars-web",
                                       "code": result["code"][0], "redirect_uri": callback,
                                       "code_verifier": verifier})
        if status != 200:
            raise RuntimeError("private owner token exchange failed")
        token = json.loads(raw).get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("private owner token was not issued")
        status, _, raw = fetch(opener, ORIGIN + "/realms/heteronetwork/protocol/openid-connect/userinfo",
                               headers={"Authorization": "Bearer " + token})
        identity = json.loads(raw)
        private_owner = broker.unique_owner(kc, broker.PRIVATE_REALM, EMAIL)
        if status != 200 or identity.get("sub") != private_owner["id"] or identity.get("email") != EMAIL:
            raise RuntimeError("private token does not belong to the existing owner")
        del token
        _, _, _, _, rejected, rejected_status, _ = login(OTHER)
        if rejected and rejected.get("code"):
            raise RuntimeError("unlinked cloud account obtained a private token")
        users = kc.get("users", realm=broker.PRIVATE_REALM, query={"max": "100"})
        if len(users) != 1:
            raise RuntimeError("unlinked cloud account was unexpectedly imported")
        print("isolated Keycloak E2E: owner password login and private token passed; unlinked account denied")


if __name__ == "__main__":
    run()
