#!/usr/bin/env python3
"""One-shot GitHub App manifest registration helper."""

from __future__ import annotations

import argparse
import html
import http.server
import json
import os
import re
import secrets
import stat
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

CLIENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
CLIENT_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9._-]{20,512}$")
MANIFEST_CODE_PATTERN = re.compile(r"^[A-Fa-f0-9]{40}$")
KEYCLOAK_REALM_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


def parse_listen(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise argparse.ArgumentTypeError("listen address must use HOST:PORT")
    port = int(port_text)
    if port < 1024 or port > 65535:
        raise argparse.ArgumentTypeError("listen port must be within 1024-65535")
    return host, port


def validate_http_url(value: str, *, allow_http: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    allowed_schemes = {"https"}
    if allow_http:
        allowed_schemes.add("http")
    if (
        parsed.scheme not in allowed_schemes
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"invalid URL: {value}")
    return value.rstrip("/")


def validate_callback_url(value: str, keycloak_realm: str) -> str:
    value = validate_http_url(value, allow_http=False)
    parsed = urllib.parse.urlsplit(value)
    if not KEYCLOAK_REALM_PATTERN.fullmatch(keycloak_realm):
        raise ValueError("Keycloak realm must be a 1-63 character safe identifier")
    expected_suffix = f"/realms/{keycloak_realm}/broker/github/endpoint"
    if parsed.path != expected_suffix:
        raise ValueError(f"callback URL must end with {expected_suffix}")
    return value


def sanitized_request_path(target: str) -> str:
    path = urllib.parse.urlsplit(target).path
    if path.startswith("/callback/"):
        return "/callback/<redacted>"
    return path


def build_manifest(
    *,
    app_name: str,
    homepage_url: str,
    redirect_url: str,
    callback_urls: list[str],
    keycloak_realm: str,
) -> dict[str, Any]:
    if not app_name or len(app_name) > 100 or any(ord(char) < 32 for char in app_name):
        raise ValueError("app name must contain 1-100 printable characters")
    homepage_url = validate_http_url(homepage_url, allow_http=False)
    redirect_url = validate_http_url(redirect_url, allow_http=True)
    callbacks = [
        validate_callback_url(value, keycloak_realm) for value in callback_urls
    ]
    if len(callbacks) != 2 or len(set(callbacks)) != 2:
        raise ValueError("exactly two distinct Keycloak callback URLs are required")
    return {
        "name": app_name,
        "url": homepage_url,
        "description": "GitHub sign-in for the HeteroNetwork Kakurizai console.",
        "redirect_url": redirect_url,
        "callback_urls": callbacks,
        "public": False,
        "request_oauth_on_install": False,
    }


def ensure_private_output_directory(path: Path) -> None:
    if not path.is_absolute():
        raise ValueError("output directory must be absolute")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
        raise ValueError("output path must be a non-symlink directory")
    if info.st_uid != os.geteuid():
        raise ValueError("output directory must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("output directory must not be group/world accessible")


def write_new_private_file(path: Path, value: str) -> None:
    if not value or "\n" in value or "\r" in value:
        raise ValueError(f"invalid single-line credential for {path.name}")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(value)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def persist_app_credentials(
    output_dir: Path, response: dict[str, Any], expected_owner: str
) -> dict[str, Any]:
    client_id = response.get("client_id")
    client_secret = response.get("client_secret")
    app_id = response.get("id")
    app_slug = response.get("slug")
    owner = response.get("owner")
    owner_login = owner.get("login") if isinstance(owner, dict) else None
    if not isinstance(client_id, str) or not CLIENT_ID_PATTERN.fullmatch(client_id):
        raise ValueError("GitHub manifest response omitted a valid client ID")
    if not isinstance(client_secret, str) or not CLIENT_SECRET_PATTERN.fullmatch(client_secret):
        raise ValueError("GitHub manifest response omitted a valid client secret")
    if not isinstance(app_id, int) or app_id <= 0:
        raise ValueError("GitHub manifest response omitted a valid app ID")
    if not isinstance(app_slug, str) or not app_slug:
        raise ValueError("GitHub manifest response omitted a valid app slug")
    if not isinstance(owner_login, str) or not secrets.compare_digest(
        owner_login.casefold(), expected_owner.casefold()
    ):
        raise ValueError("GitHub App owner did not match the expected account")

    ensure_private_output_directory(output_dir)
    write_new_private_file(output_dir / "github-client.id", client_id)
    try:
        write_new_private_file(output_dir / "github-client.secret", client_secret)
        status = {
            "app_id": app_id,
            "app_slug": app_slug,
            "client_id": client_id,
            "complete": True,
            "owner": owner_login,
        }
        write_new_private_file(
            output_dir / "complete.json",
            json.dumps(status, separators=(",", ":"), sort_keys=True),
        )
    except BaseException:
        for name in ("github-client.id", "github-client.secret", "complete.json"):
            try:
                (output_dir / name).unlink()
            except FileNotFoundError:
                pass
        raise
    return status


def exchange_manifest_code(code: str) -> dict[str, Any]:
    if not MANIFEST_CODE_PATTERN.fullmatch(code):
        raise ValueError("GitHub returned an invalid manifest code")
    request = urllib.request.Request(
        f"https://api.github.com/app-manifests/{code}/conversions",
        data=b"",
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "HeteroNetwork-Keycloak-Bootstrap",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            body = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        error.read(4096)
        raise RuntimeError(f"GitHub manifest conversion failed with HTTP {error.code}") from error
    if len(body) > 1024 * 1024:
        raise RuntimeError("GitHub manifest response exceeded 1 MiB")
    parsed = json.loads(body)
    if not isinstance(parsed, dict):
        raise RuntimeError("GitHub manifest response was not an object")
    return parsed


class ManifestState:
    def __init__(
        self,
        *,
        manifest: dict[str, Any],
        registration_state: str,
        callback_path: str,
        output_dir: Path,
        expected_owner: str,
    ) -> None:
        self.manifest = manifest
        self.registration_state = registration_state
        self.callback_path = callback_path
        self.output_dir = output_dir
        self.expected_owner = expected_owner
        self.complete = threading.Event()
        self.result: dict[str, Any] | None = None


class ManifestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "HeteroNetworkManifest/1.0"

    @property
    def manifest_state(self) -> ManifestState:
        return self.server.manifest_state  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format_string: str, *args: object) -> None:
        print(f"{self.client_address[0]} - {format_string % args}", flush=True)

    def log_request(self, code: object = "-", size: object = "-") -> None:
        print(
            f"{self.client_address[0]} - {self.command} "
            f"{sanitized_request_path(self.path)} {code} {size}",
            flush=True,
        )

    def send_html(self, status: int, title: str, body: str) -> None:
        payload = (
            "<!doctype html><html lang=\"en\"><head>"
            "<meta charset=\"utf-8\"><meta name=\"viewport\" "
            "content=\"width=device-width,initial-scale=1\">"
            f"<title>{html.escape(title)}</title>"
            "<style>body{font:16px system-ui;max-width:42rem;margin:4rem auto;"
            "padding:0 1rem;color:#171717}button{font:inherit;padding:.7rem 1rem}"
            "}</style></head><body>"
            f"{body}</body></html>"
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action https://github.com")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/":
            if self.manifest_state.complete.is_set():
                self.send_html(410, "Completed", "<h1>Registration already completed</h1>")
                return
            manifest_json = json.dumps(
                self.manifest_state.manifest, separators=(",", ":"), ensure_ascii=True
            )
            form_action = (
                "https://github.com/settings/apps/new?state="
                + urllib.parse.quote(self.manifest_state.registration_state, safe="")
            )
            body = (
                "<h1>Register HeteroNetwork GitHub sign-in</h1>"
                f"<form action=\"{html.escape(form_action)}\" method=\"post\">"
                f"<input type=\"hidden\" name=\"manifest\" value=\"{html.escape(manifest_json, quote=True)}\">"
                "<button type=\"submit\">Continue to GitHub</button></form>"
            )
            self.send_html(200, "Register GitHub App", body)
            return
        if parsed.path != self.manifest_state.callback_path:
            self.send_error(404)
            return
        try:
            query = urllib.parse.parse_qs(parsed.query, strict_parsing=True)
        except ValueError:
            self.send_html(400, "Invalid callback", "<h1>Invalid registration callback</h1>")
            return
        state = query.get("state", [""])[0]
        code = query.get("code", [""])[0]
        if not secrets.compare_digest(state, self.manifest_state.registration_state):
            self.send_html(400, "Invalid state", "<h1>Registration state mismatch</h1>")
            return
        try:
            response = exchange_manifest_code(code)
            self.manifest_state.result = persist_app_credentials(
                self.manifest_state.output_dir,
                response,
                self.manifest_state.expected_owner,
            )
        except Exception as error:  # The response intentionally omits secret details.
            print(f"manifest callback failed: {type(error).__name__}: {error}", flush=True)
            self.send_html(502, "Registration failed", "<h1>GitHub App registration failed</h1>")
            return
        self.send_html(200, "Registration complete", "<h1>Registration complete</h1>")
        self.manifest_state.complete.set()
        threading.Thread(target=self.server.shutdown, daemon=True).start()


class ManifestServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        server_address: tuple[str, int],
        state: ManifestState,
    ) -> None:
        self.manifest_state = state
        super().__init__(server_address, ManifestHandler)


def run_self_test() -> None:
    manifest = build_manifest(
        app_name="HeteroNetwork Kakurizai Login",
        homepage_url="https://163.220.236.51",
        redirect_url="http://100.105.153.15:39090/callback/test",
        keycloak_realm="kakurizai",
        callback_urls=[
            "https://163.220.236.51/realms/kakurizai/broker/github/endpoint",
            "https://163.220.236.52/realms/kakurizai/broker/github/endpoint",
        ],
    )
    assert manifest["public"] is False
    assert "default_permissions" not in manifest
    assert "default_events" not in manifest
    assert (
        sanitized_request_path("/callback/private?code=secret&state=secret")
        == "/callback/<redacted>"
    )
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir) / "output"
        status = persist_app_credentials(
            output_dir,
            {
                "client_id": "Iv1.0123456789abcdef",
                "client_secret": "0123456789abcdef0123456789abcdef01234567",
                "id": 123,
                "slug": "heteronetwork-kakurizai-login",
                "owner": {"login": "mizuamedesu"},
            },
            "mizuamedesu",
        )
        assert status["complete"] is True
        assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
        for name in ("github-client.id", "github-client.secret", "complete.json"):
            assert stat.S_IMODE((output_dir / name).stat().st_mode) == 0o600
    print("GitHub App manifest server self-test passed")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--listen", type=parse_listen)
    parser.add_argument("--public-base-url")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--app-name", default="HeteroNetwork Kakurizai Login")
    parser.add_argument("--expected-owner", default="mizuamedesu")
    parser.add_argument("--homepage-url", default="https://163.220.236.51")
    parser.add_argument("--keycloak-realm", default="kakurizai")
    parser.add_argument("--callback-url", action="append", default=[])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return 0
    if args.listen is None or args.public_base_url is None or args.output_dir is None:
        raise SystemExit("--listen, --public-base-url, and --output-dir are required")
    if len(args.callback_url) != 2:
        raise SystemExit("--callback-url must be supplied exactly twice")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", args.expected_owner):
        raise SystemExit("--expected-owner must be a valid GitHub login")

    public_base_url = validate_http_url(args.public_base_url, allow_http=True)
    listen_host, listen_port = args.listen
    public = urllib.parse.urlsplit(public_base_url)
    if public.hostname != listen_host or (public.port or (443 if public.scheme == "https" else 80)) != listen_port:
        raise SystemExit("public base URL must match the listen address")

    ensure_private_output_directory(args.output_dir)
    callback_path = "/callback/" + secrets.token_urlsafe(24)
    registration_state = secrets.token_urlsafe(32)
    redirect_url = public_base_url + callback_path
    manifest = build_manifest(
        app_name=args.app_name,
        homepage_url=args.homepage_url,
        redirect_url=redirect_url,
        callback_urls=args.callback_url,
        keycloak_realm=args.keycloak_realm,
    )
    state = ManifestState(
        manifest=manifest,
        registration_state=registration_state,
        callback_path=callback_path,
        output_dir=args.output_dir,
        expected_owner=args.expected_owner,
    )
    server = ManifestServer((listen_host, listen_port), state)
    print(f"registration_url={public_base_url}/", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    if state.result is None:
        return 1
    print(
        json.dumps(
            {
                "app_id": state.result["app_id"],
                "app_slug": state.result["app_slug"],
                "client_id": state.result["client_id"],
                "complete": True,
                "owner": state.result["owner"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
