#!/usr/bin/env python3
"""Verify the console through a freshly registered, real WireGuard client."""

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time
import urllib.request
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
CONSOLE_CHECK = ROOT / "scripts/verify-console-gateways.mjs"
AUTHENTICATED_CONSOLE_CHECK = ROOT / "scripts/heteronetwork-console-browser-e2e.mjs"
CONSOLE_IDENTITY_RECONCILER = ROOT / "scripts/reconcile-console-e2e-user.py"
OVERLAY_MTU = 1280
CONSOLE_DNS_NAME = "console.heteronetwork.internal"
CONSOLE_PORT = 9781


def b64url(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def generate_registration():
    identity = Ed25519PrivateKey.generate()
    wireguard = X25519PrivateKey.generate()
    identity_public = identity.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    wireguard_public = wireguard.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    identity_public_b64 = base64.b64encode(identity_public).decode("ascii")
    wireguard_public_b64 = base64.b64encode(wireguard_public).decode("ascii")
    client_id = "node-" + hashlib.sha256(identity_public).digest()[:16].hex()
    issued_at = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    expires_at = issued_at + datetime.timedelta(minutes=15)
    nonce = b64url(secrets.token_bytes(24))
    payload = (
        "heteronetwork-client-registration-v1\n"
        f"{client_id}\n{identity_public_b64}\n{wireguard_public_b64}\n"
        f"{int(issued_at.timestamp())}\n{int(expires_at.timestamp())}\n{nonce}\n"
    ).encode()
    bundle = {
        "schema_version": 1,
        "registration": {
            "client_id": client_id,
            "identity_public_key": identity_public_b64,
            "wireguard_public_key": wireguard_public_b64,
        },
        "issued_at": timestamp(issued_at),
        "expires_at": timestamp(expires_at),
        "nonce": nonce,
        "signature": base64.b64encode(identity.sign(payload)).decode("ascii"),
    }
    encoded = b64url(json.dumps(bundle, separators=(",", ":")).encode())
    request_uri = f"heteronetwork://register?request={encoded}"
    private = wireguard.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return request_uri, identity, base64.b64encode(private).decode("ascii"), client_id


def sponsor(inventory, request_uri):
    all_hosts = inventory["all"]
    variables = all_hosts["vars"]
    bootstrap = all_hosts["children"]["bootstrap"]["hosts"]["uc-k8sp5"]["ansible_host"]
    password = os.environ.pop("HNN_IAC_BECOME_PASSWORD", "")
    if not password:
        raise RuntimeError("HNN_IAC_BECOME_PASSWORD is required for client sponsorship")
    remote = (
        "sudo -S -p '' /opt/heteronetwork/bin/ipars client register "
        + shlex.quote(request_uri)
    )
    result = subprocess.run(
        [
            "ssh", "-i", variables["ansible_ssh_private_key_file"],
            "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + variables["ansible_ssh_common_args"].split(
                "UserKnownHostsFile=", 1)[1].split()[0],
            "-o", "ConnectTimeout=10",
            f"{variables['ansible_user']}@{bootstrap}", remote,
        ],
        input=password + "\n", capture_output=True, text=True, timeout=45,
    )
    if result.returncode:
        raise RuntimeError("client sponsorship failed: " + result.stderr.strip()[:500])
    lines = [line.strip() for line in result.stdout.splitlines()
             if line.strip().startswith("heteronetwork://import?")]
    if len(lines) != 1:
        raise RuntimeError("client sponsorship did not return one import profile")
    return lines[0]


def private_credential_file(path):
    path = path.expanduser()
    if not path.is_absolute():
        raise RuntimeError("console credential file must use an absolute path")
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or path.is_symlink()
            or metadata.st_nlink != 1 or metadata.st_size < 2
            or metadata.st_size > 8192 or metadata.st_mode & 0o077):
        raise RuntimeError(
            "console credential file must be a private, single-link regular file")
    return path


def reconcile_console_identity(inventory, credential_file):
    credential_file = private_credential_file(credential_file)
    credential_record = credential_file.read_text()
    if credential_record.count("\n") != 1 or not credential_record.endswith("\n"):
        raise RuntimeError("console credential file must contain one JSON record")
    all_hosts = inventory["all"]
    variables = all_hosts["vars"]
    bootstrap = all_hosts["children"]["bootstrap"]["hosts"]["uc-k8sp5"]["ansible_host"]
    password = os.environ.get("HNN_IAC_BECOME_PASSWORD", "")
    if not password:
        raise RuntimeError("HNN_IAC_BECOME_PASSWORD is required for identity reconciliation")
    known_hosts = variables["ansible_ssh_common_args"].split(
        "UserKnownHostsFile=", 1)[1].split()[0]
    remote = "sudo -S -p '' python3 -c " + shlex.quote(
        CONSOLE_IDENTITY_RECONCILER.read_text())
    result = subprocess.run(
        [
            "ssh", "-i", variables["ansible_ssh_private_key_file"],
            "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + known_hosts,
            "-o", "ConnectTimeout=10",
            f"{variables['ansible_user']}@{bootstrap}", remote,
        ],
        input=password + "\n" + credential_record,
        capture_output=True, text=True, timeout=60,
    )
    credential_record = ""
    if result.returncode:
        raise RuntimeError(
            "console E2E identity reconciliation failed without exposing credentials: "
            + result.stderr.strip()[-500:])
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("console E2E identity reconciliation returned invalid output") from error
    if response.get("result") != "reconciled" or not isinstance(response.get("created"), bool):
        raise RuntimeError("console E2E identity reconciliation was not confirmed")
    return response


def browser_environment():
    """Keep unrelated job secrets out of Node and Chromium child processes."""
    environment = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/root"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    for name in ("PLAYWRIGHT_BROWSERS_PATH", "XDG_CACHE_HOME", "TMPDIR"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    return environment


def decode_profile(uri):
    parsed = urlparse(uri)
    query = parse_qs(parsed.query, strict_parsing=True)
    if parsed.scheme != "heteronetwork" or parsed.netloc != "import" or set(query) != {"profile"}:
        raise RuntimeError("invalid import profile URI")
    encoded = query["profile"]
    if len(encoded) != 1:
        raise RuntimeError("ambiguous import profile URI")
    data = base64.urlsafe_b64decode(encoded[0] + "=" * (-len(encoded[0]) % 4))
    return json.loads(data)


def select_gateway(profile):
    peers = profile["registration"]["peer_map"]["peers"]
    choices = []
    for peer in peers:
        for candidate in peer["endpoint_candidates"]:
            if candidate["kind"] not in ("ipv6", "public_udp"):
                continue
            # GitHub-hosted runners do not advertise usable IPv6. Prefer the
            # public IPv4/UDP endpoint so the live CI path is deterministic,
            # while retaining IPv6 as a fallback for other environments.
            choices.append((0 if candidate["kind"] == "public_udp" else 1,
                            candidate["cost"], -candidate["priority"],
                            candidate["addr"], peer))
    if not choices:
        raise RuntimeError("import profile has no public WireGuard gateway")
    _, _, _, endpoint, peer = min(choices, key=lambda value: value[:4])
    return peer, endpoint


def safe_routes(peer):
    gateway = ipaddress.ip_address(peer["vpn_ip"])
    routes = [ipaddress.ip_network(f"{gateway}/{gateway.max_prefixlen}")]
    routes.extend(ipaddress.ip_network(route["cidr"], strict=True) for route in peer["routes"])
    for route in routes:
        if route.version != 4 or not route.subnet_of(ipaddress.ip_network("10.250.0.0/16")):
            raise RuntimeError(f"gateway returned an unsafe client route: {route}")
    return list(dict.fromkeys(str(route) for route in routes))


def run_checked(*command, timeout=15):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)


def wait_for_interface(name, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("wireguard-go exited before creating its interface")
        if subprocess.run(["ip", "link", "show", name], capture_output=True).returncode == 0:
            return
        time.sleep(0.1)
    raise RuntimeError("wireguard-go did not create its interface")


def wait_for_handshake(name, gateway):
    for _ in range(100):
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", gateway],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        handshakes = run_checked("wg", "show", name, "latest-handshakes").stdout.split()
        if handshakes and int(handshakes[-1]) > 0:
            return int(handshakes[-1])
        time.sleep(0.1)
    raise RuntimeError("real client WireGuard handshake was not established")


def configure_tunnel(work, profile, peer, endpoint, private_key):
    name = "hne2e" + secrets.token_hex(3)
    log_path = work / "wireguard.log"
    log = log_path.open("w")
    os.chmod(log_path, 0o600)
    process = None
    try:
        kernel = subprocess.run(
            ["ip", "link", "add", "dev", name, "type", "wireguard"],
            capture_output=True, text=True)
        if kernel.returncode:
            wireguard_go = shutil.which("wireguard-go")
            if wireguard_go is None:
                raise RuntimeError(
                    "kernel WireGuard is unavailable and wireguard-go is not installed: "
                    + kernel.stderr.strip()[:300])
            process = subprocess.Popen(
                [wireguard_go, "-f", name], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log)
            wait_for_interface(name, process)
        else:
            log.write("using kernel WireGuard\n")
            log.flush()
        routes = safe_routes(peer)
        config = work / "wireguard.conf"
        config.write_text(
            "[Interface]\nPrivateKey = " + private_key + "\n\n"
            "[Peer]\nPublicKey = " + peer["wireguard_public_key"] + "\n"
            "Endpoint = " + endpoint + "\nAllowedIPs = " + ", ".join(routes) + "\n"
            "PersistentKeepalive = 5\n")
        config.chmod(0o600)
        client_ip = ipaddress.ip_address(profile["registration"]["client"]["vpn_ip"])
        if client_ip.version != 4 or client_ip not in ipaddress.ip_network("10.250.0.0/16"):
            raise RuntimeError("control plane returned an unsafe client address")
        run_checked("wg", "setconf", name, str(config))
        run_checked("ip", "address", "add", f"{client_ip}/32", "dev", name)
        run_checked("ip", "link", "set", "dev", name, "mtu", str(OVERLAY_MTU), "up")
        for route in routes:
            run_checked("ip", "route", "add", route, "dev", name, "src", str(client_ip))
        return name, process, log, routes
    except Exception:
        subprocess.run(["ip", "link", "delete", name], capture_output=True)
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log.close()
        raise


def browser_check(work, gateway, gateways, output):
    resolv = work / "resolv.conf"
    resolv.write_text(f"nameserver {gateway}\noptions timeout:1 attempts:2\n")
    resolv.chmod(0o600)
    fallback_resolv = work / "fallback-resolv.conf"
    fallback_resolv.write_text(Path("/etc/resolv.conf").read_text())
    fallback_resolv.chmod(0o600)
    inner_output = work / "console-browser.json"
    wrapper = (
        "import os,subprocess,sys;"
        "subprocess.run(['mount','--bind',sys.argv[1],'/etc/resolv.conf'],check=True);"
        "os.execvp('node',['node',sys.argv[2],'--gateways',sys.argv[3],"
        "'--output',sys.argv[4],'--fallbackResolv',sys.argv[5]])"
    )
    result = subprocess.run(
        ["unshare", "-m", "--propagation", "private", "python3", "-c", wrapper,
         str(resolv), str(CONSOLE_CHECK), gateways, str(inner_output),
         str(fallback_resolv)],
        capture_output=True, text=True, timeout=600, env=browser_environment(),
    )
    if result.returncode:
        failure = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError("real client browser E2E failed: " + failure[-1000:])
    report = json.loads(inner_output.read_text())
    if report.get("result") != "passed" or report.get("canonical", {}).get("open_ms", 3001) > 3000:
        raise RuntimeError("real client browser E2E did not satisfy the 3-second gate")
    return report


def authenticated_browser_check(work, gateway, credential_file):
    credential_file = private_credential_file(credential_file)
    artifacts = work / "authenticated-console"
    artifacts.mkdir(mode=0o700)
    environment = browser_environment()
    environment.update({
        "HETERONETWORK_CONSOLE_BROWSER_E2E_CREDENTIAL_FILE": str(credential_file),
        "HETERONETWORK_CONSOLE_BROWSER_E2E_ARTIFACT_DIR": str(artifacts),
        "HETERONETWORK_CONSOLE_BROWSER_E2E_GATEWAY": gateway,
        "HETERONETWORK_CONSOLE_BROWSER_E2E_URL": (
            "http://console.heteronetwork.internal:9781/ui/"),
    })
    result = subprocess.run(
        ["node", str(AUTHENTICATED_CONSOLE_CHECK)],
        capture_output=True, text=True, timeout=180, env=environment,
    )
    reports = list(artifacts.glob("console-browser-*/report.json"))
    if len(reports) != 1:
        raise RuntimeError("authenticated browser E2E did not write one private report")
    browser_report = json.loads(reports[0].read_text())
    if result.returncode or browser_report.get("result") != "passed":
        failure = browser_report.get("failure") or result.stderr.strip() or result.stdout.strip()
        diagnostic = {
            "failure": failure[-1000:],
            "checks": browser_report.get("checks", []),
            "responses": browser_report.get("responses", []),
            "errors": browser_report.get("errors", []),
            "identity_provider": browser_report.get("identityProvider"),
        }
        raise RuntimeError(
            "authenticated console browser E2E failed: "
            + json.dumps(diagnostic, separators=(",", ":")))
    checks = {row.get("check"): row.get("status")
              for row in browser_report.get("checks", [])}
    required = {
        "Authenticated overview": 200,
        "Overview after reload": 200,
        "Refresh cookie in new tab": 200,
        "Authenticated overview in new tab": 200,
    }
    if (checks != required or browser_report.get("authenticated") is not True
            or browser_report.get("sessionRestored") is not True
            or browser_report.get("httpOnlyRefreshCookie") is not True):
        raise RuntimeError("authenticated console browser E2E omitted a required session check")
    return {
        "result": "passed",
        "authenticated": True,
        "session_restored": True,
        "http_only_refresh_cookie": True,
        "checks": checks,
    }


def signed_client_control_request(identity, client_id, kind, active_gateway=None):
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    nonce = b64url(secrets.token_bytes(24))
    if active_gateway is None:
        payload = (
            f"heteronetwork-client-request-v1\n{kind}\n"
            f"{client_id}\n{int(now.timestamp())}\n{nonce}\n"
        ).encode()
    else:
        payload = (
            f"heteronetwork-client-request-v2\n{kind}\n"
            f"{client_id}\n{active_gateway}\n{int(now.timestamp())}\n{nonce}\n"
        ).encode()
    request = {
        "client_id": client_id,
        "request_signature": {
            "signed_at": timestamp(now),
            "nonce": nonce,
            "signature": base64.b64encode(identity.sign(payload)).decode("ascii"),
        },
    }
    if active_gateway is not None:
        request["active_gateway_node_id"] = active_gateway
    return json.dumps(request).encode()


def refresh_client_peers(identity, client_id, peer):
    body = signed_client_control_request(
        identity, client_id, "peer_map", peer["node_id"])
    request = urllib.request.Request(
        f"http://{peer['vpn_ip']}/v1/clients/peers/query", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        data = json.load(response)
    peers = data.get("peer_map", {}).get("peers", [])
    if not peers or peers[0].get("node_id") != peer["node_id"]:
        raise RuntimeError("control plane did not retain the active client gateway")
    return data["peer_map"].get("generated_at")


def gateway_client_probe_is_ready(gateway):
    request = urllib.request.Request(
        f"http://{gateway}/v1/web-ui/healthz",
        headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=1) as response:
            return response.status == 200 and json.load(response).get("status") == "ok"
    except Exception:
        return False


def dns_a_query(name, query_id):
    labels = name.rstrip(".").split(".")
    if (not labels or any(not label or len(label.encode("ascii")) > 63
                          for label in labels)):
        raise ValueError("invalid DNS query name")
    question = b"".join(
        bytes([len(label.encode("ascii"))]) + label.encode("ascii")
        for label in labels
    ) + b"\x00" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question


def skip_dns_name(message, offset):
    labels = 0
    while True:
        if offset >= len(message):
            raise ValueError("truncated DNS name")
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(message):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if pointer >= offset:
                raise ValueError("invalid DNS compression pointer")
            return offset + 2
        if length & 0xC0 or length > 63:
            raise ValueError("invalid DNS label")
        offset += 1
        if length == 0:
            return offset
        if offset + length > len(message):
            raise ValueError("truncated DNS label")
        offset += length
        labels += 1
        if labels > 127:
            raise ValueError("DNS name has too many labels")


def dns_a_answers(message, query_id):
    if len(message) < 12:
        raise ValueError("truncated DNS response")
    response_id, flags, questions, answers, _, _ = struct.unpack(
        "!HHHHHH", message[:12])
    if (response_id != query_id or flags & 0x8000 == 0 or flags & 0x0200
            or flags & 0x000F or questions != 1):
        raise ValueError("invalid DNS response")
    offset = skip_dns_name(message, 12)
    if offset + 4 > len(message):
        raise ValueError("truncated DNS question")
    offset += 4
    if message[12:offset] != dns_a_query(CONSOLE_DNS_NAME, query_id)[12:]:
        raise ValueError("unexpected DNS question")
    addresses = []
    for _ in range(answers):
        offset = skip_dns_name(message, offset)
        if offset + 10 > len(message):
            raise ValueError("truncated DNS answer")
        record_type, record_class, _, length = struct.unpack(
            "!HHIH", message[offset:offset + 10])
        offset += 10
        if offset + length > len(message):
            raise ValueError("truncated DNS record data")
        if record_type == 1 and record_class == 1 and length == 4:
            addresses.append(socket.inet_ntoa(message[offset:offset + length]))
        offset += length
    return addresses


def overlay_dns_resolves_to_gateway(gateway):
    query_id = secrets.randbits(16)
    query = dns_a_query(CONSOLE_DNS_NAME, query_id)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(query, (gateway, 53))
            response, source = client.recvfrom(4096)
        return (source[0] == gateway and source[1] == 53
                and dns_a_answers(response, query_id) == [gateway])
    except (OSError, ValueError):
        return False


def gateway_console_ui_is_ready(gateway):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    headers = {
        "Accept": "text/html",
        "Host": f"{CONSOLE_DNS_NAME}:{CONSOLE_PORT}",
    }
    try:
        request = urllib.request.Request(
            f"http://{gateway}:{CONSOLE_PORT}/ui/", headers=headers)
        with opener.open(request, timeout=1) as response:
            document = response.read(128 * 1024)
            if (response.status != 200 or b'<div id="root"></div>' not in document
                    or b'<script src="/ui/app.js" async></script>' not in document):
                return False
        request = urllib.request.Request(
            f"http://{gateway}:{CONSOLE_PORT}/ui/config",
            headers={**headers, "Accept": "application/json"})
        with opener.open(request, timeout=1) as response:
            configuration = json.load(response)
        return (response.status == 200
                and configuration.get("auth_enabled") is True
                and configuration.get("provider") == "keycloak")
    except Exception:
        return False


def gateway_route_is_ready(gateway):
    # A small port-80 probe can succeed while the Agent's split DNS or direct
    # port-9781 listener is still starting. Chromium uses all three paths, so
    # do not start its strict three-second timer until each one is usable.
    return (gateway_client_probe_is_ready(gateway)
            and overlay_dns_resolves_to_gateway(gateway)
            and gateway_console_ui_is_ready(gateway))


def wait_for_gateway_routes(gateways, timeout=20):
    started = time.monotonic()
    targets = tuple(sorted(set(gateways.split(","))))
    if not targets or "" in targets:
        raise RuntimeError("at least one gateway is required for route convergence")
    pending = set(targets)
    stable_rounds = 0
    while time.monotonic() - started < timeout:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
            results = dict(zip(targets, executor.map(gateway_route_is_ready, targets)))
        pending = {gateway for gateway, ready in results.items() if not ready}
        if pending:
            stable_rounds = 0
        else:
            stable_rounds += 1
            if stable_rounds == 2:
                return round((time.monotonic() - started) * 1000)
        time.sleep(0.2)
    if pending:
        raise RuntimeError(
            "client console routes, split DNS, and listeners did not converge on gateways: "
            + ", ".join(sorted(pending)))
    raise RuntimeError("client console readiness did not remain stable across two probes")


def remove_client(identity, client_id, peer):
    body = signed_client_control_request(identity, client_id, "remove")
    request = urllib.request.Request(
        f"http://{peer['vpn_ip']}/v1/clients/{client_id}", data=body,
        headers={"Content-Type": "application/json"}, method="DELETE")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=5) as response:
        return response.status == 200


def write_report(path, report):
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(report, indent=2) + "\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--gateways", required=True)
    parser.add_argument("--credential-file", type=Path)
    parser.add_argument("--require-authenticated-console", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    work_root = Path(args.work_dir).expanduser().resolve()
    work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    work = Path(tempfile.mkdtemp(prefix="overlay-client-", dir=work_root))
    work.chmod(0o700)
    report = {"started_at_utc": timestamp(datetime.datetime.now(datetime.timezone.utc)),
              "result": "failed"}
    tunnel = None
    identity = None
    client_id = None
    peer = None
    try:
        if args.require_authenticated_console and args.credential_file is None:
            raise RuntimeError(
                "--credential-file is required by --require-authenticated-console")
        inventory = json.loads((work_root / "inventory.json").read_text())
        if args.credential_file is not None:
            identity_result = reconcile_console_identity(inventory, args.credential_file)
            report["console_identity_reconciled"] = True
            report["console_identity_created"] = identity_result["created"]
        request_uri, identity, private_key, client_id = generate_registration()
        profile = decode_profile(sponsor(inventory, request_uri))
        peer, endpoint = select_gateway(profile)
        report.update({
            "client_id": client_id,
            "client_vpn_ip": profile["registration"]["client"]["vpn_ip"],
            "gateway_node_id": peer["node_id"],
            "gateway_vpn_ip": peer["vpn_ip"],
        })
        name, process, log, routes = configure_tunnel(work, profile, peer, endpoint, private_key)
        tunnel = (name, process, log)
        handshake_at = wait_for_handshake(name, peer["vpn_ip"])
        report.update({
            "wireguard_handshake_at": handshake_at,
            "wireguard_mtu": OVERLAY_MTU,
            "routes": routes,
        })
        report["peer_map_generated_at"] = refresh_client_peers(
            identity, client_id, peer)
        report["route_convergence_ms"] = wait_for_gateway_routes(args.gateways)
        write_report(args.output, report)
        console = browser_check(work, peer["vpn_ip"], args.gateways, args.output)
        if args.credential_file is not None:
            console["authenticated"] = authenticated_browser_check(
                work, peer["vpn_ip"], args.credential_file)
        elif args.require_authenticated_console:
            raise RuntimeError("authenticated console verification was required but skipped")
        report.update({
            "result": "passed",
            "console": console,
        })
    except Exception as error:
        report["failure"] = str(error)
    finally:
        if tunnel is not None:
            name, process, log = tunnel
            if identity is not None and client_id is not None and peer is not None:
                try:
                    report["client_removed"] = remove_client(identity, client_id, peer)
                except Exception as error:
                    report["client_removed"] = False
                    report["client_removal_failure"] = str(error)[:500]
            subprocess.run(["ip", "link", "delete", name], capture_output=True)
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.close()
        if report["result"] == "passed" and not report.get("client_removed"):
            report["result"] = "failed"
            report["failure"] = "temporary E2E client could not be removed"
        report["finished_at_utc"] = timestamp(datetime.datetime.now(datetime.timezone.utc))
        write_report(args.output, report)
        print(json.dumps(report))
        shutil.rmtree(work)
    raise SystemExit(0 if report["result"] == "passed" and report.get("client_removed") else 1)


if __name__ == "__main__":
    main()
