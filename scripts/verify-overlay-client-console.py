#!/usr/bin/env python3
"""Verify the console through a freshly registered, real WireGuard client."""

import argparse
import base64
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
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
    password = os.environ.get("HNN_IAC_BECOME_PASSWORD", "")
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
        run_checked("ip", "link", "set", "dev", name, "mtu", "1420", "up")
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
        capture_output=True, text=True, timeout=600,
    )
    if result.returncode:
        failure = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError("real client browser E2E failed: " + failure[-1000:])
    report = json.loads(inner_output.read_text())
    if report.get("result") != "passed" or report.get("canonical", {}).get("open_ms", 3001) > 3000:
        raise RuntimeError("real client browser E2E did not satisfy the 3-second gate")
    return report


def remove_client(identity, client_id, peer):
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    nonce = b64url(secrets.token_bytes(24))
    payload = (
        "heteronetwork-client-request-v1\nremove\n"
        f"{client_id}\n{int(now.timestamp())}\n{nonce}\n"
    ).encode()
    body = json.dumps({
        "client_id": client_id,
        "active_gateway_node_id": None,
        "request_signature": {
            "signed_at": timestamp(now),
            "nonce": nonce,
            "signature": base64.b64encode(identity.sign(payload)).decode("ascii"),
        },
    }).encode()
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
        inventory = json.loads((work_root / "inventory.json").read_text())
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
        console = browser_check(work, peer["vpn_ip"], args.gateways, args.output)
        report.update({
            "result": "passed",
            "wireguard_handshake_at": handshake_at,
            "routes": routes,
            "console": console,
        })
    except Exception as error:
        failure = str(error)
        password = os.environ.get("HNN_IAC_BECOME_PASSWORD", "")
        report["failure"] = failure.replace(password, "[redacted]") if password else failure
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
