#!/usr/bin/env python3
"""Test the private connector over an isolated WireGuard tunnel in a disposable runner.

This deliberately does not enroll a production HeteroNetwork client. Both peers,
addresses, keys, and the mock identity server exist only for this test.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time


CONFIG = Path(__file__).resolve().parents[1] / "deploy/gitops/cluster-dns/keycloak-haproxy.cfg"
VPN_SERVER = "10.253.179.1"
VPN_CLIENT = "10.253.179.2"
UNDERLAY_SERVER = "198.18.173.1"
UNDERLAY_CLIENT = "198.18.173.2"


class Backend(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run(*args, input=None, check=True):
    return subprocess.run(args, input=input, text=True, capture_output=True, check=check)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("the isolated WireGuard test must run as root")
    suffix = secrets.token_hex(3)
    namespace, veth_host, veth_client, wg_host = (
        "hn" + suffix, "vh" + suffix, "vc" + suffix, "wh" + suffix
    )
    backend = ThreadingHTTPServer(("127.0.0.1", 18080), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    process = None
    namespace_created = False
    veth_created = False
    wg_created = False
    try:
        with tempfile.TemporaryDirectory(prefix="hn-private-vpn-e2e-") as directory:
            root = Path(directory)
            server_key, client_key = root / "server.key", root / "client.key"
            for key in (server_key, client_key):
                key.write_text(run("wg", "genkey").stdout)
                key.chmod(0o600)
            server_public = run("wg", "pubkey", input=server_key.read_text()).stdout.strip()
            client_public = run("wg", "pubkey", input=client_key.read_text()).stdout.strip()

            run("ip", "netns", "add", namespace)
            namespace_created = True
            run("ip", "link", "add", veth_host, "type", "veth", "peer", "name", veth_client)
            veth_created = True
            run("ip", "link", "set", veth_client, "netns", namespace)
            run("ip", "addr", "add", UNDERLAY_SERVER + "/30", "dev", veth_host)
            run("ip", "link", "set", veth_host, "up")
            run("ip", "-n", namespace, "link", "set", "lo", "up")
            run("ip", "-n", namespace, "addr", "add", UNDERLAY_CLIENT + "/30", "dev", veth_client)
            run("ip", "-n", namespace, "link", "set", veth_client, "up")
            run("ip", "link", "add", wg_host, "type", "wireguard")
            wg_created = True
            run("ip", "addr", "add", VPN_SERVER + "/24", "dev", wg_host)
            run("wg", "set", wg_host, "private-key", str(server_key), "listen-port", "51963",
                "peer", client_public, "allowed-ips", VPN_CLIENT + "/32")
            run("ip", "link", "set", wg_host, "up")
            run("ip", "-n", namespace, "link", "add", "wg0", "type", "wireguard")
            run("ip", "-n", namespace, "addr", "add", VPN_CLIENT + "/24", "dev", "wg0")
            run("ip", "netns", "exec", namespace, "wg", "set", "wg0", "private-key", str(client_key),
                "peer", server_public, "allowed-ips", VPN_SERVER + "/32",
                "endpoint", UNDERLAY_SERVER + ":51963", "persistent-keepalive", "5")
            run("ip", "-n", namespace, "link", "set", "wg0", "up")

            original = CONFIG.read_text()
            if original.count("bind :18079") != 1:
                raise RuntimeError("identity connector bind changed; review the VPN test")
            config = root / "haproxy.cfg"
            config.write_text(original.replace("bind :18079", "bind " + VPN_SERVER + ":18079"))
            env = {**os.environ, "NODE_IP": "127.0.0.1"}
            subprocess.run(["haproxy", "-c", "-f", str(config)], env=env, check=True,
                           stdout=subprocess.DEVNULL)
            process = subprocess.Popen(["haproxy", "-f", str(config)], env=env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            def curl(address, path):
                return run("ip", "netns", "exec", namespace, "curl", "--silent", "--show-error",
                           "--fail", "--noproxy", "*", "--connect-timeout", "2", "--max-time", "4",
                           "-H", "Host: console.heteronetwork.internal:18079",
                           "http://" + address + ":18079" + path, check=False)

            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                result = curl(VPN_SERVER, "/connector-ready")
                if result.returncode == 0:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("private connector was not reachable through WireGuard")
            for path in ("/realms/heteronetwork/device", "/resources/theme/login.css"):
                result = curl(VPN_SERVER, path)
                if result.returncode or result.stdout != path:
                    raise RuntimeError("private connector did not forward the expected VPN request: " + path)
            for path in ("/admin/", "/metrics"):
                if curl(VPN_SERVER, path).returncode == 0:
                    raise RuntimeError("private connector exposed an unrelated path: " + path)
            if curl(UNDERLAY_SERVER, "/realms/heteronetwork/device").returncode == 0:
                raise RuntimeError("private identity was reachable via the underlay")
            handshake = run("wg", "show", wg_host, "latest-handshakes").stdout.split()
            if len(handshake) != 2 or int(handshake[1]) < time.time() - 60:
                raise RuntimeError("WireGuard did not establish a recent handshake")
            print("isolated WireGuard E2E: private identity and assets reachable only via VPN")
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if wg_created:
            run("ip", "link", "delete", wg_host, check=False)
        if veth_created:
            run("ip", "link", "delete", veth_host, check=False)
        if namespace_created:
            run("ip", "netns", "delete", namespace, check=False)
        backend.shutdown()
        thread.join()
        backend.server_close()


if __name__ == "__main__":
    main()
