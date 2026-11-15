#!/usr/bin/env python3
"""Exercise CoreDNS's real imported-forwarder reload on an isolated CI runner."""

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "overlay_dns_discovery", ROOT / "deploy/gitops/cluster-dns/overlay-dns-service-discovery.py"
)
assert SPEC and SPEC.loader
discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discovery)
IMAGE = "registry.k8s.io/coredns/coredns@sha256:e7e6440cfd1e919280958f5b5a6ab2b184d385bba774c12ad2a9e1e4183f90d9"
ADDRESSES = ("10.254.254.201", "10.254.254.202")


def command(*args, check=True, timeout=30):
    return subprocess.run(args, check=check, timeout=timeout, capture_output=True, text=True)


def question_end(packet):
    if len(packet) < 17 or packet[4:6] != b"\x00\x01":
        raise ValueError("invalid DNS question")
    offset = 12
    while packet[offset]:
        length = packet[offset]
        if length > 63:
            raise ValueError("invalid DNS label")
        offset += length + 1
        if offset >= len(packet):
            raise ValueError("truncated DNS question")
    end = offset + 5
    if end > len(packet):
        raise ValueError("truncated DNS question")
    return end


def skip_name(packet, offset):
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS pointer")
            return offset + 2
        if length & 0xc0 or length > 63:
            raise ValueError("invalid DNS name")
        offset += 1
        if length == 0:
            return offset
        offset += length


def answer(packet, answer_ip):
    end = question_end(packet)
    query_type = struct.unpack("!H", packet[end - 4:end - 2])[0]
    include_a = query_type == 1
    header = struct.pack("!HHHHHH", struct.unpack("!H", packet[:2])[0], 0x8180, 1, int(include_a), 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton(answer_ip) if include_a else b""
    return header + packet[12:end] + record


class FixtureDns:
    def __init__(self, address, answer_ip):
        self.address = address
        self.answer_ip = answer_ip
        self.stop_event = threading.Event()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((address, 53))
        self.udp.settimeout(0.2)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((address, 53))
        self.tcp.listen(16)
        self.tcp.settimeout(0.2)
        self.threads = [threading.Thread(target=self.serve_udp, daemon=True),
                        threading.Thread(target=self.serve_tcp, daemon=True)]
        for thread in self.threads:
            thread.start()

    def serve_udp(self):
        while not self.stop_event.is_set():
            try:
                packet, peer = self.udp.recvfrom(4096)
                self.udp.sendto(answer(packet, self.answer_ip), peer)
            except (socket.timeout, ValueError, IndexError):
                continue
            except OSError:
                break

    def serve_tcp(self):
        while not self.stop_event.is_set():
            try:
                connection, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                connection.settimeout(1)
                try:
                    size = connection.recv(2, socket.MSG_WAITALL)
                    if len(size) != 2:
                        continue
                    packet = connection.recv(struct.unpack("!H", size)[0], socket.MSG_WAITALL)
                    response = answer(packet, self.answer_ip)
                    connection.sendall(struct.pack("!H", len(response)) + response)
                except (OSError, ValueError, IndexError):
                    continue

    def close(self):
        self.stop_event.set()
        self.udp.close()
        self.tcp.close()
        for thread in self.threads:
            thread.join(timeout=2)


def query(port):
    query_id = secrets.randbits(16)
    name = b"\x05probe\x0dheteronetwork\x08internal\x00"
    request = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(1)
        client.sendto(request, ("127.0.0.1", port))
        response, _ = client.recvfrom(4096)
    if len(response) < 12 or struct.unpack("!H", response[:2])[0] != query_id or response[3] & 15:
        raise ValueError("invalid CoreDNS response")
    if struct.unpack("!H", response[6:8])[0] < 1:
        raise ValueError("CoreDNS returned no answer")
    offset = skip_name(response, question_end(response))
    record_type, record_class, _, size = struct.unpack("!HHIH", response[offset:offset + 10])
    if (record_type, record_class, size) != (1, 1, 4):
        raise ValueError("unexpected CoreDNS answer")
    return socket.inet_ntoa(response[offset + 10:offset + 14])


def write_forward(path, nodes):
    upstreams = discovery.ready_overlay_dns_upstreams(nodes, "10.254.0.0/16")
    assert upstreams
    # Kubernetes projects ConfigMaps through a stable file symlink and swaps
    # its ..data directory symlink atomically. Exercise that actual mechanism,
    # not just an ordinary file replacement.
    revision = ".." + secrets.token_hex(8)
    directory = path.parent / revision
    directory.mkdir(mode=0o755)
    projected = directory / path.name
    projected.write_text(discovery.render_coredns_forward(upstreams))
    projected.chmod(0o644)
    next_link = path.parent / "..data_next"
    next_link.symlink_to(revision, target_is_directory=True)
    os.replace(next_link, path.parent / "..data")
    if not path.is_symlink():
        path.symlink_to("..data/" + path.name)


def node(name, address, ready=True):
    return {"metadata": {"name": name, "annotations": {discovery.VPN_IP_ANNOTATION: address}},
            "status": {"conditions": [{"type": "Ready", "status": "True" if ready else "False"}]}}


def wait_for(predicate, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.15)
    raise RuntimeError("CoreDNS did not converge before the deadline")


def main():
    if os.geteuid() != 0:
        raise RuntimeError("run the isolated CoreDNS E2E as root")
    assigned = []
    fixtures = []
    container = "heteronet-coredns-e2e-" + secrets.token_hex(6)
    started = False
    try:
        existing = command("ip", "-j", "address", "show", "dev", "lo").stdout
        occupied = {item.get("local") for interface in json.loads(existing) for item in interface.get("addr_info", [])}
        if any(address in occupied for address in ADDRESSES):
            raise RuntimeError("fixture address already exists")
        for address in ADDRESSES:
            ipaddress.ip_address(address)
            command("ip", "address", "add", address + "/32", "dev", "lo")
            assigned.append(address)
        fixtures.append(FixtureDns(ADDRESSES[0], "192.0.2.11"))
        fixtures.append(FixtureDns(ADDRESSES[1], "192.0.2.12"))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with tempfile.TemporaryDirectory(prefix="heteronet-coredns-e2e-") as directory:
            root = Path(directory)
            root.chmod(0o755)
            (root / "Corefile").write_text(
                f"heteronetwork.internal:{port} {{\n    errors\n"
                "    import /config/forward.conf\n    reload 2s 0s\n}\n"
            )
            (root / "Corefile").chmod(0o644)
            forward = root / "forward.conf"
            one, two = node("one", ADDRESSES[0]), node("two", ADDRESSES[1])
            write_forward(forward, [one])
            command("docker", "run", "-d", "--name", container, "--network", "host",
                    "-v", f"{root}:/config:ro", IMAGE, "-conf", "/config/Corefile", timeout=240)
            started = True
            time.sleep(0.5)
            running = command("docker", "inspect", "--format", "{{.State.Running}}", container).stdout.strip()
            if running != "true":
                raise RuntimeError("CoreDNS exited before accepting DNS requests")
            wait_for(lambda: query(port) == "192.0.2.11", timeout=30)
            write_forward(forward, [one, two])
            wait_for(lambda: query(port) == "192.0.2.12", timeout=30)
            stopped = node("one", ADDRESSES[0])
            stopped["metadata"]["labels"] = {"heteronetwork.io/lifecycle": "stopped"}
            write_forward(forward, [stopped, two])
            streak = [0]
            def only_second():
                streak[0] = streak[0] + 1 if query(port) == "192.0.2.12" else 0
                return streak[0] >= 20
            wait_for(only_second, timeout=30)
            fixtures[0].close()
            fixtures = fixtures[1:]
            for _ in range(10):
                if query(port) != "192.0.2.12":
                    raise RuntimeError("removed upstream still received DNS traffic")
            print(json.dumps({"result": "passed", "added": True, "stopped_removed": True,
                              "queries_after_removal": 10}))
    except Exception:
        if started:
            logs = command("docker", "logs", container, check=False)
            print((logs.stdout + logs.stderr)[-4000:])
        raise
    finally:
        if started:
            command("docker", "rm", "-f", container, check=False)
        for fixture in fixtures:
            fixture.close()
        for address in reversed(assigned):
            command("ip", "address", "del", address + "/32", "dev", "lo", check=False)


if __name__ == "__main__":
    main()
