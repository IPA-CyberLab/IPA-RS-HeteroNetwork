"""Disposable sudo-v2 integration. Never run directly on a host."""
import concurrent.futures
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time

ROOT = Path("/opt/quorum-lifecycle")
RUN = Path("/run/ipars-sudo-v2")


def ipc():
    request = json.load(sys.stdin)
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(6)
        stream.connect(str(RUN / "submit.sock"))
        payload = json.dumps(request).encode()
        stream.sendall(struct.pack("!I", len(payload)) + payload)
        def read(n):
            data = b""
            while len(data) < n:
                chunk = stream.recv(n - len(data))
                if not chunk:
                    raise RuntimeError("request rejected")
                data += chunk
            return data
        size, = struct.unpack("!I", read(4))
        if size > 16384:
            raise RuntimeError("response exceeds limit")
        print(read(size).decode())


def main():
    if not Path("/.dockerenv").exists() or os.getuid() != 0 or Path(__file__).resolve().parent != ROOT:
        raise SystemExit("disposable root container only")
    subprocess.run([str(ROOT / "disposable-v2-fixture"), "provision"], check=True)
    subprocess.run(["/usr/sbin/chpasswd"], input=b"fixture:disposable-test-password\n", check=True)
    policy = Path("/etc/sudoers.d/quorum-v2-test")
    policy.write_text("Defaults:fixture timestamp_timeout=0, passwd_tries=1\n"
                      "fixture ALL=(root) CWD=/opt/quorum-lifecycle/work PASSWD: /opt/quorum-lifecycle/command\n")
    policy.chmod(0o440)
    subprocess.run(["/usr/sbin/visudo", "-c"], check=True, capture_output=True)
    with Path("/etc/sudo.conf").open("a") as config:
        config.write(f"\nPlugin quorum_v2_gate {ROOT}/privilege_v2_gate.so\n")
    command = ["/usr/sbin/runuser", "-u", "fixture", "--", "/usr/bin/sudo", "-k", "-S", "-p", "", str(ROOT / "command")]
    children = []
    service = None

    def fixture(mode, value=None):
        result = subprocess.run([str(ROOT / "disposable-v2-fixture"), mode],
                                input=None if value is None else json.dumps(value).encode(), capture_output=True, timeout=8)
        assert result.returncode == 0, "offline typed fixture failed (output withheld)"
        return json.loads(result.stdout)

    def launch_service():
        child = subprocess.Popen([str(ROOT / "local-sudo-v2")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if child.poll() is not None:
                raise AssertionError("v2 service startup rejected")
            if (RUN / "submit.sock").exists():
                return child
            time.sleep(.02)
        child.kill()
        child.communicate(timeout=8)
        raise AssertionError("v2 service startup deadline")

    def request(nonce, operation, user="fixture", version=2):
        value = {"version": version, "nonce": nonce, "operation": operation}
        return subprocess.run(["/usr/sbin/runuser", "-u", user, "--", "python3", __file__, "ipc"],
                              input=json.dumps(value).encode(), capture_output=True, timeout=8)

    def response(result, expected):
        assert result.returncode == 0, "v2 request rejected (output withheld)"
        value = json.loads(result.stdout)
        assert value["version"] == 2 and value["response"]["type"] == expected
        return value["response"]

    def start_sudo():
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        child.stdin.write(b"disposable-test-password\n")
        child.stdin.close()
        child.stdin = None
        assert select.select([child.stdout], [], [], 8)[0], "v2 challenge handle deadline"
        line = child.stdout.readline().strip()
        prefix = b"sudo-v2 approval handle: "
        assert line.startswith(prefix), "v2 adapter did not create an invocation"
        nonce = list(bytes.fromhex(line[len(prefix):].decode()))
        assert len(nonce) == 32 and any(nonce)
        return child, nonce

    def cleanup_sockets():
        for name in ("adapter.sock", "submit.sock"):
            (RUN / name).unlink()

    try:
        service = launch_service()
        wrong = subprocess.run(command, input=b"wrong\n", capture_output=True, timeout=8)
        assert wrong.returncode != 0 and b"approval handle" not in wrong.stdout
        denied = subprocess.run(command[:-1] + ["/usr/bin/true"], input=b"disposable-test-password\n", capture_output=True, timeout=8)
        assert denied.returncode != 0 and b"approval handle" not in denied.stdout
        spoof = subprocess.run(["/usr/sbin/runuser", "-u", "fixture", "--", "python3", "-c",
            "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/ipars-sudo-v2/adapter.sock')"], capture_output=True, timeout=5)
        assert spoof.returncode != 0
        child, nonce = start_sudo()
        public = fixture("requester")
        bind = {"type": "bind_requester", "requester_public_key": public}
        assert request(nonce, bind, user="other").returncode != 0
        assert request(nonce, bind, version=1).returncode != 0
        assert request(nonce, dict(bind, caller_uid=0)).returncode != 0
        assert request(nonce, {"type": "bind_requester", "requester_public_key": [0] * 32}).returncode != 0
        challenge = response(request(nonce, bind), "challenge")["challenge"]
        grant = challenge["grant"]
        assert grant["nonce"] == nonce and grant["caller_uid"] == 1000 and grant["host_node_id"] == "node-1"
        assert grant["requester_public_key"] == public
        assert request(nonce, bind).returncode != 0, "requester binding is immutable"
        token = fixture("issue", challenge)
        bad = json.loads(json.dumps(token))
        bad["signature"][0] ^= 1
        assert request(nonce, {"type": "submit_token", "token": bad}).returncode != 0
        invocation = response(request(nonce, {"type": "submit_token", "token": token}), "redemption")["invocation"]
        assert invocation["nonce"] != nonce and any(invocation["nonce"])
        assert invocation["caller_uid"] == 1000 and invocation["expires_at"] <= grant["expires_at"]
        assert request(nonce, {"type": "submit_token", "token": token}).returncode != 0
        assert child.poll() is None, "a token alone must not release sudo"
        wrong_invocation = json.loads(json.dumps(invocation))
        wrong_invocation["nonce"][0] ^= 1
        wrong_proof = fixture("redeem", {"token": token, "invocation": wrong_invocation})
        assert request(nonce, {"type": "redeem", "requester_proof": wrong_proof}).returncode != 0
        proof = fixture("redeem", {"token": token, "invocation": invocation})
        redeem = {"type": "redeem", "requester_proof": proof}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(lambda _: request(nonce, redeem), range(2)))
        assert sum(result.returncode == 0 for result in results) == 1
        stdout, _ = child.communicate(timeout=8)
        assert child.returncode == 0 and b"EXECUTED uid=1" in stdout
        assert request(nonce, redeem).returncode != 0
        print("PASS: v2 host attestation, immutable requester binding, real sudo, fresh redemption PoP, UID/version protections and concurrent replay denial", flush=True)

        child, abandoned = start_sudo()
        assert abandoned != nonce
        service.terminate()
        service.communicate(timeout=8)
        stdout, _ = child.communicate(timeout=8)
        assert child.returncode != 0 and b"EXECUTED" not in stdout
        cleanup_sockets()
        key_path = Path("/etc/ipars-sudo-v2/host.key")
        key = key_path.read_bytes()
        key_path.write_bytes(bytes([44] * 32))
        mismatch = subprocess.run([str(ROOT / "local-sudo-v2")], capture_output=True, timeout=8)
        assert mismatch.returncode != 0 and not (RUN / "adapter.sock").exists()
        key_path.write_bytes(key)
        key_path.chmod(0o644)
        insecure = subprocess.run([str(ROOT / "local-sudo-v2")], capture_output=True, timeout=8)
        assert insecure.returncode != 0 and not (RUN / "adapter.sock").exists()
        key_path.chmod(0o600)
        service = launch_service()
        assert request(nonce, redeem).returncode != 0
        # A trusted adapter cannot reuse even an abandoned persisted nonce after restart.
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(5)
            stream.connect(str(RUN / "adapter.sock"))
            stream.sendall(b"SQV2" + struct.pack("!I", 1000) + bytes(abandoned))
            assert stream.recv(1) == b""
        print("PASS: disconnect/restart, durable adapter nonce uniqueness and root host-key provenance/pinning", flush=True)

        child, expired = start_sudo()
        response(request(expired, bind), "challenge")
        stdout, _ = child.communicate(timeout=68)
        assert child.returncode != 0 and b"EXECUTED" not in stdout
        assert request(expired, bind).returncode != 0
        print("PASS: real v2 expiry denies admission", flush=True)
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=8)
        if service is not None:
            if service.poll() is None:
                service.terminate()
            service.communicate(timeout=8)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "ipc":
        try:
            ipc()
        except (OSError, ValueError, RuntimeError):
            raise SystemExit("v2 request rejected")
    else:
        main()
