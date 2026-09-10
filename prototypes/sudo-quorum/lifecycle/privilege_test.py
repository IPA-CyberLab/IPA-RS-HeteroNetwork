"""Disposable real-sudo tests. No host mounts, production keys or network."""
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
RUN = Path("/run/ipars-sudo-prototype")


def ipc():
    request = json.load(sys.stdin)
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(6)
        stream.connect(str(RUN / "submit.sock"))
        data = json.dumps(request).encode()
        stream.sendall(struct.pack("!I", len(data)) + data)
        def read(n):
            out = b""
            while len(out) < n:
                chunk = stream.recv(n - len(out))
                if not chunk:
                    raise RuntimeError("submission rejected")
                out += chunk
            return out
        size, = struct.unpack("!I", read(4))
        if size > 16384:
            raise RuntimeError("response too large")
        print(read(size).decode())


def main():
    if not Path("/.dockerenv").exists() or os.getuid() != 0 or Path(__file__).resolve().parent != ROOT:
        raise SystemExit("disposable root container only")
    subprocess.run([str(ROOT / "disposable-fixture"), "provision"], check=True)
    subprocess.run(["/usr/sbin/chpasswd"], input=b"fixture:disposable-test-password\n", check=True)
    policy = Path("/etc/sudoers.d/quorum-privilege")
    policy.write_text("Defaults:fixture timestamp_timeout=0, passwd_tries=1\n"
                      "fixture ALL=(root) CWD=/opt/quorum-lifecycle/work PASSWD: /opt/quorum-lifecycle/command\n")
    policy.chmod(0o440)
    subprocess.run(["/usr/sbin/visudo", "-c"], check=True, capture_output=True)
    with Path("/etc/sudo.conf").open("a") as config:
        config.write(f"\nPlugin quorum_privilege_gate {ROOT}/privilege_gate.so\n")
    sudo_command = ["/usr/sbin/runuser", "-u", "fixture", "--", "/usr/bin/sudo", "-k", "-S", "-p", "", str(ROOT / "command")]
    service = None
    children = []

    def launch_service():
        child = subprocess.Popen([str(ROOT / "local-sudo-grants")], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(100):
            if child.poll() is not None:
                raise AssertionError("grant service failed to start")
            if (RUN / "submit.sock").exists():
                return child
            time.sleep(.02)
        child.kill()
        child.wait()
        raise AssertionError("service startup deadline")

    def request(value, user="fixture"):
        return subprocess.run(["/usr/sbin/runuser", "-u", user, "--", "python3", __file__, "ipc"],
                              input=json.dumps(value).encode(), capture_output=True, timeout=8)

    def start_sudo():
        child = subprocess.Popen(sudo_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        children.append(child)
        child.stdin.write(b"disposable-test-password\n")
        child.stdin.close()
        child.stdin = None
        assert select.select([child.stdout], [], [], 8)[0], "adapter did not expose challenge"
        line = child.stdout.readline().strip()
        prefix = b"sudo privilege approval handle: "
        assert line.startswith(prefix), "challenge unavailable"
        nonce = list(bytes.fromhex(line[len(prefix):].decode()))
        assert len(nonce) == 32
        response = request({"nonce": nonce, "signed": None})
        assert response.returncode == 0, "owner could not fetch challenge"
        return child, json.loads(response.stdout)

    def signed(grant):
        result = subprocess.run([str(ROOT / "disposable-fixture"), "sign"], input=json.dumps(grant).encode(),
                                capture_output=True, check=True, timeout=8)
        return json.loads(result.stdout)

    try:
        service = launch_service()
        wrong_password = subprocess.run(sudo_command, input=b"wrong\n", capture_output=True, timeout=8)
        assert wrong_password.returncode != 0 and b"approval handle" not in wrong_password.stdout
        denied = subprocess.run(sudo_command[:-1] + ["/usr/bin/true"], input=b"disposable-test-password\n", capture_output=True, timeout=8)
        assert denied.returncode != 0 and b"approval handle" not in denied.stdout
        spoof = subprocess.run(["/usr/sbin/runuser", "-u", "fixture", "--", "python3", "-c",
            "import socket; s=socket.socket(socket.AF_UNIX); s.connect('/run/ipars-sudo-prototype/adapter.sock')"], capture_output=True, timeout=5)
        assert spoof.returncode != 0

        # Privileged fixture fills the bounded adapter admission slots without executing anything.
        held = []
        try:
            for _ in range(8):
                stream = socket.socket(socket.AF_UNIX)
                stream.settimeout(5)
                stream.connect(str(RUN / "adapter.sock"))
                stream.sendall(b"SQP1" + struct.pack("!I", 1000))
                assert len(stream.recv(32)) == 32
                held.append(stream)
            with socket.socket(socket.AF_UNIX) as excess:
                excess.settimeout(5)
                excess.connect(str(RUN / "adapter.sock"))
                assert excess.recv(1) == b"", "excess admission must fail closed"
        finally:
            for stream in held:
                stream.close()
        time.sleep(.1)

        child, grant = start_sudo()
        approval = signed(grant)
        assert request({"nonce": grant["nonce"], "signed": None}, "other").returncode != 0
        for field, value in (("host_node_id", "wrong-host"), ("caller_uid", 1001), ("epoch", 2), ("expires_at", 1)):
            bad = json.loads(json.dumps(approval))
            bad["grant"][field] = value
            assert request({"nonce": grant["nonce"], "signed": bad}).returncode != 0
        submission = {"nonce": grant["nonce"], "signed": approval}
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(request, [submission, submission]))
        assert sum(result.returncode == 0 for result in results) == 1
        stdout, _ = child.communicate(timeout=8)
        assert child.returncode == 0 and b"EXECUTED uid=1" in stdout
        assert request(submission).returncode != 0
        print("PASS: normal auth/policy, IPC UID protection, scoped denial, majority sudo success, concurrent one-use and replay", flush=True)

        # A bad signature cannot approve, even though its typed fields match the challenge.
        child, grant = start_sudo()
        approval = signed(grant)
        approval["signature"][0] ^= 1
        request({"nonce": grant["nonce"], "signed": approval})
        stdout, _ = child.communicate(timeout=8)
        assert child.returncode != 0 and b"EXECUTED" not in stdout

        # Disconnect invalidates the in-memory invocation; its grant cannot authorize another.
        child, abandoned = start_sudo()
        approval = signed(abandoned)
        service.terminate()
        service.communicate(timeout=8)
        stdout, _ = child.communicate(timeout=8)
        assert child.returncode != 0 and b"EXECUTED" not in stdout
        for name in ("adapter.sock", "submit.sock"):
            (RUN / name).unlink()  # Only this disposable service's sockets, never database/anchor.
        service = launch_service()
        assert request(submission).returncode != 0
        assert request({"nonce": abandoned["nonce"], "signed": approval}).returncode != 0
        print("PASS: bad signature, daemon disconnect and restart rejection", flush=True)

        # Frozen UID mapping cannot be replaced against the durable anchor after restart.
        service.terminate()
        service.communicate(timeout=8)
        for name in ("adapter.sock", "submit.sock"):
            (RUN / name).unlink()
        config = Path("/etc/ipars-sudo-prototype.json")
        original = config.read_bytes()
        altered = json.loads(original)
        altered["owners"]["1000"] = "replacement-owner"
        config.write_text(json.dumps(altered))
        rejected = subprocess.run([str(ROOT / "local-sudo-grants")], capture_output=True, timeout=8)
        assert rejected.returncode != 0 and not (RUN / "adapter.sock").exists()
        config.write_bytes(original)
        config.chmod(0o666)
        rejected = subprocess.run([str(ROOT / "local-sudo-grants")], capture_output=True, timeout=8)
        assert rejected.returncode != 0 and not (RUN / "adapter.sock").exists()
        config.chmod(0o600)
        service = launch_service()
        print("PASS: bounded admission, immutable UID mapping and root-only configuration", flush=True)

        child, expired = start_sudo()
        approval = signed(expired)
        stdout, _ = child.communicate(timeout=68)
        assert child.returncode != 0 and b"EXECUTED" not in stdout
        assert request({"nonce": expired["nonce"], "signed": approval}).returncode != 0
        print("PASS: real 60-second grant expiration denies sudo", flush=True)
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
            raise SystemExit("submission rejected")
    else:
        main()
