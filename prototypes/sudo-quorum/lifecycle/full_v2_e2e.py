"""Disposable full wire E2E. No production inputs; see Dockerfile.full-v2.

Only the requester companion runs as UID 1000. All threshold signatures come
from the real HTTP routers through the real CLI, never an offline token fixture.
"""
import http.server
import ipaddress
import json
import os
from pathlib import Path
import pty
import re
import resource
import select
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

ROOT = Path("/opt/full-v2")
SOCKET = "/run/ipars-sudo-v2/submit.sock"
ADDRESS = "172.30.99.2"
PASSWORD = b"disposable-full-v2-password\n"
CHILDREN = []
CHILD_LOGS = []
TERMINALS = []
CALLS = []


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def ipc():
    value = json.load(sys.stdin)
    data = json.dumps(value).encode()
    check(0 < len(data) <= 16384, "request frame length")
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(6)
        stream.connect(SOCKET)
        stream.sendall(struct.pack("!I", len(data)) + data)

        def read(size):
            result = b""
            while len(result) < size:
                part = stream.recv(size - len(result))
                if not part:
                    raise RuntimeError("local request denied")
                result += part
            return result

        size, = struct.unpack("!I", read(4))
        check(0 < size <= 16384, "response frame length")
        value = json.loads(read(size))
        check(value["version"] == 2, "response version")
        print(json.dumps(value["response"]))


def caller(argv, value=None, timeout=45):
    return subprocess.run(argv, input=None if value is None else json.dumps(value).encode(),
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                          user=1000, group=1000, extra_groups=[], cwd=ROOT)


def local(nonce, operation, success=True):
    result = caller(["python3", __file__, "ipc"],
                    {"version": 2, "nonce": nonce, "operation": operation}, timeout=8)
    if (result.returncode == 0) != success:
        print(f"Local diagnostic: operation={operation['type']} exit={result.returncode} "
              f"hints={resource_hints(result.stderr)}", flush=True)
        metadata = Path(__file__).stat()
        print(f"Public companion mode={metadata.st_mode & 0o777:04o} uid={metadata.st_uid}", flush=True)
        for name in ("pids.current", "pids.max", "pids.events"):
            path = Path("/sys/fs/cgroup") / name
            if path.exists():
                print(f"Local diagnostic: {name}={path.read_text().strip()}", flush=True)
        for index, path in enumerate(CHILD_LOGS):
            print(f"Child diagnostic: index={index} exit={CHILDREN[index].poll()} "
                  f"hints={resource_hints(path.read_bytes()[:65536])}", flush=True)
        raise AssertionError("unexpected local authorization result")
    return json.loads(result.stdout) if success else None


def private(name, value, owner=1000):
    path = ROOT / name
    with path.open("x") as stream:
        stream.write(value if isinstance(value, str) else json.dumps(value))
    path.chmod(0o600)
    os.chown(path, owner, owner)
    return path


class Owner(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/realms/disposable/protocol/openid-connect/userinfo":
            self.send_error(404)
            return
        token = self.headers.get("Authorization")
        CALLS.append(token == "Bearer disposable-owner")
        if token not in ("Bearer disposable-owner", "Bearer disposable-other"):
            self.send_error(401)
            return
        body = json.dumps({"sub": "owner" if token.endswith("-owner") else "other",
                           "email": "owner@example.invalid"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass  # Never log bearer tokens or request bodies.


def resource_hints(data):
    text = data.lower()
    return [word for word in ("memoryerror", "cannot allocate memory", "memory allocation",
                             "can't start new thread", "resource temporarily unavailable",
                             "runtimeerror", "permissionerror", "connectionrefusederror",
                             "timeouterror", "modulenotfounderror", "permission denied") if word.encode() in text]


def spawn(argv):
    path = ROOT / f"child-{len(CHILDREN)}.stderr"
    with path.open("xb") as errors:
        child = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=errors)
    CHILDREN.append(child)
    CHILD_LOGS.append(path)
    return child


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)


def ready(child, predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        check(child.poll() is None, "fixture process exited during readiness")
        try:
            if predicate():
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.05)
    raise AssertionError("fixture readiness deadline")


def signer(number):
    child = spawn([str(ROOT / "sudo_v2_fixture"), "serve", str(number)])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def health():
        with opener.open(f"http://{ADDRESS}:{19100 + number}/healthz", timeout=.3) as response:
            return response.status == 200

    ready(child, health)
    return child


class Invocation:
    def __init__(self, command=None, password=PASSWORD):
        master, slave = pty.openpty()
        self.fd = master
        self.output = b""
        self.child = subprocess.Popen(
            ["/usr/bin/sudo", "-k", "-S", "-p", "fixture-password:"]
            + (command or ["/usr/bin/id", "-u"]),
            stdin=slave, stdout=slave, stderr=slave, user=1000, group=1000,
            extra_groups=[], start_new_session=True, cwd=ROOT)
        os.close(slave)
        TERMINALS.append(self)
        os.write(master, password)

    def drain(self, duration=.1):
        if self.fd is not None and select.select([self.fd], [], [], duration)[0]:
            try:
                self.output += os.read(self.fd, 65536)
            except OSError:
                pass

    def handle(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            self.drain()
            match = re.search(rb"sudo-v2 approval handle: ([0-9a-f]{64})", self.output)
            if match:
                return list(bytes.fromhex(match[1].decode()))
            check(self.child.poll() is None, "sudo exited before live handle")
        raise AssertionError("live sudo handle deadline")

    def finish(self, success, timeout=70):
        deadline = time.monotonic() + timeout
        while self.child.poll() is None and time.monotonic() < deadline:
            self.drain()
        check(self.child.poll() is not None, "sudo completion deadline")
        self.drain(0)
        executed = re.search(rb"(?:^|[\r\n])0\r*\n", self.output) is not None
        check((self.child.returncode == 0) == success and executed == success,
              "actual sudo execution outcome mismatch")

    def disconnect(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGTERM)
        stop(self.child)


def begin(label):
    invocation = Invocation()
    nonce = invocation.handle()
    public = json.loads((ROOT / "requester.pub").read_text())
    reply = local(nonce, {"type": "bind_requester", "requester_public_key": public})
    check(reply["type"] == "challenge", "host challenge reply")
    challenge = reply["challenge"]
    private(f"{label}.challenge", challenge)
    return invocation, nonce, challenge


def issue(label, owner="owner", success=True):
    output = ROOT / "work" / f"{label}.token"
    result = caller([str(ROOT / "ipars"), "quorum", "sudo-issue",
                     "--policy", str(ROOT / "policy.json"),
                     "--challenge", str(ROOT / f"{label}.challenge"),
                     "--requester-key", str(ROOT / "requester.key"),
                     "--oidc-token", str(ROOT / f"{owner}.oidc"),
                     "--token-out", str(output), "--vpn-cidr", "172.30.99.0/24"])
    check((result.returncode == 0) == success, "real CLI issuance outcome mismatch")
    check(output.exists() == success, "failed CLI must not publish token")
    return json.loads(output.read_text()) if success else None


def approve(nonce, success=True):
    result = caller([str(ROOT / "ipars"), "quorum", "sudo-approve",
                     "--handle", bytes(nonce).hex(), "--policy", str(ROOT / "policy.json"),
                     "--requester-key", str(ROOT / "requester.key"),
                     "--oidc-token", str(ROOT / "owner.oidc"), "--vpn-cidr", "172.30.99.0/24"])
    check((result.returncode == 0) == success, "real CLI approval outcome mismatch")


def submit(nonce, token):
    reply = local(nonce, {"type": "submit_token", "token": token})
    check(reply["type"] == "redemption", "fresh local invocation required")
    result = caller([str(ROOT / "sudo_v2_fixture"), "redeem-proof"],
                    [token, reply["invocation"]], timeout=5)
    check(result.returncode == 0, "typed redemption proof generation")
    return json.loads(result.stdout)


def rejected_http(challenge):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    cases = [
        ("/v1/quorum/sudo/round1", {"identifier": 1, "challenge": challenge,
                                    "requester_proof": [0] * 64}, 400),
        ("/v1/quorum/sudo/round1", {"claims": {}, "proof": {}}, 400),
        ("/v1/quorum/sudo/round2", {"transition": {}}, 400),
        ("/v1/quorum/round1", {}, 404),
        ("/v1/quorum/rotation/round1", {}, 404),
    ]
    for path, body, expected in cases:
        request = urllib.request.Request(
            f"http://{ADDRESS}:19101{path}", data=json.dumps(body).encode(),
            headers={"Authorization": "Bearer disposable-owner", "Content-Type": "application/json"})
        try:
            with opener.open(request, timeout=5):
                raise AssertionError("invalid proof/domain accepted by real router")
        except urllib.error.HTTPError as error:
            check(error.code == expected, "unexpected typed router rejection")


def consumed():
    with sqlite3.connect("file:/var/lib/ipars-sudo-v2/sudo-v2.sqlite?mode=ro", uri=True) as db:
        return {bytes(row[0]) for row in db.execute("SELECT nonce FROM sudo_v2_invocations WHERE consumed = 1")}


def main():
    check(Path("/.dockerenv").exists() and os.getuid() == 0
          and Path(__file__).resolve().parent == ROOT, "disposable root container only")
    if os.environ.get("IPARS_SUDO_V2_LOCAL_RLIMITS") == "1":
        check(resource.getrlimit(resource.RLIMIT_AS) == (268435456, 268435456),
              "local mode requires inherited hard address-space bound")
        check(resource.getrlimit(resource.RLIMIT_CPU) == (120, 120),
              "local mode requires inherited hard CPU bound")
        cpus = sorted(os.sched_getaffinity(0))[:2]
        check(bool(cpus), "local mode needs an available CPU")
        os.sched_setaffinity(0, cpus)
        check(len(os.sched_getaffinity(0)) <= 2, "local CPU affinity bound")
        print("Bounded local mode: inherited AS/CPU hard limits and <=2 CPU affinity verified", flush=True)
    check(ipaddress.ip_address(ADDRESS).is_private, "private fixture address")
    with socket.socket() as probe:
        probe.bind((ADDRESS, 0))
    # Refuse an externally routed network. Docker --internal leaves no default route.
    routes = Path("/proc/net/route").read_text().splitlines()[1:]
    check(not any(row.split()[1] == "00000000" for row in routes), "internal network required")
    os.umask(0o077)
    subprocess.run([str(ROOT / "sudo_v2_fixture"), "init"], check=True, timeout=10)
    for name in ("policy.json", "requester.key", "requester.pub"):
        os.chown(ROOT / name, 1000, 1000)
    # Only CLI outputs are writable by the caller; binaries and plugin stay root-owned.
    (ROOT / "work").mkdir(mode=0o700)
    os.chown(ROOT / "work", 1000, 1000)
    private("owner.oidc", "disposable-owner")
    private("other.oidc", "disposable-other")
    subprocess.run(["/usr/sbin/chpasswd"], input=b"fixture:" + PASSWORD, check=True)
    sudoers = Path("/etc/sudoers.d/full-v2")
    sudoers.write_text("Defaults:fixture timestamp_timeout=0, passwd_tries=1\n"
                       "fixture ALL=(root) PASSWD: /usr/bin/id -u\n")
    sudoers.chmod(0o440)
    subprocess.run(["/usr/sbin/visudo", "-c"], check=True, capture_output=True)
    with Path("/etc/sudo.conf").open("a") as config:
        config.write(f"\nPlugin quorum_v2_gate {ROOT}/privilege_v2_gate.so\n")
    owner = http.server.ThreadingHTTPServer(("127.0.0.1", 19200), Owner)
    thread = threading.Thread(target=owner.serve_forever, daemon=True)
    thread.start()
    try:
        signers = [signer(i) for i in range(1, 4)]
        daemon = spawn([str(ROOT / "local-sudo-v2")])
        ready(daemon, lambda: Path(SOCKET).exists())
        check(not consumed(), "disposable ledger must initially be empty")
        successes = set()
        for label in ("all-up", "one-dead"):
            if label == "one-dead":
                stop(signers[2])
            inv, nonce, challenge = begin(label)
            if label == "all-up":
                rejected_http(challenge)
            token = issue(label)
            proof = submit(nonce, token)
            local(nonce, {"type": "redeem", "requester_proof": proof})
            inv.finish(True)
            successes.add(bytes(nonce))
            check(bytes(nonce) in consumed(), "successful issue invocation durably consumed")
            if label == "all-up":
                socket_stamp = Path(SOCKET).stat().st_ctime_ns
                stop(daemon)
                daemon = spawn([str(ROOT / "local-sudo-v2")])
                ready(daemon, lambda: Path(SOCKET).exists()
                      and Path(SOCKET).stat().st_ctime_ns != socket_stamp)
                check(time.time() < challenge["grant"]["expires_at"], "restart replay test must precede expiry")
                check(bytes(nonce) in consumed(), "consumption must survive daemon restart")
            local(nonce, {"type": "redeem", "requester_proof": proof}, success=False)
            fresh, fresh_nonce, _ = begin(label + "-replay")
            local(fresh_nonce, {"type": "submit_token", "token": token}, success=False)
            fresh.disconnect()
            print(f"PASS {label}: actual UID0, same/fresh invocation replay denied", flush=True)
            automatic = Invocation()
            automatic_nonce = automatic.handle()
            approve(automatic_nonce)
            automatic.finish(True)
            successes.add(bytes(automatic_nonce))
            check(bytes(automatic_nonce) in consumed(), "sudo-approve invocation durably consumed")
            approve(automatic_nonce, success=False)
            print(f"PASS sudo-approve {label}: actual UID0, completed handle replay denied", flush=True)
        check(consumed() <= successes, "only successful nonce identities may be consumed")

        stop(signers[1])
        inv, _, _ = begin("two-dead")
        issue("two-dead", success=False)
        check(consumed() <= successes, "signer loss must not consume a new nonce")
        inv.finish(False)
        signers[1] = signer(2)
        signers[2] = signer(3)
        inv, _, _ = begin("bad-owner")
        issue("bad-owner", owner="other", success=False)
        check(consumed() <= successes, "wrong owner must not consume a new nonce")
        inv.finish(False)
        print("PASS two unavailable signers and wrong pinned owner deny", flush=True)

        inv, nonce, _ = begin("bad-proof")
        token = issue("bad-proof")
        proof = submit(nonce, token)
        proof[0] ^= 1
        local(nonce, {"type": "redeem", "requester_proof": proof}, success=False)
        check(consumed() <= successes, "bad proof must not consume a new nonce")
        inv.finish(False)

        inv, nonce, challenge = begin("expired")
        token = issue("expired")
        time.sleep(max(0, challenge["grant"]["expires_at"] - time.time() + 1))
        local(nonce, {"type": "submit_token", "token": token}, success=False)
        check(consumed() <= successes, "expired submission must not consume a new nonce")
        inv.finish(False)

        inv, nonce, _ = begin("disconnected")
        token = issue("disconnected")
        inv.disconnect()
        time.sleep(.2)
        local(nonce, {"type": "submit_token", "token": token}, success=False)
        # begin() legitimately collects expired rows. Verify identities, not a lifetime count.
        check(consumed() <= successes, "denials must not create new consumed nonce identities")
        print("PASS bad PoP, natural expiry, and original sudo disconnect deny", flush=True)

        count = len(CALLS)
        for inv in (Invocation(command=["/usr/bin/true"]), Invocation(password=b"wrong\n")):
            inv.finish(False, timeout=10)
            check(b"approval handle" not in inv.output, "sudoers/password denial reached gate")
        check(len(CALLS) == count, "sudo authorization denial contacted owner")
        check(any(CALLS) and not all(CALLS), "real owner authentication exercised")
        print("PASS sudoers/password deny; full-v2 E2E complete", flush=True)
    finally:
        for invocation in TERMINALS:
            invocation.disconnect()
        for child in reversed(CHILDREN):
            stop(child)
        owner.shutdown()
        owner.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "ipc":
        try:
            ipc()
        except Exception as error:
            raise SystemExit(f"local request rejected ({type(error).__name__})") from None
    else:
        main()
