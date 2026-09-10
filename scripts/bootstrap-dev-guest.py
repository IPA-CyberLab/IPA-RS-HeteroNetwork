#!/usr/bin/env python3
"""Local preparation and explicit on-guest installation of a fresh dev cluster only."""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

SCRIPT = Path(__file__).resolve()
CP = "172.28.240.11"
URL = "http://172.28.240.11:8443"
NAMES = tuple(f"hetero-dev-{i}" for i in range(1, 4))
CONFIG = Path("/etc/heteronetwork")
STATE = Path("/var/lib/heteronetwork")
BIN = Path("/opt/heteronetwork/bin")
JOURNAL = Path("/var/lib/heteronetwork-dev-bootstrap")
UNITS = Path("/etc/systemd/system")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
PREREQUISITE_PACKAGES = ("python3", "python3-cryptography", "iproute2", "iputils-ping", "curl", "systemd", "wireguard-tools")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def native():
    spec = importlib.util.spec_from_file_location("native_stage", SCRIPT.with_name("native-release-stage.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read(path, limit=2 * 1024 * 1024):
    return native().read_source(str(path), limit)


def decode(data):
    return native().decode(data)


def private_path(path):
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode), "Symlinked path rejected")
        require(info.st_uid in (0, os.geteuid()), "Untrusted path owner")
        require(not info.st_mode & 0o022, "Writable path ancestor rejected")
    info = path.stat()
    require(info.st_uid == os.geteuid() and not info.st_mode & 0o077, "Private owned path required")
    return path


def write_new(path, data, mode=0o600):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as target:
        target.write(data)
        target.flush()
        os.fchmod(target.fileno(), mode)
        os.fsync(target.fileno())


def directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    private_path(path)


def inventory(value):
    require(set(value) == {"schema_version", "guests"} and value["schema_version"] == 1, "Invalid inventory schema")
    require(len(value["guests"]) == 3, "Exactly three exclusive dev guests required")
    machines = set()
    for i, guest in enumerate(value["guests"], 1):
        validate_guest(guest)
        require(guest["name"] == f"hetero-dev-{i}", "Guests must be in allocation order")
        machine = guest["machine_id"]
        require(machine not in machines, "Cloned machine IDs rejected")
        machines.add(machine)
    return value


def validate_guest(guest):
    require(isinstance(guest, dict) and guest.get("name") in NAMES, "Not a dedicated dev guest")
    require(set(guest) == {"name", "address", "product_uuid", "machine_id"}, "Invalid guest identity fields")
    name = guest["name"]
    expected_uuid = str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:heteronetwork:dev:ichikawap1:domain:{name}"))
    require(guest["address"] == f"172.28.240.{11+NAMES.index(name)}", "Guest outside fixed dev allocation")
    require(guest["product_uuid"] == expected_uuid, "Guest UUID differs from provisioning allocation")
    machine = guest["machine_id"]
    require(isinstance(machine, str) and re.fullmatch(r"[a-f0-9]{32}", machine) and machine != "0" * 32, "Observed machine ID required")


def run(arguments, timeout=60):
    # Capture potentially sensitive CLI output; never include it in an error or journal.
    result = subprocess.run([str(a) for a in arguments], env=ENV, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    require(result.returncode == 0, "Bounded bootstrap command failed; inspect locally with secret-safe handling")
    require(len(result.stdout) <= 2 * 1024 * 1024, "Command output limit")
    return result.stdout


def agent_args(enroll=False):
    args = [str(BIN / "iparsd"), "agent", "--listen", "127.0.0.1:9780",
            "--state-path", str(STATE / "agent.json"), "--api-bearer-token-path", str(CONFIG / "kubernetes/agent-api-token"),
            "--control-plane-url", URL, "--signal-url", f"http://{CP}:9443",
            "--stun-server", f"{CP}:3478", "--disable-public-stun-fallback",
            "--disable-public-services-autopromotion", "--disable-overlay-services",
            "--kubernetes-discover-api-server", "false",
            "--wireguard-interface", "heteronetwork0"]
    if enroll:
        args += ["--join-token-path", str(CONFIG / "join-token.json"), "--enroll-only"]
    else:
        args += ["--apply-peer-map", "--wireguard-backend", "kernel-netlink"]
    return args


def unit(arguments):
    require(all(re.fullmatch(r"[A-Za-z0-9_./:=+,?-]+", a) for a in arguments), "Unsafe generated service argument")
    command = " ".join(["/usr/bin/env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                        "HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_ENABLED=false", *arguments])
    return ("[Unit]\nDescription=Dedicated fresh HeteroNetwork DEV only\nAfter=network-online.target\nWants=network-online.target\n"
            "[Service]\nType=simple\nUser=root\nUMask=0077\nRestart=on-failure\nRestartSec=5\n"
            f"ExecStart={command}\n[Install]\nWantedBy=multi-user.target\n").encode()


def service_files(guest, cluster):
    files = {"heteronetwork-agent.service": unit(agent_args())}
    if guest["name"] != NAMES[0]:
        return files
    args = [str(BIN / "iparsd"), "control-plane", "--listen", f"{CP}:8443",
            "--cluster-id", cluster["cluster_id"], "--vpn-pool", "10.251.0.0/24",
            "--database-url", f"sqlite://{STATE}/control-plane.sqlite?mode=rwc",
            "--issuer-node-id", cluster["issuer_node_id"], "--issuer-key-id", "dev-bootstrap",
            "--issuer-public-key", cluster["issuer_public_key"], "--web-ui-enabled", "false",
            "--service-instance-id", cluster["issuer_node_id"],
            "--service-owner-host-id", cluster["issuer_node_id"],
            "--service-owner-node-id", cluster["issuer_node_id"],
            "--node-enrollment-enabled", "false", "--dynamic-web-gateway-enabled", "false",
            "--operator-api-bearer-token-path", str(CONFIG / "operator.token"),
            "--advertise-control-plane-url", URL, "--advertise-signal-url", f"http://{CP}:9443",
            "--advertise-stun-url", f"udp://{CP}:3478"]
    files["heteronetwork-control-plane.service"] = unit(args)
    files["heteronetwork-signal.service"] = unit([str(BIN / "iparsd"), "signal", "--listen", f"{CP}:9443",
        "--control-plane-url", URL, "--operator-api-bearer-token-path", str(CONFIG / "signal.token")])
    files["heteronetwork-stun.service"] = unit([str(BIN / "iparsd"), "stun", "--listen", f"{CP}:3478",
        "--alternate-listen", f"{CP}:3479", "--http-listen", "127.0.0.1:3480",
        "--operator-api-bearer-token-path", str(CONFIG / "stun.token")])
    return files


def target_file(name):
    if name.endswith(".service"):
        return UNITS / name, 0o600
    if name == "agent-api.token":
        return CONFIG / "kubernetes/agent-api-token", 0o400
    return CONFIG / name, 0o600


def stage(artifact_path, archive_path, inventory_path, output):
    module = native()
    guests = inventory(decode(read(inventory_path)))
    manifest, canonical = module.validated_catalog(read(artifact_path))
    require(manifest["component"] == "heteronetwork" and "-dev." in manifest["version"], "Explicit dev native release required")
    output = Path(os.path.abspath(output))
    private_path(output.parent)
    output.mkdir(mode=0o700)  # Never replace or resume partially generated credentials.
    payload = output / "verified"
    payload.mkdir(mode=0o700)
    fd = module.open_directory(str(payload), trusted=True)
    try:
        with module.source_file(archive_path) as source:
            module.checked_copy(source, fd, "archive.tar.gz", module.native(manifest)["sha256"])
        module.unpack_verified_archive(fd, manifest)
    finally:
        os.close(fd)
    cli = payload / "bin/ipars"
    cli.chmod(0o500)
    issuer = output / "issuer.key"
    # init only creates fresh local keys/token; never --spawn-daemons or network enrollment.
    cluster = decode(run([cli, "init", "--public-endpoint", f"{CP}:8443", "--disable-relay",
                         "--issuer-key-id", "dev-bootstrap", "--issuer-private-key-path", issuer,
                         "--max-uses", "1", "--tag", "hetero-dev"]))
    for field in ("cluster_id", "issuer_node_id", "issuer_public_key"):
        require(isinstance(cluster.get(field), str), "Unexpected verified CLI init output")
    for guest in guests["guests"]:
        node = output / guest["name"]
        node.mkdir(mode=0o700)
        write_new(node / "artifact.json", canonical)
        # Recopy and rehash rather than trusting a mutable source between guests.
        fd = module.open_directory(str(node), trusted=True)
        try:
            with module.source_file(str(payload / "archive.tar.gz")) as source:
                module.checked_copy(source, fd, "archive.tar.gz", module.native(manifest)["sha256"])
        finally:
            os.close(fd)
        token = run([cli, "token", "create", "--cluster-id", cluster["cluster_id"],
                     "--issuer-key-id", "dev-bootstrap", "--issuer-private-key-path", issuer,
                     "--control-plane-bootstrap", URL, "--signal-bootstrap", f"http://{CP}:9443",
                     "--stun-bootstrap", f"udp://{CP}:3478", "--disable-relay", "--max-uses", "1",
                     "--ttl-seconds", "86400", "--tag", "hetero-dev", "--tag", guest["name"]])
        generated = {"join-token.json": token, "agent-api.token": secrets.token_hex(32).encode()}
        if guest["name"] == NAMES[0]:
            for name in ("operator.token", "signal.token", "stun.token"):
                generated[name] = secrets.token_hex(32).encode()
        for name, content in generated.items():
            write_new(node / name, content)
        for name, content in service_files(guest, cluster).items():
            write_new(node / name, content)
            generated[name] = content
        config = {"schema_version": 1, "guest": guest, "cluster_id": cluster["cluster_id"],
                  "artifact_sha256": digest(canonical), "files": {k: digest(v) for k, v in generated.items()}}
        write_new(node / "bootstrap.json", (json.dumps(config, sort_keys=True) + "\n").encode())
        for source in (SCRIPT, SCRIPT.with_name("native-release-stage.py")):
            write_new(node / source.name, read(source), 0o700)
        write_new(node / "INSTRUCTIONS.txt", (
            f"Dedicated {guest['name']} only; UUID {guest['product_uuid']}; machine ID {guest['machine_id']}.\n"
            "Transfer this entire directory through the approved provisioning/admin path, then make it root-owned and private.\n"
            "Do not transfer issuer.key or another guest's directory. Do not copy production configuration.\n"
            "Required guest packages: python3, python3-cryptography, iproute2, iputils-ping, curl, wireguard-tools, systemd.\n"
            "Curie must place the payload at /opt/heteronetwork-dev-bootstrap (root:root, directory 0700),\n"
            "Curie's fresh devadmin already has temporary bootstrap NOPASSWD ALL inside this exclusive VM.\n"
            "This tool does not alter cloud-init, sudoers, SSH policy or administrator credentials.\n"
            "  sudo /usr/bin/python3 /opt/heteronetwork-dev-bootstrap/bootstrap-dev-guest.py prerequisites --bundle /opt/heteronetwork-dev-bootstrap\n"
            "  sudo /usr/bin/python3 /opt/heteronetwork-dev-bootstrap/bootstrap-dev-guest.py install --bundle /opt/heteronetwork-dev-bootstrap\n"
            "  sudo /usr/bin/python3 /opt/heteronetwork-dev-bootstrap/bootstrap-dev-guest.py start --bundle /opt/heteronetwork-dev-bootstrap\n"
            "Start hetero-dev-1 first. CP uses private-underlay HTTP on port 8443, not TLS or CP HA.\n"
            "Start is not readiness. Collect the observed public three-node roster, then run verify-vpn on every guest.\n"
            "  sudo /usr/bin/python3 /opt/heteronetwork-dev-bootstrap/bootstrap-dev-guest.py verify-vpn --bundle /opt/heteronetwork-dev-bootstrap --roster /root/dev-vpn-roster.json\n"
            "Require all three sustained VPN reports before Kubernetes. Current kubeadm prepare needs a reviewed no-autopromotion guard first.\n"
            "Keep the journal after any failure. Never reset a machine/agent ID or copy keys to retry.\n"
        ).encode())
    write_new(output / "READY", b"Local staging only. Install node 1 first; issuer.key stays offline.\n")
    return {"stage": "prepared", "verification_scope": "base_archive_only",
            "sudo_companion_verified": False, "sudo_installed": False,
            "nodes": list(NAMES), "cluster_id": cluster["cluster_id"], "remote_execution": False}


def guest_identity(guest):
    require(socket.gethostname() == guest["name"], "Wrong guest hostname")
    require(read("/sys/devices/virtual/dmi/id/product_uuid", 4096).decode().strip().lower() == guest["product_uuid"], "Wrong VM UUID")
    require(read("/etc/machine-id", 128).decode().strip() == guest["machine_id"], "Wrong machine ID")
    addresses = decode(run(["/usr/sbin/ip", "-j", "address", "show", "dev", "dev0"]))
    found = [a["local"] for link in addresses for a in link["addr_info"] if a["family"] == "inet"]
    require(found == [guest["address"]], "Wrong dedicated dev0 address")


def journal_write(value):
    temporary = JOURNAL / (".journal-" + secrets.token_hex(8))
    write_new(temporary, (json.dumps(value, sort_keys=True) + "\n").encode())
    os.replace(temporary, JOURNAL / "journal.json")
    fd = os.open(JOURNAL, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def owned_file(path, content, mode):
    if path.exists() or path.is_symlink():
        private_path(path) if mode == 0o600 else private_path(path.parent)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1,
                "Existing file is not exclusively owned")
        require(stat.S_IMODE(info.st_mode) == mode and read(path, 256*1024*1024) == content, "Refusing existing different file")
    else:
        write_new(path, content, mode)


def wait_control_plane():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with opener.open(URL + "/healthz", timeout=2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(1)
    raise ValueError("Dev control plane not healthy; enrollment was not attempted")


def checked_guest_bundle(bundle):
    require(os.geteuid() == 0, "Guest operations are local root-only")
    bundle = private_path(Path(bundle))
    private_path(bundle / "bootstrap.json")
    config_raw = read(bundle / "bootstrap.json")
    config = decode(config_raw)
    guest = config["guest"]
    require(config["schema_version"] == 1 and guest["name"] in NAMES, "Not a dev bootstrap bundle")
    validate_guest(guest)
    guest_identity(guest)
    private_path(bundle / "artifact.json")
    artifact_raw = read(bundle / "artifact.json")
    require(digest(artifact_raw) == config["artifact_sha256"], "Artifact identity changed")
    manifest = decode(artifact_raw)
    require(manifest["component"] == "heteronetwork" and "-dev." in manifest["version"], "Not a dev artifact")
    return bundle, config_raw, config, manifest


def prerequisites(bundle):
    bundle, _, config, manifest = checked_guest_bundle(bundle)
    # Lock the directory inode without creating or changing any prepared files.
    fd = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for path in (CONFIG, STATE, BIN.parent, JOURNAL):
            require(not path.exists() and not path.is_symlink(), "Prerequisites require an uninstalled fresh dev guest")
        for root in (UNITS, Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")):
            require(not list(root.glob("heteronetwork*")), "Existing HeteroNetwork units rejected")
        for name, expected in config["files"].items():
            require(re.fullmatch(r"[a-z0-9.-]+", name), "Unsafe bundle filename")
            private_path(bundle / name)
            require((bundle / name).stat().st_nlink == 1, "Hardlinked bundle file rejected")
            require(digest(read(bundle / name)) == expected, "Bundle file changed")
        module = native()
        with module.source_file(str(bundle / "archive.tar.gz")) as source:
            require(module.bounded_digest(source, module.MAX_ARCHIVE) == module.native(manifest)["sha256"], "Archive digest mismatch")
        release = read("/usr/lib/os-release", 16384).decode()
        ids = re.findall(r'^ID=(?:"([a-z]+)"|([a-z]+))$', release, re.MULTILINE)
        require(len(ids) == 1 and (ids[0][0] or ids[0][1]) in ("ubuntu", "debian"), "Only distro Debian/Ubuntu apt is supported")
        apt = ["/usr/bin/env", "-i", "PATH=" + ENV["PATH"], "LC_ALL=C",
               "DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get",
               "-o", "DPkg::Lock::Timeout=60", "-o", "Acquire::Retries=0",
               "-o", "Acquire::http::Timeout=30", "-o", "Acquire::https::Timeout=30"]
        run([*apt, "-o", "APT::Update::Error-Mode=any", "update"], timeout=600)
        run([*apt, "install", "--yes", "--no-install-recommends", "--no-upgrade",
             *PREREQUISITE_PACKAGES], timeout=900)
        run(["/usr/bin/wg", "--version"])
        return {"phase": "prerequisites-installed", "node": config["guest"]["name"],
                "packages": list(PREREQUISITE_PACKAGES), "hn_installed": False,
                "vpn_verified": False, "sudo_installed": False}
    finally:
        os.close(fd)


def install(bundle, start=False):
    bundle, config_raw, config, manifest = checked_guest_bundle(bundle)
    guest = config["guest"]
    binding = digest(config_raw)
    first = not JOURNAL.exists()
    if first:
        require(not start, "Install before starting")
        for path in (CONFIG, STATE, BIN.parent):
            require(not path.exists() and not path.is_symlink(), "Guest is not fresh; existing state/config rejected")
        for root in (UNITS, Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")):
            require(not list(root.glob("heteronetwork*")), "Existing HeteroNetwork units rejected")
        JOURNAL.mkdir(mode=0o700)
        write_new(JOURNAL / "lock", b"")
        journal_write({"schema_version": 1, "binding": binding, "phase": "installing"})
    private_path(JOURNAL)
    with (JOURNAL / "lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = decode(read(JOURNAL / "journal.json"))
        require(state["schema_version"] == 1 and state["binding"] == binding, "Bootstrap journal binding mismatch")
        module = native()
        with module.source_file(str(bundle / "archive.tar.gz")) as source:
            require(module.bounded_digest(source, module.MAX_ARCHIVE) == module.native(manifest)["sha256"], "Archive digest mismatch")
        for name, expected in config["files"].items():
            require(re.fullmatch(r"[a-z0-9.-]+", name), "Unsafe bundle filename")
            private_path(bundle / name)
            require((bundle / name).stat().st_nlink == 1, "Hardlinked bundle file rejected")
            require(digest(read(bundle / name)) == expected, "Bundle file changed")
        if not start:
            require(state["phase"] in ("installing", "installed", "enrolled", "started", "vpn-verified-local"), "Uncertain prior start requires inspection")
            for path in (CONFIG, CONFIG / "kubernetes", STATE, BIN):
                directory(path)
            payload = JOURNAL / "payload"
            if not payload.exists():
                payload.mkdir(mode=0o700)
                fd = module.open_directory(str(payload), trusted=True)
                try:
                    with module.source_file(str(bundle / "archive.tar.gz")) as source:
                        module.checked_copy(source, fd, "archive.tar.gz", module.native(manifest)["sha256"])
                    module.unpack_verified_archive(fd, manifest)
                finally:
                    os.close(fd)
            for name in module.REQUIRED_BINARIES:
                data = read(payload / name, module.MAX_BINARY)
                require(digest(data) == module.native(manifest)["files"][name], "Installed binary source changed")
                owned_file(BIN / Path(name).name, data, 0o700)
            for name in config["files"]:
                target, mode = target_file(name)
                owned_file(target, read(bundle / name), mode)
            if state["phase"] == "installing":
                state["phase"] = "installed"
                journal_write(state)
            return {"phase": state["phase"], "services_started": False}
        require(state["phase"] in ("installed", "enrolled", "started", "vpn-verified-local"), "Uncertain enrollment/start; do not retry or delete state")
        # Verify installed commands and units immediately before activation.
        for name in module.REQUIRED_BINARIES:
            require(digest(read(BIN / Path(name).name, module.MAX_BINARY)) == module.native(manifest)["files"][name], "Installed binary mismatch")
        for name, expected in config["files"].items():
            target, _ = target_file(name)
            require(digest(read(target)) == expected, "Installed config/unit mismatch")
        run(["/usr/bin/systemctl", "daemon-reload"])
        services = [name for name in config["files"] if name.endswith(".service") and "-agent." not in name]
        for name in services:
            run(["/usr/bin/systemctl", "enable", "--now", name])
        if state["phase"] == "installed":
            require(not (STATE / "agent.json").exists(), "Unexpected existing agent identity")
            wait_control_plane()
            state["phase"] = "enrolling"
            journal_write(state)
            # This call is never retried automatically after an ambiguous outcome.
            run(["/usr/bin/env", "HETERONETWORK_AGENT_PUBLIC_WEB_GATEWAY_ENABLED=false", *agent_args(enroll=True)], timeout=90)
            enrolled = decode(read(STATE / "agent.json"))
            require(enrolled.get("registered_node") and ipaddress.ip_address(enrolled["vpn_ip"]) in ipaddress.ip_network("10.251.0.0/24"), "Enrollment did not produce a dev identity")
            state["phase"] = "enrolled"
            journal_write(state)
        run(["/usr/bin/systemctl", "enable", "--now", "heteronetwork-agent.service"])
        state["phase"] = "started"
        state.pop("vpn_check", None)
        journal_write(state)
        return {"phase": "started", "node": guest["name"], "cp_ha": False, "vpn_verified": False, "kubernetes_ready": False}


def checked_roster(roster, cluster_id):
    require(set(roster) == {"schema_version", "cluster_id", "nodes"} and roster["schema_version"] == 1
            and roster["cluster_id"] == cluster_id, "VPN roster cluster mismatch")
    require(len(roster["nodes"]) == 3 and [n["name"] for n in roster["nodes"]] == list(NAMES), "All three dev nodes required")
    for node in roster["nodes"]:
        require(set(node) == {"name", "node_id", "vpn_ip", "wireguard_public_key"}, "Unexpected roster fields")
        require(isinstance(node["node_id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", node["node_id"]), "Invalid node ID")
        address = ipaddress.ip_address(node["vpn_ip"])
        require(address in ipaddress.ip_network("10.251.0.0/24") and str(address) not in ("10.251.0.0", "10.251.0.255"), "Non-dev VPN address")
        key = base64.b64decode(node["wireguard_public_key"], validate=True)
        require(len(key) == 32 and key != bytes(32), "Invalid WireGuard public key")
    for field in ("node_id", "vpn_ip", "wireguard_public_key"):
        require(len({node[field] for node in roster["nodes"]}) == 3, "Duplicate VPN roster identity")
    return roster["nodes"]


def health_json(url, token=None):
    require(url in (URL + "/healthz", "http://127.0.0.1:9780/v1/status"), "Unexpected health endpoint")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token} if token else {})
    with opener.open(request, timeout=2) as response:
        require(response.status == 200, "Unhealthy dev endpoint")
        data = response.read(2*1024*1024+1)
        require(len(data) <= 2*1024*1024, "Health output limit")
        return decode(data)


def wg_table(field):
    lines = run(["/usr/bin/wg", "show", "heteronetwork0", field], timeout=5).decode().splitlines()
    rows = [line.split() for line in lines]
    require(all(len(row) >= 2 for row in rows), "Invalid WireGuard output")
    require(len({row[0] for row in rows}) == len(rows), "Duplicate WireGuard peers")
    return {row[0]: row[1:] for row in rows}


def quarantine_key(local_public_key):
    raw = base64.b64decode(local_public_key, validate=True)
    require(len(raw) == 32 and base64.b64encode(raw).decode() == local_public_key,
            "Noncanonical local WireGuard key")
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    except ImportError as error:
        raise ValueError("VPN verification requires distro python3-cryptography X25519") from error
    # Match ipars-agent's u8 counter loop and ipars-crypto's fixed X25519 probe.
    probe = X25519PrivateKey.from_private_bytes(bytes([0x42]) * 32)
    for counter in range(256):
        candidate_raw = hashlib.sha256(
            b"HeteroNetwork bounded overlay quarantine key v1\0"
            + local_public_key.encode("ascii") + bytes([counter])).digest()
        candidate = base64.b64encode(candidate_raw).decode()
        if candidate == local_public_key:
            continue
        try:
            shared = probe.exchange(X25519PublicKey.from_public_bytes(candidate_raw))
        except ValueError:
            # OpenSSL rejects null shared secrets rather than returning zero.
            continue
        if shared != bytes(32):
            return candidate
    raise ValueError("No valid bounded-overlay quarantine candidate")


def check_quarantine(key, keys):
    for field, expected in (("allowed-ips", ["10.251.0.0/24"]),
                            ("endpoints", ["127.0.0.1:9"]),
                            ("persistent-keepalive", ["off"]),
                            ("latest-handshakes", ["0"])):
        table = wg_table(field)
        require(set(table) == keys and table[key] == expected, "Unexpected quarantine peer state")


def vpn_sample(local, peers, api_token):
    health_json(URL + "/healthz")
    status = health_json("http://127.0.0.1:9780/v1/status", api_token)
    for field in ("node_id", "vpn_ip", "wireguard_public_key"):
        require(status[field] == local[field], "Local agent identity differs from pinned roster")
    require(run(["/usr/bin/wg", "show", "heteronetwork0", "public-key"], timeout=5).decode().strip()
            == local["wireguard_public_key"], "Kernel WireGuard identity differs from pinned agent")
    keys = {peer["wireguard_public_key"] for peer in peers}
    quarantine = quarantine_key(local["wireguard_public_key"])
    require(len(keys) == 2 and quarantine not in keys, "Invalid remote/quarantine peer identities")
    all_keys = keys | {quarantine}
    check_quarantine(quarantine, all_keys)
    before = wg_table("transfer")
    allowed = wg_table("allowed-ips")
    require(set(before) == all_keys and set(allowed) == all_keys, "Unexpected or missing encrypted peer")
    for peer in peers:
        key, address = peer["wireguard_public_key"], peer["vpn_ip"]
        require(allowed[key] == [address + "/32"], "Unexpected encrypted route scope")
        route = decode(run(["/usr/sbin/ip", "-j", "route", "get", address], timeout=5))
        require(route and all(entry.get("dev") == "heteronetwork0" for entry in route), "Peer route bypasses VPN")
        run(["/usr/bin/ping", "-n", "-I", "heteronetwork0", "-c", "1", "-W", "2", address], timeout=5)
    after, handshakes = wg_table("transfer"), wg_table("latest-handshakes")
    require(set(after) == all_keys and set(handshakes) == all_keys, "Encrypted peer set changed")
    check_quarantine(quarantine, all_keys)
    for key in keys:
        require(len(before[key]) == len(after[key]) == 2 and all(int(a) > int(b) for a, b in zip(after[key], before[key])),
                "No bidirectional encrypted traffic growth")
        age = time.time() - int(handshakes[key][0])
        require(0 <= age <= 180, "WireGuard handshake is not fresh")


def verify_vpn(bundle, roster_path):
    require(os.geteuid() == 0, "VPN verification is explicit and guest-local")
    bundle = private_path(Path(bundle))
    config_raw = read(bundle / "bootstrap.json")
    config = decode(config_raw)
    validate_guest(config["guest"])
    guest_identity(config["guest"])
    private_path(Path(roster_path))
    roster_raw = read(roster_path)
    nodes = checked_roster(decode(roster_raw), config["cluster_id"])
    local = next(node for node in nodes if node["name"] == config["guest"]["name"])
    peers = [node for node in nodes if node is not local]
    private_path(JOURNAL)
    with (JOURNAL / "lock").open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = decode(read(JOURNAL / "journal.json"))
        require(state["schema_version"] == 1 and state["binding"] == digest(config_raw)
                and state["phase"] in ("started", "vpn-verified-local"), "Start enrollment/runtime before verification")
        state["phase"] = "started"
        state.pop("vpn_check", None)
        journal_write(state)
        token_path, _ = target_file("agent-api.token")
        private_path(token_path)
        token = read(token_path, 128).decode().strip()
        started = time.monotonic()
        for sample in range(13):
            require(time.monotonic() - started < 180, "Sustained VPN check deadline exceeded")
            vpn_sample(local, peers, token)
            if sample < 12:
                time.sleep(5)
        result = {"schema_version": 1, "node": local["name"], "cluster_id": config["cluster_id"],
                  "roster_sha256": digest(roster_raw), "samples": 13,
                  "duration_seconds": time.monotonic() - started, "checked_at": int(time.time()),
                  "peer_names": [peer["name"] for peer in peers], "kubernetes_ready": False}
        require(60 <= result["duration_seconds"] < 180, "Invalid sustained observation interval")
        state.update(phase="vpn-verified-local", vpn_check=result)
        journal_write(state)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("stage")
    for name in ("artifact", "archive", "inventory", "output"):
        prepare.add_argument("--" + name, required=True)
    for name in ("prerequisites", "install", "start"):
        command = commands.add_parser(name)
        command.add_argument("--bundle", required=True)
    verify = commands.add_parser("verify-vpn")
    verify.add_argument("--bundle", required=True)
    verify.add_argument("--roster", required=True)
    args = parser.parse_args()
    if args.command == "stage":
        result = stage(args.artifact, args.archive, args.inventory, args.output)
    elif args.command == "verify-vpn":
        result = verify_vpn(args.bundle, args.roster)
    elif args.command == "prerequisites":
        result = prerequisites(args.bundle)
    else:
        result = install(args.bundle, start=args.command == "start")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        print(f"DEV bootstrap stopped ({type(error).__name__}); preserve the journal and inspect locally", file=sys.stderr)
        sys.exit(1)
