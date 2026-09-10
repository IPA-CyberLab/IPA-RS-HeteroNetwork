#!/usr/bin/env python3
"""Local, root-only, guarded creation of the fixed hetero-dev libvirt allocation."""
import argparse
import contextlib
import fcntl
import hashlib
import ipaddress
import inspect
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy/dev/libvirt/profile.json"
TABLE = "hetero_dev"
STATE = Path("/var/lib/hetero-dev-provisioner")
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
FIELDS = ("underlay", "overlay", "pods", "services")
BLOCKED = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
           "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
           "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
           "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")


class Refusal(ValueError):
    """Only fixed source-literal require messages may be reported to the operator."""


class CommandFailure(Refusal):
    def __init__(self, tool, returncode):
        super().__init__("Prerequisite or resource command failed; inspect local state")
        self.tool = tool if tool in ("virsh", "nft", "qemu-img", "cloud-localds", "ssh-keygen",
                                     "ssh", "gpgv", "hostname", "ip") else "external-command"
        self.returncode = returncode


class GuestRepairFailure(Refusal):
    def __init__(self, stage):
        super().__init__("Guest exact seed-clean validation refused; no general reset is permitted")
        self.guest_stage = stage if stage in ("identity", "cloud-init-terminal", "pinned-host-keys",
            "fresh-clean-scope", "exact-userdata", "plain-clean") else "unknown"


def require(condition, message):
    if not condition:
        raise Refusal(message)


def failure_report(error):
    # Read code locations only, never frame locals, command arguments or raw
    # exception text from parsers, operating system calls or subprocesses.
    stage, line = "cli", None
    frame = error.__traceback__
    while frame is not None:
        code = frame.tb_frame.f_code
        if code.co_filename == __file__ and code.co_name not in ("require", "run", "<module>"):
            stage, line = code.co_name, frame.tb_lineno
        frame = frame.tb_next
    if isinstance(error, Refusal):
        reason = str(error)
    elif isinstance(error, KeyboardInterrupt):
        reason = "Interrupted"
    elif isinstance(error, OSError):
        reason = "Operating system operation failed"
    elif isinstance(error, subprocess.TimeoutExpired):
        reason = "Command timeout"
    elif isinstance(error, subprocess.SubprocessError):
        reason = "Subprocess operation failed"
    elif isinstance(error, (json.JSONDecodeError, ET.ParseError)):
        reason = "Invalid structured input or command response"
    else:
        reason = "Invalid data or missing expected record"
    report = {"error": "dev-provisioner-refused", "stage": stage, "line": line, "reason": reason,
              "next_action": "Inspect owned journal and local state; do not blindly retry or clear pending"}
    if isinstance(error, CommandFailure):
        report.update(tool=error.tool, exit_code=error.returncode)
    if isinstance(error, GuestRepairFailure):
        report["guest_stage"] = error.guest_stage
    if isinstance(error, OSError):
        report["errno"] = error.errno
    return report


def checked_path(path):
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        require(not part.is_symlink(), "Symlinked paths are not accepted")
    return path


def read(path, limit=2 * 1024 * 1024):
    path = checked_path(path)
    with path.open("rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "Regular file required")
        data = source.read(limit + 1)
    require(len(data) <= limit, "Input too large")
    return data


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def profile(path=PROFILE):
    value = decode(read(path))
    # This first profile is intentionally fixed to the authorized allocation.
    require(value == decode(read(PROFILE)), "Only the committed hetero-dev profile is supported")
    networks = [ipaddress.ip_network(value[field]) for field in FIELDS]
    require(all(not a.overlaps(b) for i, a in enumerate(networks) for b in networks[i + 1:]), "Dev CIDRs overlap")
    require(all(ipaddress.ip_address(address) in networks[0] for address in value["addresses"]), "Guest outside dev underlay")
    return value


def identity(p, kind, name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"urn:heteronetwork:dev:{p['host']}:{kind}:{name}"))


def plan(p):
    return {"schema_version": 1, "stage": "plan", "host": p["host"],
            "connection": p["connection"], "profile_sha256": hashlib.sha256(json.dumps(p, sort_keys=True).encode()).hexdigest(),
            "resources": [{"kind": kind, "name": name, "uuid": identity(p, kind, name)}
                          for kind, names in (("network", [p["name"]]), ("pool", [p["name"]]), ("domain", p["vms"]))
                          for name in names],
            "vcpu_total": 3 * p["vcpu"], "memory_mib_total": 3 * p["memory_mib"],
            "disk_gib_total": 3 * p["disk_gib"], "autostart": False,
            "activation_performed": False, "apply_starts_guests": True,
            "run_lifetime": "normal guest reboot; no host autostart"}


def child(parent, tag, text=None, **attrs):
    element = ET.SubElement(parent, tag, {key: str(value) for key, value in attrs.items()})
    if text is not None:
        element.text = str(text)
    return element


def xml(root):
    ET.indent(root)
    return ET.tostring(root, encoding="unicode") + "\n"


def mac(p, name):
    return "52:54:00:" + ":".join(f"{byte:02x}" for byte in uuid.UUID(identity(p, "domain", name)).bytes[-3:])


def network_xml(p):
    root = ET.Element("network", {"ipv6": "no"})
    child(root, "name", p["name"])
    child(root, "uuid", identity(p, "network", p["name"]))
    child(root, "bridge", name=p["bridge"], stp="on", delay="0")
    child(root, "forward", mode="nat")
    child(root, "domain", name="hetero-dev.internal", localOnly="yes")
    dhcp = child(child(root, "ip", address=p["gateway"], netmask="255.255.255.0"), "dhcp")
    for name, address in zip(p["vms"], p["addresses"]):
        child(dhcp, "host", mac=mac(p, name), name=name, ip=address)
    return xml(root)


def pool_xml(p):
    root = ET.Element("pool", {"type": "dir"})
    child(root, "name", p["name"])
    child(root, "uuid", identity(p, "pool", p["name"]))
    child(child(root, "target"), "path", p["pool_path"])
    return xml(root)


def domain_xml(p, name):
    require(name in p["vms"], "Unknown dev VM")
    root = ET.Element("domain", {"type": "kvm"})
    child(root, "name", name)
    child(root, "uuid", identity(p, "domain", name))
    child(root, "memory", p["memory_mib"], unit="MiB")
    child(root, "currentMemory", p["memory_mib"], unit="MiB")
    child(root, "vcpu", p["vcpu"], placement="static")
    child(child(root, "os"), "type", "hvm", arch="x86_64")
    features = child(root, "features")
    child(features, "acpi")
    child(features, "apic")
    child(root, "on_poweroff", "destroy")
    child(root, "on_reboot", "restart")
    child(root, "on_crash", "destroy")
    devices = child(root, "devices")
    for device, filename, fmt, bus, target in (
            ("disk", name + ".qcow2", "qcow2", "virtio", "vda"),
            ("cdrom", name + "-seed.iso", "raw", "sata", "sda")):
        disk = child(devices, "disk", type="file", device=device)
        child(disk, "driver", name="qemu", type=fmt)
        child(disk, "source", file=p["pool_path"] + "/" + filename)
        child(disk, "target", dev=target, bus=bus)
        if device == "cdrom":
            child(disk, "readonly")
    interface = child(devices, "interface", type="network")
    child(interface, "source", network=p["name"])
    child(interface, "mac", address=mac(p, name))
    child(interface, "model", type="virtio")
    child(child(devices, "console", type="pty"), "target", type="serial", port="0")
    return xml(root)


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def meta(key):
    return {"meta": {"key": key}}


def payload(protocol, field):
    return {"payload": {"protocol": protocol, "field": field}}


def prefix(cidr):
    network = ipaddress.ip_network(cidr)
    return {"prefix": {"addr": str(network.network_address), "len": network.prefixlen}}


def firewall(p):
    """Candidate additive guard, NOT an installed/verified firewall assertion."""
    objects = []
    for family in ("inet", "bridge"):
        objects.append({"add": {"table": {"family": family, "name": TABLE}}})

    def chain(family, name, hook):
        objects.append({"add": {"chain": {"family": family, "table": TABLE, "name": name,
            "type": "filter", "hook": hook, "prio": -10, "policy": "accept"}}})

    def rule(family, name, expr, verdict, comment):
        objects.append({"add": {"rule": {"family": family, "table": TABLE, "chain": name,
            "expr": expr + [{verdict: None}], "comment": "hetero-dev: " + comment}}})

    guest = match(meta("iifname"), p["bridge"])
    to_guest = match(meta("oifname"), p["bridge"])
    ipv6 = match(meta("nfproto"), "ipv6")
    source = match(payload("ip", "saddr"), prefix(p["underlay"]))
    established = match({"ct": {"key": "state"}}, "established", "in")
    reply = match({"ct": {"key": "direction"}}, "reply")
    gateway = match(payload("ip", "daddr"), p["gateway"])
    udp = match(meta("l4proto"), "udp")
    for hook in ("input", "forward"):
        chain("inet", hook, hook)
        rule("inet", hook, [guest, ipv6], "drop", "deny guest IPv6")
    rule("inet", "input", [guest, udp, match(payload("udp", "sport"), 68), match(payload("udp", "dport"), 67),
         match(payload("ip", "saddr"), {"set": ["0.0.0.0", prefix(p["underlay"])]}),
         match(payload("ip", "daddr"), {"set": [p["gateway"], "255.255.255.255"]})], "accept", "DHCP only")
    rule("inet", "input", [guest, match(payload("ip", "saddr"), prefix(p["underlay"]), "!=")], "drop", "deny spoofed source")
    rule("inet", "input", [guest, source, established, reply], "accept", "host-initiated management replies")
    for protocol in ("udp", "tcp"):
        rule("inet", "input", [guest, source, gateway, match(meta("l4proto"), protocol),
            match(payload(protocol, "dport"), 53)], "accept", "DNS to own gateway only")
    rule("inet", "input", [guest], "drop", "deny other host services")
    rule("inet", "forward", [to_guest, ipv6], "drop", "deny inbound IPv6")
    rule("inet", "forward", [guest, match(payload("ip", "saddr"), prefix(p["underlay"]), "!=")], "drop", "deny spoofed source")
    rule("inet", "forward", [guest, to_guest, source, match(payload("ip", "daddr"), prefix(p["underlay"]))], "accept", "own subnet only")
    for cidr in (*BLOCKED, *p["production_public_cidrs"]):
        rule("inet", "forward", [guest, match(payload("ip", "daddr"), prefix(cidr))], "drop", "deny destination " + cidr)
    rule("inet", "forward", [guest, source], "accept", "public IPv4 Internet after exclusions")
    rule("inet", "forward", [guest], "drop", "deny other guest forwarding")
    rule("inet", "forward", [to_guest, established, reply], "accept", "Internet replies only")
    rule("inet", "forward", [to_guest], "drop", "deny unsolicited forwarded ingress")
    # Bridge-family coverage does not depend on bridge-nf-call-ip6tables.
    for hook in ("input", "forward", "output"):
        chain("bridge", hook, hook)
        for key in (("ibrname",) if hook == "input" else ("obrname",) if hook == "output" else ("ibrname", "obrname")):
            rule("bridge", hook, [match(meta(key), p["bridge"]), match(payload("ether", "type"), "ip6")], "drop", "deny L2 IPv6")
    return {"nftables": objects}


def check_conflicts(p, routes, addresses, networks, domains, pools, links):
    requested = [ipaddress.ip_network(p[field]) for field in FIELDS]
    existing = []
    for route in routes:
        destination = route.get("dst", "default")
        if destination != "default":
            net = ipaddress.ip_network(destination, strict=False)
            if net.prefixlen:
                existing.append(net)
    for interface in addresses:
        for address in interface.get("addr_info", []):
            existing.append(ipaddress.ip_network(f"{address['local']}/{address['prefixlen']}", strict=False))
    for text in networks:
        root = ET.fromstring(text)
        require(root.findtext("name") != p["name"], "Network name collision")
        bridge = root.find("bridge")
        require(bridge is None or bridge.get("name") != p["bridge"], "Bridge name collision")
        for address in root.findall("ip"):
            bits = address.get("prefix") or address.get("netmask")
            require(bits is not None, "Cannot establish existing network prefix")
            existing.append(ipaddress.ip_network(f"{address.attrib['address']}/{bits}", strict=False))
        for route in root.findall("route"):
            bits = route.get("prefix") or route.get("netmask")
            require(bits is not None, "Cannot establish existing network route prefix")
            net = ipaddress.ip_network(f"{route.attrib['address']}/{bits}", strict=False)
            if net.prefixlen:
                existing.append(net)
    require(not set(domains) & set(p["vms"]), "Domain name collision; resume not implemented")
    require(p["name"] not in pools, "Pool name collision; resume not implemented")
    require(p["bridge"] not in links, "Existing bridge must not be reused")
    require(not any(a.version == b.version and a.overlaps(b) for a in requested for b in existing), "Dev CIDR overlaps existing network")


def run(arguments, input_data=None, timeout=20):
    """Bound output while reading, including stderr; never print command output on error."""
    with tempfile.TemporaryFile() as stdin, selectors.DefaultSelector() as selector:
        if input_data is not None:
            require(len(input_data) <= 2 * 1024 * 1024, "Command input limit")
            stdin.write(input_data.encode() if isinstance(input_data, str) else input_data)
            stdin.seek(0)
        process = subprocess.Popen(arguments, stdin=stdin, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=ENV, start_new_session=True)
        output = bytearray()
        count = 0
        deadline = time.monotonic() + timeout
        try:
            for stream in (process.stdout, process.stderr):
                selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                require(time.monotonic() < deadline, "Command timeout")
                for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    count += len(chunk)
                    require(count <= 16 * 1024 * 1024, "Command output limit")
                    if key.fileobj is process.stdout:
                        output.extend(chunk)
            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if returncode != 0:
                raise CommandFailure(arguments[0], returncode)
            return output.decode()
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            process.stdout.close()
            process.stderr.close()


def preflight(p, journal=None):
    require(run(["hostname"]).strip() == p["host"], "Wrong host; run preflight locally on the specified hypervisor")
    require(read("/proc/sys/net/ipv4/ip_forward").strip() == b"1",
            "IPv4 forwarding must already be enabled; provisioner must not change global forwarding")
    require(Path("/dev/kvm").exists(), "KVM is unavailable")
    kvm = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC)
    try:
        require(fcntl.ioctl(kvm, 0xAE00) == 12, "Unsupported KVM API")
    finally:
        os.close(kvm)
    virsh = ["virsh", "-c", p["connection"]]
    domains = run(virsh + ["list", "--all", "--name"]).split()
    pools = run(virsh + ["pool-list", "--all", "--name"]).split()
    network_names = run(virsh + ["net-list", "--all", "--name"]).split()
    networks = [run(virsh + ["net-dumpxml", name]) for name in network_names]
    # Read inactive definitions too: an inactive conflicting subnet is still reserved.
    networks += [run(virsh + ["net-dumpxml", name, "--inactive"]) for name in network_names]
    routes = decode(run(["ip", "-j", "-4", "route", "show", "table", "all"]))
    routes += decode(run(["ip", "-j", "-6", "route", "show", "table", "all"]))
    addresses = decode(run(["ip", "-j", "address", "show"]))
    links = [item["ifname"] for item in decode(run(["ip", "-j", "link", "show"]))]
    if journal:
        verify_resources(p, journal, allow_running=True)
        domains = [name for name in domains if "domain:" + name not in journal["resources"]]
        pools = [name for name in pools if "pool:" + name not in journal["resources"]]
        own_network = "network:" + p["name"] in journal["resources"]
        if own_network:
            networks = [text for text in networks if ET.fromstring(text).findtext("name") != p["name"]]
            underlay = ipaddress.ip_network(p["underlay"])
            routes = [route for route in routes if not (route.get("dev") == p["bridge"]
                and route.get("dst", "default") != "default"
                and ipaddress.ip_network(route["dst"], strict=False).version == 4
                and ipaddress.ip_network(route["dst"], strict=False).subnet_of(underlay))]
            addresses = [entry for entry in addresses if entry.get("ifname") != p["bridge"]]
            links = [name for name in links if name != p["bridge"]]
    check_conflicts(p, routes, addresses, networks, domains, pools, links)
    target = checked_path(p["pool_path"])
    if target.exists():
        require(journal and journal.get("pool_directory") == inode(target), "Pool directory collision")
    for name in pools:
        pool = ET.fromstring(run(virsh + ["pool-dumpxml", name]))
        old = pool.findtext("target/path")
        if old:
            old = checked_path(old)
            require(not (old == target or old in target.parents or target in old.parents), "Storage overlaps an existing pool")
    available = int(next(line.split()[1] for line in read("/proc/meminfo").decode().splitlines() if line.startswith("MemAvailable:")))
    already_running = 0
    if journal:
        already_running = sum(resource_info(p, "domain", name).get("State") == "running"
            for name in p["vms"] if "domain:" + name in journal["resources"])
    require(available >= ((3 - already_running) * p["memory_mib"] + p["host_memory_reserve_mib"]) * 1024,
            "Insufficient host memory reserve")
    require((os.cpu_count() or 0) >= 3 * p["vcpu"] + 4, "Insufficient CPU capacity")
    disk = os.statvfs(target.parent)
    require(disk.f_bavail * disk.f_frsize >= (3 * p["disk_gib"] + p["host_disk_reserve_gib"] + 5) * 1024**3, "Insufficient disk reserve")
    return {"preflight": "passed", "activation_performed": False, "isolation_verified": False,
            "note": "Read-only inventory snapshot"}


def verify_image(p, directory):
    directory = checked_path(directory)
    name = p["image_url"].rsplit("/", 1)[1]
    sums = read(directory / "SHA256SUMS")
    signature = read(directory / "SHA256SUMS.gpg")
    keyring = checked_path(p["image_keyring"])
    info = keyring.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o022, "Trusted root-owned Ubuntu keyring required")
    # Authenticate the same checksum bytes that are parsed, not a second read of
    # the caller's metadata paths. The temporary directory contains no secrets.
    with tempfile.TemporaryDirectory(prefix="hetero-dev-image-check-") as temporary:
        checksum_copy = Path(temporary) / "SHA256SUMS"
        signature_copy = Path(temporary) / "SHA256SUMS.gpg"
        checksum_copy.write_bytes(sums)
        signature_copy.write_bytes(signature)
        status = run(["gpgv", "--status-fd", "1", "--keyring", str(keyring),
                      str(signature_copy), str(checksum_copy)])
    signers = [line.split()[2] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    require(signers, "Authenticated checksum signature required")
    records = [line.split() for line in sums.decode("ascii").splitlines()]
    hashes = [record[0] for record in records if len(record) == 2 and record[1].lstrip("*") == name]
    require(hashes == [p["image_sha256"]], "Signed image checksum differs from pinned profile")
    image = checked_path(directory / name)
    with image.open("rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 2 * 1024**3, "Invalid image file")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    require(digest == p["image_sha256"], "Image checksum mismatch")
    return {"image_sha256": digest, "signers": signers, "activation_performed": False}


def render(p, public_key):
    parts = public_key.strip().split()
    require(len(parts) in (2, 3) and parts[0] == "ssh-ed25519" and "\n" not in public_key.strip(), "Dedicated ed25519 public key required")
    outputs = {"plan.json": json.dumps(plan(p), indent=2) + "\n", "network.xml": network_xml(p),
               "pool.xml": pool_xml(p), "guard.candidate.nft.json": json.dumps(firewall(p), indent=2) + "\n"}
    for name in p["vms"]:
        outputs[name + ".xml"] = domain_xml(p, name)
        outputs[name + "/user-data"] = "#cloud-config\n" + json.dumps({
            "users": [{"name": "devadmin", "lock_passwd": True, "shell": "/bin/bash",
                       "ssh_authorized_keys": [" ".join(parts[:2])]}],
            "ssh_pwauth": False, "disable_root": True, "ssh_deletekeys": True,
            "package_update": False, "package_upgrade": False}, indent=2) + "\n"
        outputs[name + "/meta-data"] = json.dumps({"instance-id": identity(p, "domain", name), "local-hostname": name}) + "\n"
        outputs[name + "/network-config"] = json.dumps({"version": 2, "ethernets": {"devnic": {
            "match": {"macaddress": mac(p, name)}, "set-name": "dev0", "dhcp4": True,
            "dhcp6": False, "accept-ra": False, "link-local": []}}}, indent=2) + "\n"
    return outputs


def write_render(directory, outputs):
    directory = checked_path(directory)
    # No overwrite/resume ambiguity in this checkpoint. UUIDs and rendered bytes
    # are deterministic; live ownership cannot be inferred from a name alone.
    directory.mkdir(mode=0o700)
    for name, data in outputs.items():
        target = directory / name
        target.parent.mkdir(mode=0o700, exist_ok=True)
        with target.open("x") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)


def inode(path):
    info = checked_path(path).stat()
    return [info.st_dev, info.st_ino]


def digest_file(path):
    fd = os.open(checked_path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Unsafe owned file")
        return hashlib.file_digest(source, "sha256").hexdigest()


def root_directory(path, private=False):
    """Pin a directory descriptor through root-owned non-writable ancestors."""
    path = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            info = os.fstat(fd)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "Untrusted directory ancestor")
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
        info = os.fstat(fd)
        require(info.st_uid == 0 and not info.st_mode & (0o077 if private else 0o022), "Untrusted directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def exclusive(directory, name, data, mode=0o600):
    require(Path(name).name == name, "Flat filename required")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory)
    with os.fdopen(fd, "wb") as output:
        output.write(data.encode() if isinstance(data, str) else data)
        output.flush()
        os.fchmod(output.fileno(), mode)
        os.fsync(output.fileno())
    os.fsync(directory)


class Journal:
    def __init__(self, directory, value):
        self.fd, self.value = directory, value

    def save(self):
        temporary = ".journal-" + str(uuid.uuid4())
        exclusive(self.fd, temporary, json.dumps(self.value, sort_keys=True, indent=2) + "\n")
        os.rename(temporary, "journal.json", src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)

    def intent(self, operation):
        require(not self.value.get("pending"), "Interrupted operation requires local ownership review")
        self.value["pending"] = operation
        self.save()

    def done(self):
        self.value["pending"] = None
        self.save()


@contextlib.contextmanager
def locked_journal(p, create=False, allow_pending_guard=False):
    require(os.geteuid() == 0, "Apply requires local root")
    require(run(["hostname"]).strip() == p["host"], "Wrong hypervisor")
    parent = root_directory(STATE.parent)
    try:
        if create:
            try:
                os.mkdir(STATE.name, 0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
    finally:
        os.close(parent)
    directory = root_directory(STATE, private=True)
    lock = None
    try:
        lock = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        info = os.fstat(lock)
        require(info.st_uid == 0 and info.st_nlink == 1 and stat.S_ISREG(info.st_mode)
                and not info.st_mode & 0o077, "Unsafe lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            fd = os.open("journal.json", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        except FileNotFoundError:
            require(create and set(os.listdir(directory)) == {"lock"}, "Unjournaled state directory")
            value = {"schema_version": 1, "host": p["host"], "profile_sha256": plan(p)["profile_sha256"],
                     "resources": {}, "files": {}, "pending": None}
            Journal(directory, value).save()
        else:
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                require(info.st_uid == 0 and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and not info.st_mode & 0o077 and info.st_size <= 2 * 1024 * 1024, "Unsafe journal")
                value = decode(source.read(2 * 1024 * 1024 + 1))
        require(value.get("schema_version") == 1 and value.get("host") == p["host"]
                and value.get("profile_sha256") == plan(p)["profile_sha256"], "Host/profile journal mismatch")
        require(not value.get("pending") or allow_pending_guard,
                "Interrupted operation: inspect pending journal; no automatic adoption")
        yield Journal(directory, value)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def record_file(journal, path, mutable=False):
    path = str(checked_path(path))
    journal.value["files"][path] = {"inode": inode(path), "sha256": None if mutable else digest_file(path), "mutable": mutable}


def verify_files(journal):
    for filename, record in journal["files"].items():
        path = checked_path(filename)
        require(path.parent in (STATE, Path(journal["pool_path"])), "Journal path outside owned directories")
        require(inode(path) == record["inode"], "Owned file replaced")
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o007, "Unsafe owned storage")
        if not record["mutable"]:
            require(digest_file(path) == record["sha256"], "Owned immutable file changed")


def resource_xml(p, kind, name):
    commands = {"domain": ["dumpxml", name, "--inactive"], "network": ["net-dumpxml", name, "--inactive"],
                "pool": ["pool-dumpxml", name, "--inactive"]}
    return run(["virsh", "-c", p["connection"], *commands[kind]])


def definition_hash(text):
    root = ET.fromstring(text)
    if root.tag == "pool":
        for field in ("capacity", "allocation", "available"):
            element = root.find(field)
            if element is not None:
                root.remove(element)
        # Even --inactive dir-pool XML gains filesystem permissions at startup.
        # Normalize only this fixed owned pool's exact observed root defaults;
        # verify_resources independently checks the real directory and inode.
        p = profile()
        targets = root.findall("target")
        if (root.attrib == {"type": "dir"} and root.findtext("name") == p["name"]
                and root.findtext("uuid") == identity(p, "pool", p["name"])
                and len(targets) == 1 and targets[0].findtext("path") == p["pool_path"]):
            permissions = targets[0].findall("permissions")
            if len(permissions) == 1:
                node = permissions[0]
                if (not node.attrib and not (node.text or "").strip() and not (node.tail or "").strip()
                        and [field.tag for field in node] == ["mode", "owner", "group"]
                        and all(not field.attrib and len(field) == 0 and not (field.tail or "").strip() for field in node)
                        and node.findtext("mode") in ("0700", "0711")
                        and node.findtext("owner") == "0" and node.findtext("group") == "0"):
                    targets[0].remove(node)
    return hashlib.sha256(ET.canonicalize(ET.tostring(root, encoding="unicode"), strip_text=True).encode()).hexdigest()


def resource_info(p, kind, name):
    command = {"domain": "dominfo", "network": "net-info", "pool": "pool-info"}[kind]
    info = run(["virsh", "-c", p["connection"], command, name])
    return {key.strip(): value.strip() for line in info.splitlines() if ":" in line for key, value in [line.split(":", 1)]}


def verify_resources(p, journal, allow_running=False):
    """Check ownership; allow_running accepts both cold and already booted guests."""
    for key, record in journal["resources"].items():
        kind, name = key.split(":")
        require(name in (p["vms"] if kind == "domain" else [p["name"]]), "Unexpected journal resource")
        if kind == "pool":
            directory = root_directory(p["pool_path"])
            try:
                info = os.fstat(directory)
                require([info.st_dev, info.st_ino] == journal.get("pool_directory"), "Owned pool directory replaced")
                require(stat.S_IMODE(info.st_mode) in (0o700, 0o711), "Unexpected owned pool directory mode")
            finally:
                os.close(directory)
        text = resource_xml(p, kind, name)
        require(ET.fromstring(text).findtext("uuid") == record["uuid"] == identity(p, kind, name), "Resource UUID mismatch")
        require(definition_hash(text) == record["definition_sha256"], "Resource definition drift")
        info = resource_info(p, kind, name)
        require(info.get("Autostart") in ("disable", "no"), "Owned resource autostart must remain disabled")
        if kind == "domain":
            require(info.get("Managed save") in (None, "no"), "Unexpected managed save")
            states = ("shut off", "running") if allow_running else ("shut off",)
            require(info.get("State") in states, "Unexpected owned guest state for guard lifecycle")


def canonical_rule_expressions(expressions):
    # nft 1.0.9 readback omits explicit l4proto when a later port match implies
    # the same protocol. Only normalize pure match rules ending in a verdict.
    if not expressions or expressions[-1] not in ({"accept": None}, {"drop": None}):
        return expressions
    if not all(set(item) == {"match"} for item in expressions[:-1]):
        return expressions
    result = []
    for index, item in enumerate(expressions):
        condition = item.get("match", {})
        protocol = condition.get("right")
        if (condition == {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": protocol}
                and protocol in ("tcp", "udp")):
            conflicting = any(
                (other.get("left") == {"meta": {"key": "l4proto"}} and other != condition)
                or (other.get("left", {}).get("payload", {}).get("protocol") in ("tcp", "udp")
                    and other["left"]["payload"]["protocol"] != protocol)
                for other in (part["match"] for part in expressions[:-1]))
            if conflicting:
                result.append(item)
                continue
            implied = any(later.get("match", {}).get("op") == "=="
                          and later["match"].get("left") in (
                              {"payload": {"protocol": protocol, "field": "sport"}},
                              {"payload": {"protocol": protocol, "field": "dport"}})
                          for later in expressions[index + 1:])
            if implied:
                continue
        result.append(item)
    return result


def canonical_guard(document):
    """Preserve rule order within each chain; ignore only kernel object handles."""
    groups = {}
    for entry in document["nftables"]:
        if "metainfo" in entry:
            continue
        if "add" in entry:
            entry = entry["add"]
        require(len(entry) == 1, "Unexpected firewall object")
        kind, item = next(iter(entry.items()))
        require(kind in ("table", "chain", "rule"), "Unexpected firewall object type")
        item = {key: value for key, value in item.items() if key not in ("handle", "index")}
        if kind == "rule":
            item["expr"] = canonical_rule_expressions(item["expr"])
        require(item.get("family") in ("inet", "bridge") and item.get("table", item.get("name")) == TABLE,
                "Unexpected firewall scope")
        key = (item["family"], kind, item.get("chain", item.get("name", "")))
        groups.setdefault(key, []).append(item)
    return [{"key": list(key), "objects": groups[key]} for key in sorted(groups)]


def live_guard():
    items = []
    for family in ("inet", "bridge"):
        items.extend(decode(run(["nft", "--json", "--stateless", "list", "table", family, TABLE]))["nftables"])
    return canonical_guard({"nftables": items})


def verify_guard(journal):
    require(journal.get("guard") and live_guard() == journal["guard"], "Isolation guard missing or changed")


def ensure_guard(p, journal):
    tables = decode(run(["nft", "--json", "list", "tables"]))["nftables"]
    present = [entry for entry in tables if entry.get("table", {}).get("name") == TABLE]
    if journal.value.get("guard") and present:
        verify_guard(journal.value)
        return
    require(not present, "Firewall name collision")
    # After a host reboot both tables may be absent. Reinstall only while every
    # owned guest is stopped; never repair a partially changed live guard.
    if journal.value.get("guard"):
        verify_resources(p, journal.value)
    batch = json.dumps(firewall(p))
    run(["nft", "--check", "--json", "--file", "-"], batch)
    journal.intent({"operation": "install-guard", "batch_sha256": hashlib.sha256(batch.encode()).hexdigest()})
    echo = decode(run(["nft", "--echo", "--json", "--file", "-"], batch))
    compiled = canonical_guard(echo)
    expected = canonical_guard(firewall(p))
    require(compiled == expected, "Kernel guard acknowledgement differs from requested batch")
    require(live_guard() == compiled, "Kernel guard readback differs from acknowledged transaction")
    # JSON makes tuple group keys into lists; canonicalize before storing/comparing.
    journal.value["guard"] = decode(json.dumps(compiled))
    journal.done()


def recover_guard(p, expected_batch_sha256):
    """Record only the exact installed guard from an otherwise empty failed apply."""
    batch_sha256 = hashlib.sha256(json.dumps(firewall(p)).encode()).hexdigest()
    require(expected_batch_sha256 == batch_sha256, "Explicit exact batch hash required")
    with locked_journal(p, allow_pending_guard=True) as journal:
        require(journal.value.get("pending") == {"operation": "install-guard", "batch_sha256": batch_sha256},
                "Recovery only accepts the exact pending install-guard operation")
        require(journal.value.get("resources") == {} and journal.value.get("files") == {}
                and not any(journal.value.get(key) for key in ("guard", "pool_directory", "ready", "boot_verified")),
                "Recovery requires no owned resources, files, storage or completed guard")
        require(set(os.listdir(journal.fd)) == {"lock", "journal.json"}, "Recovery state directory is not empty")
        preflight(p)
        expected = canonical_guard(firewall(p))
        actual = live_guard()
        require(actual == expected, "Installed guard does not exactly match pending batch semantics")
        require(live_guard() == actual, "Guard changed during recovery verification")
        journal.value["guard"] = actual
        journal.value["guard_recovery"] = {"batch_sha256": batch_sha256, "verified_existing_only": True}
        journal.done()
        return {"guard_recovered": True, "firewall_modified": False, "resources_created": False,
                "journal": str(STATE / "journal.json")}




def ensure_resource(p, journal, kind, name, text):
    key = kind + ":" + name
    if key in journal.value["resources"]:
        return
    listing = {"domain": ["list", "--all", "--name"], "network": ["net-list", "--all", "--name"], "pool": ["pool-list", "--all", "--name"]}
    require(name not in run(["virsh", "-c", p["connection"], *listing[kind]]).split(), "Resource name appeared during apply")
    filename = kind + "-" + name + ".xml"
    journal.intent({"operation": "define", "kind": kind, "name": name, "uuid": identity(p, kind, name),
                    "requested_definition_sha256": definition_hash(text)})
    exclusive(journal.fd, filename, text)
    command = {"domain": "define", "network": "net-define", "pool": "pool-define"}[kind]
    verify_guard(journal.value)
    run(["virsh", "-c", p["connection"], command, str(STATE / filename)])
    actual = resource_xml(p, kind, name)
    require(ET.fromstring(actual).findtext("uuid") == identity(p, kind, name), "Defined UUID differs")
    journal.value["resources"][key] = {"uuid": identity(p, kind, name), "definition_sha256": definition_hash(actual)}
    record_file(journal, STATE / filename)
    journal.done()
    verify_resources(p, journal.value, allow_running=True)


def ensure_keys(journal, name):
    path = STATE / name
    if str(path) in journal.value["files"]:
        return
    journal.intent({"operation": "generate-dedicated-ssh-key", "name": name})
    require(not checked_path(path).exists() and not checked_path(str(path) + ".pub").exists(), "SSH identity collision")
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hetero-dev-only", "-f", str(path)])
    for filename in (path, Path(str(path) + ".pub")):
        fd = os.open(filename.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=journal.fd)
        try:
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        record_file(journal, filename)
    journal.done()


def guest_seed(p, name, admin_public, host_private, host_public):
    outputs = render(p, admin_public)
    data = decode(outputs[name + "/user-data"].split("\n", 1)[1])
    data["users"][0]["sudo"] = ["ALL=(ALL) NOPASSWD:ALL"]
    # Supplied ssh_keys bypass generation; keep a valid ed25519-only fallback.
    data["ssh_keys"] = {"ed25519_private": host_private, "ed25519_public": host_public.strip()}
    data["ssh_genkeytypes"] = ["ed25519"]
    data["ssh_publish_hostkeys"] = {"enabled": False}
    return {"user-data": "#cloud-config\n" + json.dumps(data) + "\n",
            "meta-data": outputs[name + "/meta-data"], "network-config": outputs[name + "/network-config"]}


def guest_cloud_init_terminal(reader=None):
    """No cache access while any cloud-init stage is still executing."""
    import json
    import os
    import selectors
    import subprocess
    import time

    def bounded(args):
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output = bytearray()
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 10
                while selector.get_map():
                    assert time.monotonic() < deadline
                    for key, _ in selector.select(0.1):
                        data = os.read(key.fileobj.fileno(), 16384)
                        if not data:
                            selector.unregister(key.fileobj)
                        else:
                            output.extend(data)
                            assert len(output) <= 256 * 1024
            return process.wait(timeout=2), output.decode()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()

    reader = reader or bounded
    rc, output = reader(["cloud-init", "status", "--format", "json"])
    status = json.loads(output)
    assert rc in (0, 2) and status.get("status") == "done"
    assert status.get("extended_status") in ("done", "degraded done") and status.get("errors") == []
    warnings = status.get("recoverable_errors", {})
    assert isinstance(warnings, dict) and set(warnings) <= {"WARNING"}
    known = ("cloud-config failed schema validation!",
             "cloud-config failed schema validation! You may run 'sudo cloud-init schema --system' to check the details.")
    assert all(item in known for item in warnings.get("WARNING", []))
    rc, output = reader(["systemctl", "show", "cloud-init-local.service", "cloud-init.service",
                         "cloud-init-network.service", "cloud-config.service", "cloud-final.service",
                         "--property=SubState", "--value"])
    states = output.split()
    assert rc == 0 and len(states) == 5 and all(state in ("dead", "exited") for state in states)


def guest_clean_main():
    """Fixed plain-clean operation for a verified fresh owned guest only."""
    import hashlib
    import json
    import os
    import pathlib
    import socket
    import stat
    import subprocess
    import sys
    import yaml
    from cloudinit import settings
    from cloudinit.stages import Init

    stage = "identity"
    try:
        request = json.loads(sys.stdin.buffer.read(2 * 1024 * 1024 + 1))
        name, instance = request["name"], request["instance"]
        assert os.geteuid() == 0 and socket.gethostname() == name
        assert name in ("hetero-dev-1", "hetero-dev-2", "hetero-dev-3")

        def read_owned(path):
            for ancestor in [*reversed(path.parents), path]:
                info = ancestor.lstat()
                assert info.st_uid == 0 and not stat.S_ISLNK(info.st_mode) and not info.st_mode & 0o022
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 2 * 1024 * 1024
                data = source.read(2 * 1024 * 1024 + 1)
                assert len(data) <= 2 * 1024 * 1024
                return data

        protected = [pathlib.Path(path) for path in (
            "/etc/machine-id", "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key.pub")]
        before = {path: read_owned(path) for path in protected}
        assert before[protected[0]].decode().strip() == instance.replace("-", "")
        old = request["old"]
        stage = "pinned-host-keys"
        assert before[protected[1]].strip() == old["ssh_keys"]["ed25519_private"].encode().strip()
        assert before[protected[2]].decode().split()[:2] == old["ssh_keys"]["ed25519_public"].split()[:2]

        stage = "cloud-init-terminal"
        guest_cloud_init_terminal()
        stage = "fresh-clean-scope"
        init = Init(ds_deps=[])
        init.read_cfg()
        assert str(init.paths.cloud_dir) in ("/var/lib/cloud", "/var/lib/cloud/")
        assert str(settings.CLEAN_RUNPARTS_DIR) == "/etc/cloud/clean.d"
        hooks = pathlib.Path("/etc/cloud/clean.d")
        assert not hooks.is_symlink() and (not hooks.exists() or not list(hooks.iterdir()))
        for path in ("/etc/heteronetwork", "/var/lib/heteronetwork", "/etc/kubernetes", "/var/lib/kubelet",
                     "/var/lib/rancher", "/var/lib/docker", "/var/lib/heterocloud"):
            assert not os.path.lexists(path)
        cloud = pathlib.Path("/var/lib/cloud")
        assert cloud.resolve() == cloud and cloud.stat().st_uid == 0 and not cloud.stat().st_mode & 0o022
        directory = cloud / "instances" / instance
        assert pathlib.Path("/var/lib/cloud/instance").resolve() == directory
        assert sorted(path.name for path in (cloud / "instances").iterdir()) == [instance]
        seed = cloud / "seed"
        assert not seed.is_symlink()
        if seed.exists():
            for directory_name, directories, files in os.walk(seed, followlinks=False):
                assert not files
                assert all(not (pathlib.Path(directory_name) / child).is_symlink() for child in directories)
        stage = "exact-userdata"
        original = read_owned(directory / "user-data.txt")
        assert old["ssh_genkeytypes"] == [] and yaml.safe_load(original) == old
        fingerprint = hashlib.sha256(original).hexdigest()
        assert request["phase"] in ("inspect", "clean")
        if request["phase"] == "clean":
            assert request["expected_userdata_hash"] == fingerprint and request["fresh_unenrolled"] is True
            stage = "cloud-init-terminal"
            guest_cloud_init_terminal()
            stage = "plain-clean"
            # No flags: preserve machine-id, logs, seed, SSH/network/fstab config.
            result = subprocess.run(["cloud-init", "clean"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            assert result.returncode == 0
            assert all(read_owned(path) == data for path, data in before.items())
            assert not (cloud / "instance").exists()
        print(json.dumps({"ok": True, "userdata_hash": fingerprint, "host_keys_unchanged": True,
                          "machine_id_unchanged": True, "plain_clean": request["phase"] == "clean"}))
    except Exception:
        print(json.dumps({"ok": False, "stage": stage}))


def repair_ssh(p, name):
    address = p["addresses"][p["vms"].index(name)]
    return ["ssh", "-F", "/dev/null", "-i", str(STATE / "admin_ed25519"),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=5",
            "-o", "ConnectionAttempts=1", "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", "UserKnownHostsFile=" + str(STATE / "known_hosts"), "devadmin@" + address]


def repair_guest_clean(p, name, old, phase, expected=None):
    import shlex
    code = inspect.getsource(guest_cloud_init_terminal) + "\n" + inspect.getsource(guest_clean_main) + "\nguest_clean_main()\n"
    request = {"name": name, "instance": identity(p, "domain", name), "old": old,
               "phase": phase, "expected_userdata_hash": expected, "fresh_unenrolled": phase == "clean"}
    result = decode(run(repair_ssh(p, name) + ["sudo -n python3 -c " + shlex.quote(code)],
                        json.dumps(request), timeout=30))
    if result.get("ok") is not True or result.get("host_keys_unchanged") is not True:
        raise GuestRepairFailure(result.get("stage"))
    return result["userdata_hash"]


def repaired_seed(p, name, old_text, admin_public, host_private, host_public):
    expected = guest_seed(p, name, admin_public, host_private, host_public)["user-data"]
    desired = decode(expected.split("\n", 1)[1])
    old = decode(old_text.split("\n", 1)[1])
    require(old_text.startswith("#cloud-config\n") and old == dict(desired, ssh_genkeytypes=[]),
            "Seed repair requires exactly the known empty ssh_genkeytypes defect")
    return old, expected


def repair_seed(p, name, expected_userdata_sha256, inspect_only=False, fresh_unenrolled=False):
    require(name in p["vms"], "Explicit owned VM is required")
    require(inspect_only or fresh_unenrolled, "Explicit fresh never-enrolled guest confirmation is required")
    with locked_journal(p) as journal:
        require(set(journal.value["resources"]) == {"pool:" + p["name"], "network:" + p["name"],
                *("domain:" + vm for vm in p["vms"])}, "Seed repair requires the complete owned resource set")
        verify_files(journal.value)
        verify_resources(p, journal.value, allow_running=True)
        verify_guard(journal.value)
        preflight(p, journal.value)
        initial_state = resource_info(p, "domain", name).get("State")
        require(initial_state in ("running", "shut off"), "Selected guest is not in a repairable state")
        source = STATE / (name + "-user-data")
        seed = Path(p["pool_path"]) / (name + "-seed.iso")
        require(str(source) in journal.value["files"] and str(seed) in journal.value["files"], "Seed files must be journaled")
        require(expected_userdata_sha256 == journal.value["files"][str(source)]["sha256"], "Explicit old userdata hash required")
        old, replacement = repaired_seed(p, name, read(source).decode(), read(STATE / "admin_ed25519.pub").decode(),
                                        read(STATE / (name + "-host-ed25519")).decode(),
                                        read(STATE / (name + "-host-ed25519.pub")).decode())
        if inspect_only:
            require(initial_state == "running", "Inspect-only requires the selected guest already running")
            guest_hash = repair_guest_clean(p, name, old, "inspect")
            return {"seed_repair_inspected": name, "mutation_performed": False, "guest_userdata_sha256": guest_hash}
        pool = root_directory(p["pool_path"])
        complete = False
        try:
            backup_source, backup_seed = source.name + ".before-schema-repair", seed.name + ".before-schema-repair"
            new_source, new_seed = source.name + ".schema-repair", seed.name + ".schema-repair"
            require(not any((STATE / filename).exists() for filename in (backup_source, new_source))
                    and not any((seed.parent / filename).exists() for filename in (backup_seed, new_seed)),
                    "Seed repair artifacts already exist; inspect pending state")
            journal.intent({"operation": "repair-seed-schema", "vm": name, "old_userdata_sha256": expected_userdata_sha256})
            if initial_state == "shut off":
                verify_guard(journal.value)
                run(["virsh", "-c", p["connection"], "start", identity(p, "domain", name)])
            deadline = time.monotonic() + 90
            while True:
                require(time.monotonic() < deadline, "Selected guest SSH readiness deadline expired")
                verify_guard(journal.value)
                try:
                    require(run(repair_ssh(p, name) + ["hostname"], timeout=10).strip() == name, "Selected guest identity differs")
                    break
                except (Refusal, subprocess.SubprocessError):
                    time.sleep(1)
            guest_hash = repair_guest_clean(p, name, old, "inspect")
            journal.value["pending"]["guest_userdata_sha256"] = guest_hash
            journal.save()
            exclusive(journal.fd, new_source, replacement)
            exclusive(pool, new_seed, b"")
            run(["cloud-localds", "--network-config=" + str(STATE / (name + "-network-config")),
                 str(seed.parent / new_seed), str(STATE / new_source), str(STATE / (name + "-meta-data"))], timeout=60)
            staged = os.open(new_seed, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pool)
            try:
                os.fchmod(staged, 0o600)
                os.fsync(staged)
            finally:
                os.close(staged)
            os.fsync(pool)
            repair_guest_clean(p, name, old, "clean", guest_hash)
            verify_guard(journal.value)
            run(["virsh", "-c", p["connection"], "shutdown", identity(p, "domain", name)])
            deadline = time.monotonic() + 90
            while resource_info(p, "domain", name).get("State") != "shut off":
                require(time.monotonic() < deadline, "Selected guest shutdown deadline expired")
                time.sleep(1)
            verify_files(journal.value)
            for directory, original, backup, new in ((journal.fd, source.name, backup_source, new_source),
                                                    (pool, seed.name, backup_seed, new_seed)):
                os.rename(original, backup, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
                os.rename(new, original, src_dir_fd=directory, dst_dir_fd=directory)
                fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(directory)
            for path in (source, seed, STATE / backup_source, seed.parent / backup_seed):
                record_file(journal, path)
            journal.save()
            verify_guard(journal.value)
            run(["virsh", "-c", p["connection"], "start", identity(p, "domain", name)])
            deadline = time.monotonic() + 180
            while True:
                require(time.monotonic() < deadline, "Repaired guest boot deadline expired")
                verify_guard(journal.value)
                try:
                    require(run(repair_ssh(p, name) + ["hostname"], timeout=10).strip() == name, "Repaired guest identity differs")
                    run(repair_ssh(p, name) + ["sudo", "-n", "cloud-init", "schema", "--system"], timeout=20)
                    run(repair_ssh(p, name) + ["sudo", "-n", "cloud-init", "status", "--wait"], timeout=20)
                    break
                except (Refusal, subprocess.SubprocessError):
                    time.sleep(1)
            verify_files(journal.value)
            verify_resources(p, journal.value, allow_running=True)
            verify_guard(journal.value)
            journal.value.setdefault("seed_schema_repairs", {})[name] = {"old_userdata_sha256": expected_userdata_sha256,
                                                                        "boot_verified": True}
            journal.done()
            complete = True
            return {"seed_repaired": name, "cloud_init_verified": True, "keys_rotated": False}
        finally:
            if not complete and initial_state == "shut off":
                try:
                    require(ET.fromstring(resource_xml(p, "domain", name)).findtext("uuid") == identity(p, "domain", name),
                            "Repair cleanup identity differs")
                    if resource_info(p, "domain", name).get("State") == "running":
                        run(["virsh", "-c", p["connection"], "destroy", identity(p, "domain", name)])
                except (ValueError, OSError, subprocess.SubprocessError):
                    print("Selected repair guest stop could not be confirmed; inspect local journal.", file=sys.stderr)
            os.close(pool)


def validate_base_header(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as image:
        header = image.read(104)
    require(len(header) >= 104 and header[:4] == b"QFI\xfb"
            and struct.unpack_from(">I", header, 4)[0] in (2, 3)
            and struct.unpack_from(">Q", header, 8)[0] == 0
            and struct.unpack_from(">I", header, 16)[0] == 0, "Base must be QCOW2 with no backing file")
    # QEMU's external-data-file feature must not select an unrelated host file.
    if struct.unpack_from(">I", header, 4)[0] == 3:
        require(not struct.unpack_from(">Q", header, 72)[0] & 4, "External QCOW2 data file is not permitted")


def apply(p, image_directory):
    require(image_directory, "--image-directory is required")
    with locked_journal(p, create=True) as journal:
        if journal.value["files"]:
            verify_files(journal.value)
        preflight(p, journal.value)
        verification = verify_image(p, image_directory)
        journal.value["image_verification"] = verification
        journal.value["pool_path"] = p["pool_path"]
        journal.save()
        ensure_guard(p, journal)
        target = Path(p["pool_path"])
        if not journal.value.get("pool_directory"):
            parent = root_directory(target.parent)
            try:
                journal.intent({"operation": "create-pool-directory", "path": str(target)})
                os.mkdir(target.name, 0o711, dir_fd=parent)
                created = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    os.fchmod(created, 0o711)
                    os.fsync(created)
                finally:
                    os.close(created)
                os.fsync(parent)
                journal.value["pool_directory"] = inode(target)
                journal.done()
            finally:
                os.close(parent)
        pool = root_directory(target)
        try:
            info = os.fstat(pool)
            require([info.st_dev, info.st_ino] == journal.value["pool_directory"], "Owned pool directory replaced")
            require(stat.S_IMODE(info.st_mode) in (0o700, 0o711), "Unexpected owned pool directory mode")
            if stat.S_IMODE(info.st_mode) != 0o711:
                journal.intent({"operation": "normalize-owned-pool-mode", "mode": "0711"})
                os.fchmod(pool, 0o711)
                os.fsync(pool)
                journal.done()
            base = target / "ubuntu-base.img"
            if str(base) not in journal.value["files"]:
                journal.intent({"operation": "copy-verified-image", "path": str(base)})
                source_path = checked_path(Path(image_directory) / p["image_url"].rsplit("/", 1)[1])
                source_fd = os.open(source_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(source_fd, "rb") as source:
                    info = os.fstat(source.fileno())
                    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 2 * 1024**3, "Invalid image source")
                    output_fd = os.open(base.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pool)
                    with os.fdopen(output_fd, "wb") as output:
                        digest = hashlib.sha256()
                        count = 0
                        while chunk := source.read(1024 * 1024):
                            count += len(chunk)
                            require(count <= 2 * 1024**3, "Image grew beyond bound")
                            digest.update(chunk)
                            output.write(chunk)
                        require(count == info.st_size and digest.hexdigest() == verification["image_sha256"], "Copied image differs")
                        output.flush()
                        os.fchmod(output.fileno(), 0o400)
                        os.fsync(output.fileno())
                validate_base_header(base)
                chain = decode(run(["qemu-img", "info", "--output=json", "--backing-chain", str(base)]))
                require(len(chain) == 1 and chain[0].get("format") == "qcow2" and not chain[0].get("backing-filename")
                        and chain[0].get("virtual-size", 0) <= p["disk_gib"] * 1024**3, "Unexpected image format/backing chain")
                record_file(journal, base)
                journal.done()
            ensure_keys(journal, "admin_ed25519")
            for name in p["vms"]:
                ensure_keys(journal, name + "-host-ed25519")
                disk = target / (name + ".qcow2")
                if str(disk) not in journal.value["files"]:
                    journal.intent({"operation": "create-fresh-disk", "path": str(disk)})
                    exclusive(pool, disk.name, b"")
                    run(["qemu-img", "create", "-f", "qcow2", str(disk), str(p["disk_gib"]) + "G"])
                    run(["qemu-img", "convert", "-n", "-f", "qcow2", "-O", "qcow2", str(base), str(disk)], timeout=300)
                    fd = os.open(disk.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pool)
                    try:
                        os.fchmod(fd, 0o600)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    record_file(journal, disk, mutable=True)
                    journal.done()
                seed = target / (name + "-seed.iso")
                if str(seed) not in journal.value["files"]:
                    journal.intent({"operation": "create-private-seed", "path": str(seed)})
                    seed_data = guest_seed(p, name, read(STATE / "admin_ed25519.pub").decode(),
                                          read(STATE / (name + "-host-ed25519")).decode(),
                                          read(STATE / (name + "-host-ed25519.pub")).decode())
                    for suffix, data in seed_data.items():
                        filename = name + "-" + suffix
                        exclusive(journal.fd, filename, data)
                        record_file(journal, STATE / filename)
                    exclusive(pool, seed.name, b"")
                    run(["cloud-localds", "--network-config=" + str(STATE / (name + "-network-config")),
                         str(seed), str(STATE / (name + "-user-data")), str(STATE / (name + "-meta-data"))], timeout=60)
                    os.chmod(seed.name, 0o600, dir_fd=pool, follow_symlinks=False)
                    fd = os.open(seed.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=pool)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    record_file(journal, seed)
                    journal.done()
            known_hosts = STATE / "known_hosts"
            if str(known_hosts) not in journal.value["files"]:
                journal.intent({"operation": "pin-guest-host-identities"})
                lines = []
                for name, address in zip(p["vms"], p["addresses"]):
                    public = " ".join(read(STATE / (name + "-host-ed25519.pub")).decode().split()[:2])
                    lines.append(f"{name},{address} {public}\n")
                exclusive(journal.fd, "known_hosts", "".join(lines))
                record_file(journal, known_hosts)
                journal.done()
            # Recheck the inventory while locked immediately before definitions/NAT.
            preflight(p, journal.value)
            ensure_resource(p, journal, "pool", p["name"], pool_xml(p))
            ensure_resource(p, journal, "network", p["name"], network_xml(p))
            for kind, command in (("pool", "pool-start"), ("network", "net-start")):
                verify_guard(journal.value)
                if resource_info(p, kind, p["name"]).get("State" if kind == "pool" else "Active") not in ("running", "yes"):
                    run(["virsh", "-c", p["connection"], command, identity(p, kind, p["name"])])
                verify_guard(journal.value)
            for name in p["vms"]:
                ensure_resource(p, journal, "domain", name, domain_xml(p, name))
            verify_files(journal.value)
            verify_resources(p, journal.value, allow_running=True)
            verify_guard(journal.value)
            journal.value["ready"] = True
            journal.save()
            first_boot(p, journal)
            return {"created_or_verified": True, "guests_boot_verified": p["vms"], "guard_verified": True,
                    "journal": str(STATE / "journal.json"), "admin_key": str(STATE / "admin_ed25519"),
                    "known_hosts": str(known_hosts), "production_modified": False}
        finally:
            os.close(pool)


def first_boot(p, journal):
    started = []
    journal.value.pop("boot_verified", None)
    journal.save()
    try:
        for name in p["vms"]:
            verify_guard(journal.value)
            info = resource_info(p, "domain", name)
            require(info.get("State") in ("running", "shut off"), "Unexpected dev guest state")
            if info["State"] == "shut off":
                started.append(name)
                run(["virsh", "-c", p["connection"], "start", identity(p, "domain", name)])
                text = resource_xml(p, "domain", name)
                require(ET.fromstring(text).findtext("uuid") == identity(p, "domain", name), "Started UUID differs")
                journal.value["resources"]["domain:" + name]["definition_sha256"] = definition_hash(text)
                journal.save()
        deadline = time.monotonic() + 300
        for name, address in zip(p["vms"], p["addresses"]):
            ssh = ["ssh", "-F", "/dev/null", "-i", str(STATE / "admin_ed25519"),
                   "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ForwardAgent=no",
                   "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                   "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                   "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=5",
                   "-o", "ConnectionAttempts=1", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                   "-o", "UserKnownHostsFile=" + str(STATE / "known_hosts"), "devadmin@" + address]
            while True:
                verify_guard(journal.value)
                require(time.monotonic() < deadline, "First boot deadline expired")
                try:
                    actual = run(ssh + ["hostname"], timeout=min(10, max(1, deadline - time.monotonic())))
                    require(actual.strip() == name, "Guest hostname mismatch")
                    run(ssh + ["sudo", "-n", "cloud-init", "status", "--wait"],
                        timeout=min(30, max(1, deadline - time.monotonic())))
                    break
                except (ValueError, subprocess.SubprocessError):
                    require(time.monotonic() < deadline, "First boot failed; inspect private guest console")
                    time.sleep(min(2, max(0, deadline - time.monotonic())))
        verify_guard(journal.value)
        verify_resources(p, journal.value, allow_running=True)
        require(all(resource_info(p, "domain", name).get("State") == "running" for name in p["vms"]),
                "Guest stopped before boot verification completed")
        journal.value["boot_verified"] = p["vms"]
        journal.save()
    except BaseException:
        # Roll back runtime only for guests started by this invocation. Keep
        # definitions/disks/guard for inspection; never delete or stop prior VMs.
        for name in reversed(started):
            try:
                text = resource_xml(p, "domain", name)
                require(ET.fromstring(text).findtext("uuid") == identity(p, "domain", name), "Rollback identity drift")
                if resource_info(p, "domain", name).get("State") == "running":
                    run(["virsh", "-c", p["connection"], "destroy", identity(p, "domain", name)])
            except (ValueError, OSError, subprocess.SubprocessError):
                print("Owned guest stop could not be confirmed; inspect local journal.", file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "render", "preflight", "verify-image", "apply", "recover-guard", "repair-seed"))
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--ssh-public-key", type=Path)
    parser.add_argument("--image-directory", type=Path)
    parser.add_argument("--confirm-create", choices=("hetero-dev",))
    parser.add_argument("--expected-batch-sha256")
    parser.add_argument("--vm", choices=("hetero-dev-1", "hetero-dev-2", "hetero-dev-3"))
    parser.add_argument("--expected-userdata-sha256")
    parser.add_argument("--confirm-repair", choices=("hetero-dev",))
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--confirm-fresh-unenrolled", action="store_true")
    args = parser.parse_args()
    p = profile(args.profile)
    if args.command == "repair-seed":
        require(args.inspect_only or args.confirm_repair == "hetero-dev", "Explicit --confirm-repair hetero-dev is required")
        old_umask = os.umask(0o077)
        try:
            result = repair_seed(p, args.vm, args.expected_userdata_sha256, inspect_only=args.inspect_only,
                                 fresh_unenrolled=args.confirm_fresh_unenrolled)
        finally:
            os.umask(old_umask)
    elif args.command == "recover-guard":
        result = recover_guard(p, args.expected_batch_sha256)
    elif args.command == "apply":
        require(args.confirm_create == "hetero-dev", "Explicit --confirm-create hetero-dev is required")
        old_umask = os.umask(0o077)
        try:
            result = apply(p, args.image_directory)
        finally:
            os.umask(old_umask)
    elif args.command == "plan":
        result = plan(p)
    elif args.command == "preflight":
        result = preflight(p)
    elif args.command == "verify-image":
        require(args.image_directory, "--image-directory is required")
        result = verify_image(p, args.image_directory)
    else:
        require(args.output and args.ssh_public_key, "--output and --ssh-public-key are required")
        key = read(args.ssh_public_key, 4096).decode("ascii")
        run(["ssh-keygen", "-l", "-f", str(checked_path(args.ssh_public_key))])
        write_render(args.output, render(p, key))
        result = {"rendered": True, "activation_performed": False, "isolation_verified": False}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, StopIteration, ET.ParseError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(failure_report(error)), file=sys.stderr)
        sys.exit(1)
