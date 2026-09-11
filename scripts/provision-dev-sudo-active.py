#!/usr/bin/env python3
"""Provision and explicitly activate majority-gated sudo on the fixed DEV guests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import resource
import socket
import stat
import subprocess
import sys
import time
import urllib.request


BUNDLE = Path("/opt/heteronetwork-dev-sudo-active-v7")
VERSION = "0.1.15-dev.8"
SOURCE_COMMIT = "04ec0371dae8efad1b24efac192e016b0f8a14b1"
RELEASE_DOCUMENT_SHA256 = "69cca7eaeaf594478b96bcbaa11a66c534237ac6db477ea8842fbb228d36bef6"
PLUGIN_HEADER_SHA256 = "11234d6e47e6da95adcb3ace71dc93f1d94b759aeca4cd938d829c076adfb35f"
OLD_INCOMPATIBLE_PLUGIN_SHA256 = "b835943bb34931f785518073814b666fa2eaf9d3ee3fdf7538706954ff9a2b7e"
MANIFEST_SHA256 = "60302d9b06bd7300ecf6547bdd1b266c47dd3760b4c7e892fce9eaab1c8718b5"
POLICY_SHA256 = "9f322e6d2a9203fdd6b6faa7d175a8a7ae9616d29b234818f2bb8dde06a366d6"
LOCAL_UNIT_SHA256 = "1a7c9f32574555230056389d2b413e9db57f13a7dc4ccca3236a3735a229853d"
SIGNER_UNIT_SHA256 = "15cebfc09eb6934138230ba8d783aa9c1ab1208d89759b353aea68f4a9fc1662"
PREVIOUS_SIGNER_UNIT_SHA256 = "a7c966d14295d62ff14f645092a161b846f7b6a8b993a9d686cc8fa8849a8328"
LOGIN_HELPER_SHA256 = "0fbd6d19edf72fac10baf0298c6d0cd09ca8d1136534433d9174009bef4daeac"
PREVIOUS_LOGIN_HELPER_SHA256 = "412c8f5f409fbc51356627a363466983c8c9bc869fd5861105ef7c857c87c120"
APPROVE_HELPER_SHA256 = "405800c59902ea8bee15375657f65ce0d1d2496ffab3a6340ea65cc920b20787"
CLUSTER = "02282a57-784b-4269-90a0-8fda47ee62ec"
ISSUER = "https://heterocloud.mizuame.app/id/realms/heterocloud"
OWNER_SUBJECT = "4daa569e-635c-49ed-bb17-5fe0a07581b2"
OWNER_EMAIL = "fasutotesuto@gmail.com"
CLIENT_ID = "ipars-web"
VPN_CIDR = "10.251.0.0/24"
GUESTS = {
    "hetero-dev-1": ("381d1ae16f555c59b738d8d01dd14c94",
                     "node-e52856163b2fb3a1d67fc03943cbdda2", 1, "10.251.0.1"),
    "hetero-dev-2": ("acc5151b6b245b63864372933dab97da",
                     "node-65bbb4982793bf94af58d9a2506c4fca", 2, "10.251.0.2"),
    "hetero-dev-3": ("165a6e8acc3a56fdbf9bef8c90d6cf4d",
                     "node-dfdf53799602bd2aa9006121c33af69a", 3, "10.251.0.3"),
}
RUNTIME = Path("/opt/heteronetwork/sudo-v2/runtime")
ARTIFACTS = Path("/opt/heteronetwork/sudo-v2/artifacts")
MANIFEST = Path("/etc/heteronetwork/sudo-quorum/manifest.json")
POLICY = Path("/etc/heteronetwork/sudo-quorum/policy.json")
SIGNER_ENV = Path("/etc/heteronetwork/sudo-quorum/signer.env")
SOURCE_SHARE = Path("/var/lib/heteronetwork-dev-sudo-dkg/key-share.json")
SERVICE_SHARE = Path("/etc/credstore/heteronetwork-sudo-quorum-share.json")
LOCAL_CONFIG = Path("/etc/ipars-sudo-v2/config.json")
HOST_KEY = Path("/etc/ipars-sudo-v2/host.key")
LOCAL_UNIT = Path("/etc/systemd/system/heteronetwork-sudo-local.service")
SIGNER_UNIT = Path("/etc/systemd/system/heteronetwork-sudo-quorum-signer.service")
SUDO_CONFIG = Path("/etc/sudo.conf")
PLUGIN_LINE = ("Plugin quorum_v2_gate "
               "/opt/heteronetwork/sudo-v2/artifacts/current/lib/quorum_v2_gate.so")
SYSTEM_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def require(value, reason="DEV sudo activation rejected"):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate_json_key")
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def trusted(path, directory=False, mode=None, owner=0):
    path = Path(path)
    require(path.is_absolute(), "absolute_path_required")
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, "unsafe_path_ancestor")
    info = path.lstat()
    require(info.st_uid == owner and not info.st_mode & 0o7022, "unsafe_path_owner_or_mode")
    require(stat.S_ISDIR(info.st_mode) if directory else
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "wrong_path_type")
    require(mode is None or stat.S_IMODE(info.st_mode) == mode, "wrong_path_mode")
    return info


def read(path, maximum, mode=None, owner=0):
    info = trusted(path, mode=mode, owner=owner)
    require(info.st_size <= maximum, "input_too_large")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "input_too_large")
    return raw


def read_user(path, maximum, uid, mode=0o600):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == mode and info.st_size <= maximum,
            "unsafe_user_file")
    for parent in (path.parent, path.parent.parent):
        metadata = parent.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == uid
                and not metadata.st_mode & 0o022, "unsafe_user_directory")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "user_file_too_large")
    return raw


def bundle(name, maximum=256 * 1024 * 1024):
    return read(BUNDLE / name, maximum, mode=0o600)


def identity():
    hostname = socket.gethostname().split(".")[0]
    require(hostname in GUESTS, "not_a_fixed_dev_guest")
    machine, node, member, vpn_ip = GUESTS[hostname]
    require(read("/etc/machine-id", 128).decode().strip() == machine,
            "machine_identity_mismatch")
    require(os.getuid() == 0 and os.geteuid() == 0, "root_required")
    return hostname, machine, node, member, vpn_ip


def release_payloads():
    release_raw = bundle("release.json", 2 * 1024 * 1024)
    require(RELEASE_DOCUMENT_SHA256 != "0" * 64
            and sha(release_raw) == RELEASE_DOCUMENT_SHA256, "unreviewed_release_document")
    release = decode(release_raw)
    require(release.get("schema_version") == 1 and release.get("component") == "heteronetwork"
            and release.get("version") == VERSION and release.get("commit") == SOURCE_COMMIT,
            "wrong_release_identity")
    native = release["native"]["linux-amd64"]
    sudo = release["sudo_native"]["linux-amd64"]
    require(sudo.get("source_commit") == SOURCE_COMMIT and sudo.get("profile") == "release"
            and sudo.get("plugin_header_sha256") == PLUGIN_HEADER_SHA256,
            "wrong_sudo_release_provenance")
    names = {
        "native/ipars": native["files"]["bin/ipars"],
        "native/iparsd": native["files"]["bin/iparsd"],
        "sudo/local-sudo-v2": sudo["files"]["bin/local-sudo-v2"]["sha256"],
        "sudo/quorum_v2_gate.so": sudo["files"]["lib/quorum_v2_gate.so"]["sha256"],
        "sudo/NOT_ENABLED.txt": sudo["files"]["NOT_ENABLED.txt"]["sha256"],
    }
    require(all(isinstance(value, str) and HASH.fullmatch(value) for value in names.values()),
            "invalid_release_hash")
    require(names["sudo/quorum_v2_gate.so"] != OLD_INCOMPATIBLE_PLUGIN_SHA256,
            "sudo_api_1_21_incompatible_plugin")
    payloads = {name: bundle(name, 128 * 1024 * 1024) for name in names}
    require(all(sha(payloads[name]) == digest for name, digest in names.items()),
            "release_payload_mismatch")
    require(all(payloads[name].startswith(b"\x7fELF\x02\x01\x01")
                for name in names if name != "sudo/NOT_ENABLED.txt"), "wrong_binary_format")
    return release_raw, payloads


def public_inputs():
    manifest_raw = bundle("sudo-manifest.json", 1024 * 1024)
    policy_raw = bundle("sudo-policy.json", 2 * 1024 * 1024)
    require(sha(manifest_raw) == MANIFEST_SHA256 and sha(policy_raw) == POLICY_SHA256,
            "public_policy_hash_mismatch")
    manifest, policy = decode(manifest_raw), decode(policy_raw)
    require(policy.get("schema_version") == 2 and policy.get("manifest") == manifest
            and manifest.get("cluster_id") == CLUSTER and manifest.get("epoch") == 1,
            "public_policy_identity_mismatch")
    members = {item["node_id"]: item for item in manifest["members"]}
    require(set(members) == {value[1] for value in GUESTS.values()} and len(members) == 3,
            "wrong_voter_set")
    for _, node, member, vpn_ip in GUESTS.values():
        require(members[node] == {"node_id": node, "identifier": member,
                                  "endpoint": f"http://{vpn_ip}:8981"}, "wrong_voter_endpoint")
        caller = policy["hosts"][node]["callers"].get("1000")
        require(caller == {"issuer": ISSUER, "subject": OWNER_SUBJECT},
                "wrong_owner_policy")
    return manifest_raw, policy_raw, policy


def mkdir(path, mode, owner=0, group=0):
    path = Path(path)
    if not os.path.lexists(path):
        path.mkdir(mode=mode)
        os.chown(path, owner, group)
        os.chmod(path, mode)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and info.st_gid == group
            and stat.S_IMODE(info.st_mode) == mode, "unexpected_directory_state")


def install(path, raw, mode):
    path = Path(path)
    if not os.path.lexists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
    require(read(path, len(raw), mode=mode) == raw, "installed_file_mismatch")


def install_known_replacement(path, raw, mode, previous_sha):
    path = Path(path)
    if os.path.lexists(path):
        current = read(path, max(len(raw), 65536), mode=mode)
        if current != raw:
            require(sha(current) == previous_sha, "unknown_existing_file")
            atomic_replace(path, raw, mode)
    else:
        install(path, raw, mode)
    require(read(path, len(raw), mode=mode) == raw, "replacement_file_mismatch")


def atomic_replace(path, raw, mode):
    path = Path(path)
    temporary = path.parent / f".{path.name}.sudo-v2-{os.getpid()}"
    require(not os.path.lexists(temporary), "stale_temporary_file")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def select(root):
    current = root / "current"
    if os.path.lexists(current):
        info = current.lstat()
        require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and os.readlink(current) in ("0.1.15-dev.6", "0.1.15-dev.7", VERSION),
                "unexpected_active_slot")
        if os.readlink(current) == VERSION:
            return False
    temporary = root / f".current-{os.getpid()}"
    require(not os.path.lexists(temporary), "stale_slot_link")
    os.symlink(VERSION, temporary)
    os.replace(temporary, current)
    return True


def systemctl(*arguments, check=True):
    result = subprocess.run(["/usr/bin/systemctl", *arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=SYSTEM_ENV,
                            cwd="/", timeout=30, check=False)
    require(not check or result.returncode == 0, "systemd_operation_failed")
    return result


def unit_state(name):
    fields = ("LoadState", "ActiveState", "SubState", "FragmentPath", "DropInPaths",
              "UnitFileState", "NeedDaemonReload")
    result = systemctl("show", "--no-pager", "--property=" + ",".join(fields), name)
    values = unique(line.partition("=")[::2] for line in result.stdout.decode().splitlines())
    require(set(values) == set(fields) and values["LoadState"] == "loaded"
            and not values["DropInPaths"] and values["NeedDaemonReload"] == "no",
            "unexpected_unit_definition")
    return values


def plugin_directives(raw):
    directives = []
    for line in raw.decode("utf-8").splitlines():
        directive = line.split("#", 1)[0].strip()
        require(not directive.endswith("\\"), "sudo_config_continuation_requires_review")
        if directive and directive.split()[0].lower() == "plugin":
            directives.append(directive)
    return directives


def require_plugin(active):
    raw = read(SUDO_CONFIG, 65536, mode=0o644)
    directives = plugin_directives(raw)
    require(directives == ([PLUGIN_LINE] if active else []), "unexpected_sudo_plugin_state")
    return raw


def signer_command(node, vpn_ip, check_only=True):
    command = [str(RUNTIME / "current/bin/iparsd"), "quorum-signer"]
    if check_only:
        command.append("--check-config")
    command.extend([
        "--manifest-path", str(MANIFEST), "--sudo-policy-path", str(POLICY),
        "--key-package-path", str(SERVICE_SHARE), "--node-id", node,
        "--listen", f"{vpn_ip}:8981", "--vpn-pool", VPN_CIDR,
        "--oidc-issuer-url", ISSUER, "--oidc-client-id", CLIENT_ID,
        "--oidc-required-email", OWNER_EMAIL, "--oidc-required-subject", OWNER_SUBJECT,
    ])
    return command


def run_check(command, reason):
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=SYSTEM_ENV, cwd="/", timeout=20)
    require(result.returncode == 0, reason)


def prepare():
    hostname, _, node, member, vpn_ip = identity()
    for name in (LOCAL_UNIT.name, SIGNER_UNIT.name):
        state = unit_state(name)
        require(state["ActiveState"] == "inactive" and state["SubState"] == "dead"
                and state["UnitFileState"] == "disabled", "service_must_be_inactive")
    require_plugin(False)
    release_raw, payloads = release_payloads()
    manifest_raw, policy_raw, policy = public_inputs()
    login = bundle("helpers/heteronetwork-sudo-login", 256 * 1024)
    approve = bundle("helpers/heteronetwork-sudo-approve", 256 * 1024)
    require(LOGIN_HELPER_SHA256 != "0" * 64 and APPROVE_HELPER_SHA256 != "0" * 64
            and sha(login) == LOGIN_HELPER_SHA256 and sha(approve) == APPROVE_HELPER_SHA256,
            "unreviewed_cli_helper")
    local_unit = bundle("units/heteronetwork-sudo-local.service", 65536)
    signer_unit = bundle("units/heteronetwork-sudo-quorum-signer.service", 65536)
    require(sha(local_unit) == LOCAL_UNIT_SHA256 and sha(signer_unit) == SIGNER_UNIT_SHA256,
            "unit_hash_mismatch")
    share = read(SOURCE_SHARE, 1024 * 1024, mode=0o600)
    read(HOST_KEY, 32, mode=0o600)

    for root in (RUNTIME, ARTIFACTS):
        mkdir(root, 0o755)
        mkdir(root / VERSION, 0o755)
    mkdir(RUNTIME / VERSION / "bin", 0o755)
    install(RUNTIME / VERSION / "bin/ipars", payloads["native/ipars"], 0o555)
    install(RUNTIME / VERSION / "bin/iparsd", payloads["native/iparsd"], 0o555)
    install(RUNTIME / VERSION / "release.json", release_raw, 0o444)
    mkdir(ARTIFACTS / VERSION / "bin", 0o755)
    mkdir(ARTIFACTS / VERSION / "lib", 0o755)
    install(ARTIFACTS / VERSION / "bin/local-sudo-v2", payloads["sudo/local-sudo-v2"], 0o755)
    install(ARTIFACTS / VERSION / "lib/quorum_v2_gate.so",
            payloads["sudo/quorum_v2_gate.so"], 0o644)
    install(ARTIFACTS / VERSION / "NOT_ENABLED.txt", payloads["sudo/NOT_ENABLED.txt"], 0o644)
    install(ARTIFACTS / VERSION / "release.json", release_raw, 0o444)
    selected = {"runtime": select(RUNTIME), "artifacts": select(ARTIFACTS)}

    mkdir(MANIFEST.parent, 0o755)
    mkdir(SERVICE_SHARE.parent, 0o700)
    install(MANIFEST, manifest_raw, 0o644)
    install(POLICY, policy_raw, 0o644)
    install(SERVICE_SHARE, share, 0o600)
    env_raw = (f"HETERONETWORK_ADMIN_QUORUM_NODE_ID={node}\n"
               f"HETERONETWORK_ADMIN_QUORUM_LISTEN={vpn_ip}:8981\n"
               f"HETERONETWORK_VPN_POOL={VPN_CIDR}\n"
               f"HETERONETWORK_WEB_OIDC_ISSUER_URL={ISSUER}\n"
               f"HETERONETWORK_WEB_OIDC_CLIENT_ID={CLIENT_ID}\n"
               f"HETERONETWORK_WEB_OIDC_REQUIRED_EMAIL={OWNER_EMAIL}\n"
               f"HETERONETWORK_ADMIN_QUORUM_OWNER_SUBJECT={OWNER_SUBJECT}\n").encode()
    install(SIGNER_ENV, env_raw, 0o600)
    config_raw = (json.dumps({"host_node_id": node, "policy": policy},
                             sort_keys=True, indent=2) + "\n").encode()
    install(LOCAL_CONFIG, config_raw, 0o600)
    install(LOCAL_UNIT, local_unit, 0o644)
    install_known_replacement(SIGNER_UNIT, signer_unit, 0o644, PREVIOUS_SIGNER_UNIT_SHA256)
    install_known_replacement(Path("/usr/local/bin/heteronetwork-sudo-login"), login, 0o555,
                              PREVIOUS_LOGIN_HELPER_SHA256)
    install("/usr/local/bin/heteronetwork-sudo-approve", approve, 0o555)
    systemctl("daemon-reload")

    account = pwd.getpwnam("devadmin")
    require((account.pw_uid, account.pw_gid) == (1000, 1000), "wrong_devadmin_identity")
    user_root = Path(account.pw_dir) / ".config/heteronetwork/sudo"
    for directory in (Path(account.pw_dir) / ".config",
                      Path(account.pw_dir) / ".config/heteronetwork", user_root):
        if not os.path.lexists(directory):
            directory.mkdir(mode=0o700)
            os.chown(directory, 1000, 1000)
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 1000
                and not info.st_mode & 0o022, "unsafe_devadmin_config_directory")
    private, public = user_root / "requester.key", user_root / "requester.pub"
    require(os.path.lexists(private) == os.path.lexists(public), "partial_requester_identity")
    if not os.path.lexists(private):
        run_check(["/usr/sbin/runuser", "-u", "devadmin", "--",
                   str(RUNTIME / "current/bin/ipars"), "quorum", "requester-keygen",
                   "--out", str(private), "--public-out", str(public)],
                  "requester_key_generation_failed")
    for path in (private, public):
        data = read_user(path, 256, 1000)
        require(data and len(data) <= 128, "invalid_requester_identity")
    check_prepared(require_inactive=True)
    return {"guest": hostname, "member": member, "selected": selected,
            "prepared": True, "services_started": False, "plugin_active": False}


def check_prepared(require_inactive):
    hostname, _, node, member, vpn_ip = identity()
    release_payloads()
    manifest_raw, policy_raw, policy = public_inputs()
    require(read(MANIFEST, len(manifest_raw), mode=0o644) == manifest_raw
            and read(POLICY, len(policy_raw), mode=0o644) == policy_raw,
            "installed_policy_mismatch")
    require(decode(read(LOCAL_CONFIG, 2 * 1024 * 1024, mode=0o600))
            == {"host_node_id": node, "policy": policy}, "local_config_mismatch")
    require(read(SERVICE_SHARE, 1024 * 1024, mode=0o600)
            == read(SOURCE_SHARE, 1024 * 1024, mode=0o600), "service_share_mismatch")
    require(os.readlink(RUNTIME / "current") == VERSION
            and os.readlink(ARTIFACTS / "current") == VERSION, "wrong_selected_release")
    run_check(signer_command(node, vpn_ip), "signer_configuration_rejected")
    run_check([str(ARTIFACTS / "current/bin/local-sudo-v2"), "--check-config"],
              "local_configuration_rejected")
    units = {LOCAL_UNIT.name: LOCAL_UNIT, SIGNER_UNIT.name: SIGNER_UNIT}
    for name, path in units.items():
        state = unit_state(name)
        require(state["FragmentPath"] == str(path), "wrong_unit_fragment")
        if require_inactive:
            require_plugin(False)
            require(state["ActiveState"] == "inactive" and state["UnitFileState"] == "disabled",
                    "service_not_inactive")
    return {"guest": hostname, "member": member, "configuration_valid": True}


def wait_http(url, timeout=30):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with opener.open(url, timeout=2) as response:
                if response.status == 200 and response.read(1) == b"":
                    return
        except OSError:
            pass
        time.sleep(0.25)
    raise ValueError("signer_health_timeout")


def require_active():
    hostname, _, _, member, vpn_ip = identity()
    for name in (LOCAL_UNIT.name, SIGNER_UNIT.name):
        state = unit_state(name)
        require(state["ActiveState"] == "active" and state["SubState"] == "running"
                and state["UnitFileState"] == "enabled", "service_not_active")
    wait_http(f"http://{vpn_ip}:8981/healthz", 2)
    deadline = time.monotonic() + 5
    while True:
        try:
            sockets = [
                ((Path("/run/ipars-sudo-v2") / name).lstat(), mode)
                for name, mode in (("adapter.sock", 0o600), ("submit.sock", 0o666))
            ]
        except FileNotFoundError:
            if time.monotonic() >= deadline:
                raise ValueError("local_socket_readiness_timeout")
            time.sleep(0.05)
            continue
        require(all(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                    and stat.S_IMODE(info.st_mode) == mode for info, mode in sockets),
                "invalid_local_socket")
        break
    return {"guest": hostname, "member": member, "services_active": True}


def start():
    states = [unit_state(name) for name in (LOCAL_UNIT.name, SIGNER_UNIT.name)]
    require_plugin(False)
    check_prepared(require_inactive=False)
    if all(state["ActiveState"] == "active" and state["SubState"] == "running"
           and state["UnitFileState"] == "enabled" for state in states):
        return {**require_active(), "plugin_active": False, "changed": False}
    had_active_service = any(state["ActiveState"] == "active" for state in states)
    try:
        systemctl("enable", "--now", SIGNER_UNIT.name)
        systemctl("enable", "--now", LOCAL_UNIT.name)
        return {**require_active(), "plugin_active": False, "changed": True}
    except BaseException:
        if not had_active_service:
            systemctl("disable", "--now", LOCAL_UNIT.name, SIGNER_UNIT.name, check=False)
        raise


def all_signers():
    for _, _, _, vpn_ip in GUESTS.values():
        wait_http(f"http://{vpn_ip}:8981/healthz", 3)


def activate(confirm):
    require(confirm == "hetero-dev-sudo-v2", "explicit_activation_confirmation_required")
    require_active()
    all_signers()
    original = require_plugin(False)
    replacement = original.rstrip(b"\n") + b"\n\n" + PLUGIN_LINE.encode() + b"\n"
    atomic_replace(SUDO_CONFIG, replacement, 0o644)
    try:
        require_plugin(True)
    except BaseException:
        atomic_replace(SUDO_CONFIG, original, 0o644)
        raise
    return {"guest": identity()[0], "plugin_active": True,
            "actual_privileged_e2e_still_required": True}


def rollback():
    raw = read(SUDO_CONFIG, 65536, mode=0o644)
    directives = plugin_directives(raw)
    if not directives:
        return {"guest": identity()[0], "plugin_active": False, "changed": False}
    require(directives == [PLUGIN_LINE], "unexpected_sudo_plugin_state")
    lines = raw.decode("utf-8").splitlines()
    lines.remove(PLUGIN_LINE)
    replacement = ("\n".join(lines).rstrip("\n") + "\n").encode()
    atomic_replace(SUDO_CONFIG, replacement, 0o644)
    require_plugin(False)
    return {"guest": identity()[0], "plugin_active": False, "changed": True}


def status():
    hostname, _, _, member, vpn_ip = identity()
    services = {}
    for name in (LOCAL_UNIT.name, SIGNER_UNIT.name):
        state = unit_state(name)
        services[name] = {key: state[key] for key in ("ActiveState", "SubState", "UnitFileState")}
    directives = plugin_directives(read(SUDO_CONFIG, 65536, mode=0o644))
    return {"guest": hostname, "member": member, "vpn_ip": vpn_ip,
            "release": os.readlink(RUNTIME / "current"), "services": services,
            "plugin_active": directives == [PLUGIN_LINE], "plugin_directives": len(directives)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("prepare", "check", "start", "activate", "rollback", "status"))
    parser.add_argument("--confirm-activation")
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    identity()
    if args.phase == "prepare":
        result = prepare()
    elif args.phase == "check":
        result = check_prepared(require_inactive=True)
    elif args.phase == "start":
        result = start()
    elif args.phase == "activate":
        result = activate(args.confirm_activation)
    elif args.phase == "rollback":
        result = rollback()
    else:
        result = status()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"ok": False, "error": type(error).__name__}, sort_keys=True),
              file=sys.stderr)
        sys.exit(1)
