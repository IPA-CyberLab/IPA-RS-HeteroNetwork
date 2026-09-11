"""Offline stdlib tests: all commands and mutations mocked, no fixture mkfs."""
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("app_storage", Path(__file__).with_name("prepare-storage.py"))
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)
FS_UUID = "5a82a0fe-0eae-47d3-b3ce-f9746cd44d02"
SERIAL = "hnapp-381d1ae16f55"
NAME = r"var-lib-heteronetwork\x2ddev\x2dapp\x2dstorage.mount"


def disk():
    return {"name": "/dev/vdc", "path": "/dev/vdc", "type": "disk", "size": s.SIZE,
            "ro": False, "serial": SERIAL, "maj:min": "252:32", "pkname": None,
            "mountpoints": [None], "fstype": None, "uuid": None, "pttype": None}


class DeviceTests(unittest.TestCase):
    def validate(self, d=None, **kwargs):
        return s.validate_device({"blockdevices": [d or disk()]}, SERIAL,
                                 kwargs.pop("mounted", []), kwargs.pop("swaps", []),
                                 kwargs.pop("holders", []), kwargs.pop("signatures", []), **kwargs)

    def test_serial_not_vdb_target(self):
        self.assertEqual(self.validate()["path"], "/dev/vdc")
        d = disk()
        d.update(path="/dev/vdb", serial="wrong")
        with self.assertRaises(ValueError):
            self.validate(d)

    def test_wrong_geometry_type_or_identity(self):
        for key, value in [("size", s.SIZE - 1), ("size", s.SIZE + 1), ("ro", True),
                           ("type", "part"), ("path", "/dev/sda"), ("maj:min", "../bad"),
                           ("pkname", "/dev/vda"), ("fstype", "ext4"),
                           ("uuid", FS_UUID), ("pttype", "gpt"),
                           ("mountpoints", ["/var/lib/heteronetwork-dev-storage"])]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                d = disk()
                d[key] = value
                self.validate(d)

    def test_duplicate_serial_and_partitions(self):
        with self.assertRaises(ValueError):
            s.validate_device({"blockdevices": [disk(), disk()]}, SERIAL, [], [], [], [])
        d = disk()
        d["children"] = [{"type": "part", "serial": None}]
        with self.assertRaises(ValueError):
            self.validate(d)

    def test_root_identity_mount_swap_holders_and_signatures(self):
        for target in ("/", "/var/lib/heteronetwork-dev-storage", str(s.MOUNT)):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.validate(mounted=[{"target": target, "maj:min": "252:32"}])
        for argument in ({"holders": ["dm-0"]}, {"swaps": ["/swapfile"]},
                         {"signatures": [{"type": "ext4"}]},
                         {"signatures": [{"type": "gpt"}]}):
            with self.subTest(argument=argument), self.assertRaises(ValueError):
                self.validate(**argument)

    def test_completed_only_ext4_at_own_mount(self):
        d = disk()
        d.update(fstype="ext4", uuid=FS_UUID, mountpoints=[str(s.MOUNT)])
        self.validate(d, fresh=False, signatures=[{"type": "ext4", "uuid": FS_UUID}])
        with self.assertRaises(ValueError):
            self.validate(d, fresh=False, signatures=[{"type": "ext4"}],
                          mounted=[{"target": "/", "maj:min": "252:32"}])
        with self.assertRaises(ValueError):
            self.validate(d, fresh=False, signatures=[{"type": "ext4"}, {"type": "gpt"}])

    def test_uuid_ambiguity_and_signature_mismatch(self):
        d = disk()
        d.update(fstype="ext4", uuid=FS_UUID)
        other = disk()
        other.update(serial="other", uuid=FS_UUID)
        with self.assertRaises(ValueError):
            s.validate_device({"blockdevices": [d, other]}, SERIAL, [], [], [],
                              [{"type": "ext4", "uuid": FS_UUID}], fresh=False)
        with self.assertRaises(ValueError):
            self.validate(d, fresh=False, signatures=[{"type": "ext4", "uuid": "wrong"}])

    def test_inspect_mocked_commands_and_udev_agreement(self):
        answers = {"lsblk": json.dumps({"blockdevices": [disk()]}),
                   "udevadm": f"ID_SERIAL={SERIAL}\nDEVTYPE=disk\n",
                   "swapon": '{"swapdevices": []}', "wipefs": '{"signatures": []}'}
        with patch.object(s, "run", side_effect=lambda *a: answers[a[0]]) as run, \
                patch.object(s, "mount_inventory", return_value=[]), \
                patch.object(Path, "stat", return_value=SimpleNamespace(
                    st_mode=stat.S_IFBLK, st_rdev=s.os.makedev(252, 32))), \
                patch.object(Path, "iterdir", return_value=iter([])):
            self.assertEqual(s.inspect(SERIAL), disk())
            self.assertFalse(any(c.args[0] == "mkfs.ext4" for c in run.call_args_list))
            answers["udevadm"] = "ID_SERIAL=other\nDEVTYPE=disk\n"
            with self.assertRaises(ValueError):
                s.inspect(SERIAL)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.who = {"host": "hetero-dev-1", "serial": SERIAL}
        self.record = {"identity": self.who, "fs_uuid": FS_UUID,
                       "size": s.SIZE, "purpose": str(s.MOUNT)}
        self.files = {}
        self.events = []
        self.formatted = False
        self.fail_at = None

        def write(path, content):
            self.assertNotIn(path, self.files)
            self.files[path] = content
            self.events.append(("write", path))

        def command(*args):
            self.events.append(args)
            if args[0] == self.fail_at:
                raise ValueError("simulated interruption")
            if args[0] == "mkfs.ext4":
                self.assertIn(s.STATE / "intent.json", self.files)
                self.formatted = True
            return ""

        def inspect(serial, fresh=True):
            self.assertEqual(serial, SERIAL)
            self.assertEqual(fresh, not self.formatted)
            d = disk()
            if self.formatted:
                d.update(fstype="ext4", uuid=FS_UUID)
            return d

        mocks = {
            "run": command, "write_new": write, "read_private": lambda p: self.files[p],
            "exists": lambda p: p in self.files, "inspect": inspect,
            "mount_inventory": lambda: [], "mkdir": lambda p: None,
            "root_path": lambda *a, **kw: None, "sync_dir": lambda p: None,
            "unit_files": lambda u: (NAME, "unit", "guard"),
            "verify_files": lambda *a: None,
            "verify_mount": lambda *a, **kw: self.events.append(("verify_mount",)),
            "verify_cluster": lambda: self.events.append(("verify_cluster",)),
        }
        for key, value in mocks.items():
            p = patch.object(s, key, side_effect=value)
            p.start()
            self.addCleanup(p.stop)
        for p in (patch.object(Path, "iterdir", side_effect=lambda: iter([])),
                  patch.object(s.uuid, "uuid4", return_value=s.uuid.UUID(FS_UUID)),
                  patch.object(s.os, "symlink"), patch.object(s.os, "chmod")):
            p.start()
            self.addCleanup(p.stop)

    def test_fresh_ordering_and_complete_noop(self):
        result = s.transaction(self.who)
        self.assertTrue(result["mount_only_ready"])
        self.assertFalse(result["app_provisioning_ready"])
        self.assertFalse(result["active_kubelet_dependency_validated"])
        self.assertTrue(result["kubernetes_cluster_uid_verified"])
        self.assertEqual(result["kubernetes_ready_nodes_verified"], sorted(s.MACHINES))
        self.assertFalse(result["consumer_enforcement_validated"])
        self.assertTrue(result["external_daemon_reload_may_activate_guard"])
        commands = [e for e in self.events if e[0] not in ("write", "verify_mount", "verify_cluster")]
        self.assertEqual(sum(e[0] == "mkfs.ext4" for e in commands), 1)
        self.assertFalse(any("kubelet" in " ".join(e) for e in commands))
        self.assertEqual([e for e in commands if e[0] == "systemctl" and e[1] != "show"],
                         [("systemctl", "daemon-reload"), ("systemctl", "start", NAME)])
        self.assertLess(self.events.index(("verify_mount",)),
                        self.events.index(("write", s.DROPIN)))
        self.assertLess(self.events.index(("verify_cluster",)),
                        self.events.index(("write", s.STATE / "intent.json")))
        self.events.clear()
        self.assertFalse(s.transaction(self.who)["created"])
        self.assertEqual(self.events, [("verify_cluster",), ("verify_mount",)])

    def test_cluster_failure_blocks_first_format_and_completed_readiness(self):
        s.verify_cluster.side_effect = ValueError("cluster mismatch")
        with self.assertRaises(ValueError):
            s.transaction(self.who)
        self.assertNotIn(s.STATE / "intent.json", self.files)
        self.assertFalse(any(e[0] == "mkfs.ext4" for e in self.events))
        s.verify_cluster.side_effect = lambda: None
        s.transaction(self.who)
        self.events.clear()
        s.verify_cluster.side_effect = ValueError("cluster no longer ready")
        with self.assertRaises(ValueError):
            s.transaction(self.who)
        self.assertEqual(self.events, [])

    def test_interrupted_mkfs_and_mount_never_retry(self):
        for failure in ("mkfs.ext4", "udevadm", "systemctl"):
            with self.subTest(failure=failure):
                self.files.clear()
                self.events.clear()
                self.formatted = False
                # systemctl show is pre-intent; simulate a mount-stage failure instead.
                self.fail_at = failure if failure != "systemctl" else None
                if failure == "systemctl":
                    s.verify_mount.side_effect = ValueError("mount failed")
                with self.assertRaises(ValueError):
                    s.transaction(self.who)
                self.assertIn(s.STATE / "intent.json", self.files)
                self.assertNotIn(s.STATE / "complete.json", self.files)
                self.events.clear()
                with self.assertRaises(ValueError):
                    s.transaction(self.who)
                self.assertEqual(self.events, [])

    def test_unknown_files_refused_before_intent(self):
        for path in (s.DROPIN, s.SYSTEMD / NAME, s.STATE / "complete.json",
                     Path("/run/systemd/system/kubelet.service.d") / s.DROPIN.name):
            with self.subTest(path=path):
                self.files.clear()
                self.files[path] = "operator-owned"
                with self.assertRaises(ValueError):
                    s.transaction(self.who)
                self.assertNotIn(s.STATE / "intent.json", self.files)
                self.assertEqual(self.files[path], "operator-owned")

    def test_completed_tampering_and_missing_mount_refused(self):
        s.transaction(self.who)
        self.events.clear()
        original = self.files[s.STATE / "complete.json"]
        self.files[s.STATE / "complete.json"] = "{}"
        with self.assertRaises(ValueError):
            s.transaction(self.who)
        self.files[s.STATE / "complete.json"] = original
        s.verify_mount.side_effect = ValueError("mount absent")
        with self.assertRaises(ValueError):
            s.transaction(self.who)
        self.assertFalse(any(e[0] == "mkfs.ext4" for e in self.events))


class ContractTests(unittest.TestCase):
    def test_cluster_queries_are_pinned_bounded_and_readonly(self):
        namespace = {"metadata": {"name": "kube-system", "uid": s.K8S_UID}}
        nodes = {"items": [{"metadata": {"name": name}, "status": {
            "conditions": [{"type": "Ready", "status": "True"}]}} for name in s.MACHINES]}
        with patch.object(s, "root_path") as root, patch.object(s, "run", side_effect=[
                json.dumps(namespace), json.dumps(nodes)]) as command:
            s.verify_cluster()
        root.assert_called_once_with(s.KUBECONFIG)
        prefix = ("kubectl", "--kubeconfig=/etc/kubernetes/admin.conf", "--request-timeout=10s")
        self.assertEqual([c.args for c in command.call_args_list], [
            (*prefix, "get", "namespace", "kube-system", "--output=json"),
            (*prefix, "get", "nodes", "--output=json")])

    def test_cluster_rejects_uid_node_set_and_readiness(self):
        valid = [{"metadata": {"name": name}, "status": {
            "conditions": [{"type": "Ready", "status": "True"}]}} for name in s.MACHINES]
        cases = [(s.CLUSTER, valid), (s.K8S_UID, valid[:2]),
                 (s.K8S_UID, valid + [valid[0]]), (s.K8S_UID, [valid[0]] * 3)]
        for condition in ([], [{"type": "Ready", "status": "False"}],
                          [{"type": "Ready", "status": "Unknown"}],
                          [{"type": "Ready", "status": "True"}] * 2):
            changed = json.loads(json.dumps(valid))
            changed[0]["status"]["conditions"] = condition
            cases.append((s.K8S_UID, changed))
        wrong_name = json.loads(json.dumps(valid))
        wrong_name[0]["metadata"]["name"] = "production-1"
        cases.append((s.K8S_UID, wrong_name))
        for uid, nodes in cases:
            with self.subTest(uid=uid, nodes=nodes), patch.object(s, "root_path"), \
                    patch.object(s, "run", side_effect=[json.dumps({"metadata": {
                        "name": "kube-system", "uid": uid}}), json.dumps({"items": nodes})]), \
                    self.assertRaises(ValueError):
                s.verify_cluster()
        with patch.object(s, "root_path"), patch.object(s, "run", side_effect=
                subprocess.TimeoutExpired("kubectl", 180)), self.assertRaises(subprocess.TimeoutExpired):
            s.verify_cluster()

    def test_identity_checks_and_no_secret_reads(self):
        host = "hetero-dev-1"
        machine = s.MACHINES[host]
        dmi = str(s.uuid.UUID(machine))
        config = {"cluster_id": s.CLUSTER, "guest": {
            "name": host, "machine_id": machine, "product_uuid": dmi}}
        with patch.object(s.os, "getuid", return_value=0), \
                patch.object(s.os, "geteuid", return_value=0), \
                patch.object(s.socket, "gethostname", return_value=host), \
                patch.object(Path, "read_text", side_effect=[machine, dmi]), \
                patch.object(s, "read_private", return_value=json.dumps(config)) as manifest:
            self.assertEqual(s.identity()["serial"], SERIAL)
            manifest.assert_called_once_with(Path("/opt/heteronetwork-dev-bootstrap/bootstrap.json"))
        for wrong_machine, wrong_dmi, wrong_cluster in (
                ("0" * 32, dmi, s.CLUSTER), (machine, "wrong", s.CLUSTER),
                (machine, dmi, s.K8S_UID)):
            config["cluster_id"] = wrong_cluster
            with patch.object(s.os, "getuid", return_value=0), \
                    patch.object(s.os, "geteuid", return_value=0), \
                    patch.object(s.socket, "gethostname", return_value=host), \
                    patch.object(Path, "read_text", side_effect=[wrong_machine, wrong_dmi]), \
                    patch.object(s, "read_private", return_value=json.dumps(config)), \
                    self.assertRaises(ValueError):
                s.identity()

    def test_mount_verification_rejects_wrong_device_uuid_root_and_options(self):
        d = disk()
        d["uuid"] = FS_UUID
        mount = {"target": str(s.MOUNT), "maj:min": d["maj:min"], "fstype": "ext4",
                 "fsroot": "/", "options": "rw,nodev,nosuid,relatime"}
        with patch.object(s, "root_path"), patch.object(Path, "stat", return_value=
                SimpleNamespace(st_dev=s.os.makedev(252, 32))):
            with patch.object(s, "mount_inventory", return_value=[mount]):
                s.verify_mount(d, FS_UUID)
                with self.assertRaises(ValueError):
                    s.verify_mount(d, "wrong")
            for key, value in (("maj:min", "252:0"), ("fsroot", "/subdir"),
                               ("fstype", "xfs"), ("options", "ro,nodev,nosuid")):
                wrong = {**mount, key: value}
                with self.subTest(key=key), patch.object(s, "mount_inventory", return_value=[wrong]), \
                        self.assertRaises(ValueError):
                    s.verify_mount(d, FS_UUID)
            with patch.object(s, "mount_inventory", return_value=[]), self.assertRaises(ValueError):
                s.verify_mount(d, FS_UUID)

    def test_unknown_unit_content_not_replaced(self):
        with patch.object(s, "read_private", return_value="unknown unit"), \
                patch.object(s, "write_new") as write, self.assertRaises(ValueError):
            s.verify_files(NAME, "expected unit", "expected guard")
        write.assert_not_called()

    def test_domain_mapping_and_distinct_cluster_ids(self):
        self.assertEqual(s.MACHINES, {
            "hetero-dev-1": "381d1ae16f555c59b738d8d01dd14c94",
            "hetero-dev-2": "acc5151b6b245b63864372933dab97da",
            "hetero-dev-3": "165a6e8acc3a56fdbf9bef8c90d6cf4d"})
        self.assertNotEqual(s.CLUSTER, s.K8S_UID)
        self.assertNotIn(Path("/var/lib/heteronetwork-dev-storage"), s.MOUNT.parents)

    def test_unit_exact_uuid_and_failclosed_dependencies(self):
        with patch.object(s, "run", side_effect=[NAME, "uuid.device"]):
            name, unit, guard = s.unit_files(FS_UUID)
        self.assertEqual(name, NAME)
        self.assertIn(f"What=/dev/disk/by-uuid/{FS_UUID}\n", unit)
        self.assertIn("BindsTo=uuid.device\nAfter=uuid.device\n", unit)
        self.assertIn("TimeoutSec=90", unit)
        self.assertIn(f"BindsTo={NAME}\nAfter={NAME}\n", guard)
        self.assertIn(f"AssertPathIsMountPoint={s.MOUNT}", guard)
        self.assertNotIn("Restart", guard)

    def test_symlink_and_nonprivate_path_rejected(self):
        for mode, uid, nlink in [(stat.S_IFLNK | 0o600, 0, 1),
                                  (stat.S_IFREG | 0o644, 0, 1),
                                  (stat.S_IFREG | 0o600, 1, 1),
                                  (stat.S_IFREG | 0o600, 0, 2)]:
            with self.subTest(mode=mode, uid=uid, nlink=nlink):
                parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                info = SimpleNamespace(st_mode=mode, st_uid=uid, st_nlink=nlink)
                with patch.object(Path, "lstat", side_effect=[parent, info]), self.assertRaises(ValueError):
                    s.root_path(Path("/test"))

    def test_command_failure_does_not_expose_output(self):
        with patch.object(subprocess, "run", return_value=SimpleNamespace(
                returncode=1, stdout=b"sensitive-output", stderr=b"sensitive-output")):
            with self.assertRaises(ValueError) as error:
                s.run("mock-command")
            self.assertNotIn("sensitive", str(error.exception))


if __name__ == "__main__":
    unittest.main()
