import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import heteronet_admin as admin


class AdminCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.work = root / "work"
        self.work.mkdir()
        (self.work / "known_hosts").write_text("fixture\n")
        kubeconfig = root / "kubeconfig"; kubeconfig.write_text("fixture\n")
        key = root / "key"; key.write_text("fixture\n")
        state = root / "state"; state.mkdir()
        self.identity = {"hostname": "lost", "node_id": "node-" + "f" * 32,
                         "vpn_ip": "10.250.0.250", "cluster_id": "fixture",
                         "postgres_name": "db-z", "tailscale_ip": "100.64.0.250"}
        (state / "identity.json").write_text(json.dumps(self.identity))
        self.args = SimpleNamespace(hostname="lost", work_dir=self.work, kubeconfig=kubeconfig,
                                    ssh_key=key, ssh_user="operator", kubectl="kubectl",
                                    terraform="terraform", state_dir=state, dry_run=True, no_push=False)
        self.checked = {"node_uid": None, "node_present": False, "longhorn": [], "pods": []}

    def test_exact_address_matching_does_not_match_a_prefix(self):
        self.assertFalse(admin.contains_address({"x": ["10.250.0.10"]}, "10.250.0.1"))
        self.assertTrue(admin.contains_address({"10.250.0.1": ["10.250.0.2"]}, "10.250.0.1"))

    def test_local_api_tunnel_is_started_and_cleaned_up_when_missing(self):
        self.args.kubeconfig.write_text('''current-context: test
contexts:
  - name: test
    context: {cluster: local}
clusters:
  - name: local
    cluster: {server: "https://127.0.0.1:17443"}
''')
        class Process:
            stderr = None
            def __init__(self): self.stopped = False
            def poll(self): return None
            def terminate(self): self.stopped = True
            def wait(self, timeout=None): return 0
        process = Process()
        with patch.object(admin, "port_open", side_effect=[False, False, True, True]), \
             patch.object(admin.time, "sleep"), \
             patch.object(admin.subprocess, "Popen", return_value=process) as start:
            with admin.kube_tunnel(self.args):
                self.assertFalse(process.stopped)
            self.assertTrue(process.stopped)
        self.assertIn("127.0.0.1:17443:127.0.0.1:6443", start.call_args.args[0])

    def test_dry_run_is_read_only(self):
        remote = SimpleNamespace(database_absent=lambda identity: {"result": "absent"},
                                 registration=lambda identity, apply: {"result": "already_absent"})
        with patch.dict(os.environ, {"HNN_IAC_BECOME_PASSWORD": "fixture"}), \
             patch.object(admin, "Remote", return_value=remote), \
             patch.object(admin, "Kube"), \
             patch.object(admin, "kubernetes_preflight", return_value=self.checked), \
             patch.object(admin, "reconcile_dns", return_value={"changed": False}), \
             patch.object(admin, "require_no_static_references"), \
             patch.object(admin, "gitops") as gitops, \
             patch.object(admin, "delete_kubernetes_objects") as delete, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(admin.retire(self.args), 0)
        self.assertEqual(json.loads(output.getvalue())["result"], "preflight_passed")
        gitops.assert_not_called(); delete.assert_not_called()

    def test_dependency_failure_precedes_network_deletion(self):
        class Remote:
            def database_absent(self, identity):
                raise ValueError("database member still present")
            def registration(self, identity, apply):
                raise AssertionError("network registration must not be touched")
        with patch.dict(os.environ, {"HNN_IAC_BECOME_PASSWORD": "fixture"}), \
             patch.object(admin, "Remote", return_value=Remote()), \
             patch.object(admin, "Kube"), \
             patch.object(admin, "kubernetes_preflight", return_value=self.checked), \
             patch.object(admin, "delete_kubernetes_objects") as delete:
            with self.assertRaisesRegex(ValueError, "database member"):
                admin.retire(self.args)
        delete.assert_not_called()

    def test_remote_sudo_password_is_sent_via_stdin_only(self):
        remote = admin.Remote("192.0.2.1", "operator", self.args.ssh_key,
                              self.work / "known_hosts", "secret-fixture")
        with patch.object(admin, "run", return_value='{"result":"ok"}') as execute:
            self.assertEqual(remote.python("print('{}')", ["fixture"])["result"], "ok")
        self.assertNotIn("secret-fixture", str(execute.call_args.args[0]))
        self.assertEqual(execute.call_args.kwargs["input"], "secret-fixture\n")

    def test_application_work_is_retained_after_interruption(self):
        path = Path("deploy/gitops/applications/heterocloud-syouyu.yaml")
        self.assertEqual(admin.pending_applications(self.args.state_dir, {path: "new values"}), {path})
        self.assertEqual(admin.pending_applications(self.args.state_dir, {}), {path})
        self.assertEqual((self.args.state_dir / "pending-applications.json").stat().st_mode & 0o777, 0o600)

    def test_invalid_saved_application_cannot_select_arbitrary_resource(self):
        (self.args.state_dir / "pending-applications.json").write_text('["other"]')
        with self.assertRaisesRegex(ValueError, "invalid"):
            admin.pending_applications(self.args.state_dir, {})

    def test_fencing_checks_uid_and_version_for_both_resources(self):
        class Kube:
            def __init__(self): self.patches = []
            def patch(self, *args): self.patches.append(args)
        kube = Kube()
        checked = {"node_object": {"metadata": {"name": "lost", "uid": "n-uid", "resourceVersion": "42"}},
                   "longhorn": [{"metadata": {"name": "lost", "uid": "l-uid", "resourceVersion": "43"}}]}
        admin.fence_offline_node(kube, checked)
        self.assertEqual(len(kube.patches), 2)
        for (_, _, _, operations), uid, version in zip(kube.patches, ("n-uid", "l-uid"), ("42", "43")):
            self.assertEqual(operations[0], {"op": "test", "path": "/metadata/uid", "value": uid})
            self.assertEqual(operations[1], {"op": "test", "path": "/metadata/resourceVersion", "value": version})

    def test_snapshot_is_private_verified_and_remote_copy_is_removed(self):
        class Kube:
            def get(self, *args):
                return {"spec": {"nodeName": "executor", "containers": [{"volumeMounts": [
                    {"name": "data", "mountPath": "/var/lib/etcd"}]}], "volumes": [
                    {"name": "data", "hostPath": {"path": "/var/lib/etcd"}}]}}
        class Remote:
            def __init__(self): self.removed = []
            def stream_snapshot(self, path, output): output.write(b"x" * (1024 * 1024))
            def remove_snapshot(self, path): self.removed.append(path)
        remote = Remote()
        def command(cmd, **kwargs):
            return '{"totalSize":1048576}' if "etcdutl" in cmd else ""
        with patch.object(admin, "run", side_effect=command):
            result = admin.snapshot_etcd(Kube(), self.args, "executor", self.work / "snapshots", remote)
        saved = self.work / "snapshots" / result["snapshot_file"]
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["snapshot_sha256"], hashlib.sha256(saved.read_bytes()).hexdigest())
        self.assertEqual(len(remote.removed), 1)
        self.assertTrue(remote.removed[0].startswith("/var/lib/etcd/heteronetwork-retirement-"))

    def test_snapshot_never_uses_an_unexpected_host_mount(self):
        class Kube:
            def get(self, *args):
                return {"spec": {"nodeName": "executor", "containers": [{"volumeMounts": []}], "volumes": []}}
        with patch.object(admin, "run") as execute:
            with self.assertRaisesRegex(ValueError, "host mount"):
                admin.snapshot_etcd(Kube(), self.args, "executor", self.work / "snapshots", object())
        execute.assert_not_called()

    def test_firewall_and_boot_roster_are_reconciled_before_address_is_released(self):
        events = []
        self.args.dry_run = False
        class Remote:
            def database_absent(self, identity):
                return {"result": "absent"}
            def registration(self, identity, apply):
                if apply:
                    events.append("release-address")
                return {"result": "already_absent"}
        class Kube:
            def get(self, *args):
                return {"data": {"records.json": '{"records":{}}'}}
        def reconcile(*args):
            events.append("distribute-roster-and-clear-firewall")
            return "revision"
        with patch.dict(os.environ, {"HNN_IAC_BECOME_PASSWORD": "fixture"}), \
             patch.object(admin, "Remote", return_value=Remote()), \
             patch.object(admin, "Kube", return_value=Kube()), \
             patch.object(admin, "kubernetes_preflight", return_value=self.checked), \
             patch.object(admin, "reconcile_dns", return_value={"changed": False}), \
             patch.object(admin, "require_no_static_references"), \
             patch.object(admin, "gitops", side_effect=reconcile), \
             patch.object(admin, "run", side_effect=lambda cmd, **kw: "master\n" if cmd[1:3] == ["symbolic-ref", "--quiet"] else ""), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(admin.retire(self.args), 0)
        self.assertEqual(events, ["distribute-roster-and-clear-firewall", "release-address"])


class RetirementCommitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.work = Path(self.temp.name) / "work"
        self.work.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "master", str(self.root)], check=True)
        for key, value in (("user.name", "Test"), ("user.email", "test@example.invalid")):
            subprocess.run(["git", "-C", str(self.root), "config", key, value], check=True)
        (self.root / "setting.yaml").write_text("before\n")
        subprocess.run(["git", "-C", str(self.root), "add", "setting.yaml"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "initial"], check=True)
        self.args = SimpleNamespace(hostname="lost", work_dir=self.work)

    def status(self):
        return subprocess.check_output(["git", "-C", str(self.root), "status", "--porcelain"], text=True)

    def test_commit_updates_the_clean_checkout_through_a_temporary_worktree(self):
        with patch.object(admin, "ROOT", self.root), contextlib.redirect_stdout(io.StringIO()):
            admin.commit_retirement(self.args, None, {Path("setting.yaml"): "after\n"})
        self.assertEqual((self.root / "setting.yaml").read_text(), "after\n")
        self.assertEqual(self.status(), "")
        self.assertEqual(list((self.work / "retirement-worktrees").iterdir()), [])

    def test_commit_failure_does_not_leave_partial_changes_in_checkout(self):
        real_run = admin.run
        def fail_commit(command, **kwargs):
            if "commit" in command:
                raise ValueError("fixture commit failure")
            return real_run(command, **kwargs)
        with patch.object(admin, "ROOT", self.root), patch.object(admin, "run", side_effect=fail_commit):
            with self.assertRaisesRegex(ValueError, "fixture commit failure"):
                admin.commit_retirement(self.args, None, {Path("setting.yaml"): "after\n"})
        self.assertEqual((self.root / "setting.yaml").read_text(), "before\n")
        self.assertEqual(self.status(), "")


if __name__ == "__main__":
    unittest.main()
