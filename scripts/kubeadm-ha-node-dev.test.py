"""Non-privileged profile tests; no host preparation or network calls."""
import os
import json
from pathlib import Path
import subprocess
import shlex
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("kubeadm-ha-node.sh")


class DevProfileTests(unittest.TestCase):
    def flannel_fixture(self):
        return {"kind": "List", "items": [
            {"kind": "ConfigMap", "metadata": {"name": "kube-flannel-cfg", "namespace": "kube-flannel"},
             "data": {"net-conf.json": json.dumps({"Network": "10.244.0.0/16",
                       "Backend": {"Type": "vxlan"}, "EnableNFTables": False}), "other": "preserved"}},
            {"kind": "DaemonSet", "metadata": {"name": "kube-flannel-ds"},
             "spec": {"args": ["--iface=heteronetwork0"], "mtu": 1370}}]}

    def test_flannel_network_structured_transform_preserves_other_fields(self):
        fixture = self.flannel_fixture()
        result = self.run_shell("printf '%s' " + shlex.quote(json.dumps(fixture)) + " | render_flannel_network")
        actual = json.loads(result.stdout)
        expected_network = json.loads(fixture["items"][0]["data"]["net-conf.json"])
        expected_network["Network"] = "172.29.0.0/16"
        self.assertEqual(json.loads(actual["items"][0]["data"]["net-conf.json"]), expected_network)
        actual["items"][0]["data"]["net-conf.json"] = fixture["items"][0]["data"]["net-conf.json"]
        self.assertEqual(actual, fixture)

    def test_flannel_network_rejects_missing_duplicate_and_bad_json(self):
        for mode in ("missing", "duplicate", "bad-json", "wrong-shape", "bad-cidr"):
            fixture = self.flannel_fixture()
            if mode == "missing":
                fixture["items"].pop(0)
            elif mode == "duplicate":
                fixture["items"].append(fixture["items"][0])
            elif mode == "bad-json":
                fixture["items"][0]["data"]["net-conf.json"] = "invalid"
            elif mode == "wrong-shape":
                fixture["items"][0]["data"]["net-conf.json"] = "[]"
            prefix = "pod_cidr=invalid; " if mode == "bad-cidr" else ""
            with self.subTest(mode=mode):
                self.run_shell(prefix + "printf '%s' " + shlex.quote(json.dumps(fixture))
                               + " | render_flannel_network", False)

    def test_kubeadm_init_never_echoes_credentials_success_or_failure(self):
        for failure in ("none", "validate", "init"):
            with tempfile.TemporaryDirectory() as directory:
                result = self.run_shell("export TMPDIR=" + shlex.quote(directory) + '''
kubeadm() {
  printf 'fixture-join-token-stdout\n'
  printf 'fixture-certificate-key-stderr\n' >&2
  [[ "$1" != ''' + shlex.quote("config" if failure == "validate" else failure) + ''' ]]
}
run_private_kubeadm_init /unused/test-config
''', failure == "none")
                self.assertNotIn("fixture-", result.stdout + result.stderr)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def run_shell(self, code, success=True):
        setup = '''
source "$1" help >/dev/null
hostname() { printf 'hetero-dev-1\n'; }
profile=fresh-dev
node_name=hetero-dev-1
node_ip=10.251.0.2
control_plane_backends=10.251.0.2,10.251.0.3,10.251.0.4
api_name=k8s-api.hetero-dev.internal
pod_cidr=172.29.0.0/16
service_cidr=172.30.0.0/16
'''
        result = subprocess.run(
            ["bash", "-c", setup + code, "test", str(SCRIPT)],
            env={"PATH": os.environ["PATH"], "LC_ALL": "C"},
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def test_explicit_dev_configuration(self):
        self.run_shell("validate_common_config")

    def test_reject_defaults_foreign_network_and_identity(self):
        for change in ["api_name=$DEFAULT_API_NAME", "pod_cidr=$DEFAULT_POD_CIDR",
                       "service_cidr=$DEFAULT_SERVICE_CIDR", "node_ip=10.250.0.5",
                       "control_plane_backends=10.250.0.5", "node_name=hetero-dev-2",
                       "agent_status_url=http://10.250.0.5:9780/v1/status",
                       "apiserver_etcd_backends=10.250.0.5", "profile=typo",
                       "node_ip=10.251.0.0", "node_ip=10.251.0.255"]:
            with self.subTest(change=change):
                self.run_shell(change + "; validate_common_config", False)

    def test_disabled_components_do_not_mutate(self):
        self.run_shell('''
require_root() { exit 91; }
systemctl() { exit 92; }
install() { exit 93; }
configure_overlay_dns
install_api_backend_autopilot
install_public_services_bootstrap_autopilot
''')

    def test_preflight_before_any_host_mutation(self):
        result = self.run_shell('''
require_root() { :; }
verify_interface_address() { :; }
require_command() { :; }
prepare_preflight() { die preflight-sentinel; }
install() { echo unexpected-mutation; exit 94; }
install_kubernetes_packages() { echo unexpected-packages; exit 95; }
prepare_host
''', False)
        self.assertIn("preflight-sentinel", result.stderr)
        self.assertNotIn("unexpected", result.stdout)

    def test_standard_preflight_requires_sibling_files(self):
        # The repository checkout supplies the exact dependencies.
        self.run_shell("profile=standard; prepare_preflight")
        for relative in ["scripts/public-services-bootstrap.sh",
                         "deploy/systemd/heteronetwork-public-services-bootstrap.service",
                         "deploy/systemd/heteronetwork-public-services-bootstrap.timer"]:
            self.assertTrue((SCRIPT.parent.parent / relative).is_file())

    def test_dev_prepare_runs_host_configuration_without_timers_or_dns(self):
        result = self.run_shell('''
require_root() { :; }
require_command() { :; }
verify_interface_address() { :; }
prepare_preflight() { echo checked; }
install() { :; }
systemctl() { exit 96; }
for function in install_kubernetes_packages configure_kernel configure_pod_cidr_routing \
  configure_containerd configure_hosts_entry configure_haproxy configure_kubelet \
  configure_local_state ensure_agent_api_token verify_host; do
  eval "$function() { echo $function; }"
done
prepare_host
''')
        self.assertEqual(result.stdout.splitlines(), [
            "checked", "install_kubernetes_packages", "configure_kernel",
            "configure_pod_cidr_routing", "configure_containerd", "configure_hosts_entry",
            "configure_haproxy", "configure_kubelet", "configure_local_state",
            "ensure_agent_api_token", "verify_host"])

    def test_direct_disabled_component_still_validates_profile(self):
        for function in ["configure_overlay_dns", "install_api_backend_autopilot",
                         "install_public_services_bootstrap_autopilot"]:
            with self.subTest(function=function):
                self.run_shell("node_ip=10.250.0.5; " + function, False)

    def test_profile_persisted_for_subsequent_commands(self):
        result = self.run_shell('''
install_from_stdin() { cat; }
configure_local_state
''')
        self.assertIn("HETERONETWORK_KUBEADM_PROFILE=fresh-dev", result.stdout)
        self.assertIn("HETERONETWORK_KUBEADM_API_NAME=k8s-api.hetero-dev.internal", result.stdout)

    def test_profile_roundtrip_in_fresh_process(self):
        rendered = self.run_shell("install_from_stdin() { cat; }; configure_local_state").stdout
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "node.env").write_text(rendered)
            self.run_shell("state_dir=" + shlex.quote(directory) + '''
profile=standard
secure_root_state_file() { :; }
validate_common_config() {
  [[ "$profile" == fresh-dev && "$node_ip" == 10.251.0.2 \
     && "$api_name" == k8s-api.hetero-dev.internal ]]
}
load_local_node_state
[[ "$profile" == fresh-dev ]]
''')

    def test_legacy_state_does_not_inherit_profile(self):
        rendered = self.run_shell("install_from_stdin() { cat; }; configure_local_state").stdout
        rendered = "\n".join(line for line in rendered.splitlines()
                             if not line.startswith("HETERONETWORK_KUBEADM_PROFILE="))
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "node.env").write_text(rendered + "\n")
            self.run_shell("state_dir=" + shlex.quote(directory) + '''
HETERONETWORK_KUBEADM_PROFILE=fresh-dev
secure_root_state_file() { :; }
validate_common_config() { [[ "$profile" == standard ]]; }
load_local_node_state
[[ "$profile" == standard ]]
''')

    def test_discovery_rejects_persisted_dev_profile_before_side_effects(self):
        result = self.run_shell('''
profile=standard
require_root() { :; }
load_local_node_state() { profile=fresh-dev; }
require_command() { echo unexpected-command; exit 91; }
discover_control_plane_addresses() { echo unexpected-discovery; exit 92; }
reconcile_container_runtime() { echo unexpected-mutation; exit 93; }
reconcile_discovered_control_plane_backends
''', False)
        self.assertIn("backend discovery is disabled for fresh-dev", result.stderr)
        self.assertNotIn("unexpected", result.stdout)


if __name__ == "__main__":
    unittest.main()
