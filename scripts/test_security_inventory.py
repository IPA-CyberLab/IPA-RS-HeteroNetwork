import datetime
import json
from pathlib import Path
import tempfile
import unittest

from security_inventory import atomic_json, deployed_images, metrics, metrics_summary, normalize_trivy, scoped_registry_auth, validate_host_os
from security_update_gate import assess, fingerprint
from security_cargo_patch import fixes
from security_containerd_update import preserved


class InventoryTests(unittest.TestCase):
    def test_running_digest_is_used_and_finished_pods_are_removed(self):
        pod = {'metadata': {'namespace': 'platform'}, 'spec': {'containers': [{'name': 'app', 'image': 'image:latest'}]}, 'status': {'phase': 'Running', 'containerStatuses': [{'name': 'app', 'imageID': 'docker-pullable://image@sha256:' + 'a' * 64}]}}
        completed = {**pod, 'status': {'phase': 'Succeeded'}}
        result = deployed_images([pod, completed])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['reference'], 'image@sha256:' + 'a' * 64)
        self.assertTrue(result[0]['digest_verified'])

    def test_advisories_without_cve_are_retained(self):
        report = {'Results': [{'Type': 'cargo', 'Packages': [{'Name': 'rustls', 'Version': '0.23.43'}], 'Vulnerabilities': [{'VulnerabilityID': 'GHSA-2mjx-qc3c-rqvc', 'PkgName': 'rustls', 'InstalledVersion': '0.23.43', 'FixedVersion': '0.23.45', 'Severity': 'MEDIUM'}]}]}
        packages, findings = normalize_trivy(report, 'source')
        self.assertEqual(len(packages), 1)
        self.assertEqual(findings[0]['id'], 'GHSA-2mjx-qc3c-rqvc')
        self.assertEqual(findings[0]['fixed_version'], '0.23.45')
        self.assertEqual(findings[0]['cves'], [])

    def test_zero_packages_is_not_a_successful_host_scan(self):
        with self.assertRaises(RuntimeError):
            validate_host_os({'Metadata': {'OS': {'Family': 'none'}}}, [])
        with self.assertRaises(RuntimeError):
            validate_host_os({'Metadata': {'OS': {'Family': 'ubuntu'}}}, [])

    def test_digest_without_a_repository_uses_the_requested_repository(self):
        pod = {'metadata': {'namespace': 'platform'}, 'spec': {'containers': [{'name': 'app', 'image': 'registry.example:5443/team/app:v1'}]}, 'status': {'phase': 'Running', 'containerStatuses': [{'name': 'app', 'imageID': 'containerd://sha256:' + 'b' * 64}]}}
        self.assertEqual(deployed_images([pod])[0]['reference'], 'registry.example:5443/team/app@sha256:' + 'b' * 64)

    def test_credentials_are_never_sent_to_another_registry(self):
        auths = {'registry.example': {'auth': 'private'}, 'other.example': {'auth': 'other'}}
        self.assertEqual(scoped_registry_auth('registry.example', auths), {'registry.example': {'auth': 'private'}})
        self.assertEqual(scoped_registry_auth('unknown.example', auths), {})
        self.assertEqual(scoped_registry_auth('registry.example:5443', auths), {})

    def test_error_inventory_does_not_publish_success(self):
        value = metrics({'observed_at': '2026-10-14T00:00:00+00:00', 'status': 'incomplete', 'errors': [{'source': 'node1'}], 'packages': [], 'findings': []}, now=datetime.datetime(2026, 10, 14, tzinfo=datetime.timezone.utc).timestamp())
        self.assertIn('heterocloud_security_scan_complete 0\n', value)
        self.assertIn('heterocloud_security_scan_errors 1\n', value)

    def test_metrics_do_not_need_to_reload_all_package_records(self):
        report = {'observed_at': '2026-10-14T00:00:00+00:00', 'status': 'incomplete', 'errors': [{}], 'packages': [{}] * 1000, 'findings': [{'severity': 'HIGH', 'fixed_version': '2'}] * 10000}
        compact = metrics_summary(report)
        self.assertNotIn('packages', compact)
        self.assertNotIn('findings', compact)
        self.assertEqual(metrics(compact, now=0), metrics(report, now=0))

    def test_snapshots_are_private_and_atomic(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'inventory.json'
            atomic_json(p, {'status': 'complete'})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(p.read_text())['status'], 'complete')
            self.assertEqual(len(list(Path(d).iterdir())), 1)


class UpdateGateTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((Path(__file__).resolve().parents[1] / 'deploy/security/policy.json').read_text())
        self.now = datetime.datetime(2026, 10, 14, tzinfo=datetime.timezone.utc)
        self.plan = {'severity': 'HIGH', 'cves': ['CVE-2026-12345'], 'fixed_version': '20261005.0', 'source_sha256': 'a' * 64, 'running_workloads': ['test'], 'from_runtime': 'old', 'to_runtime': 'new', 'inventory_complete': True, 'fleet_healthy': True, 'generation': 5}
        self.proof = {'verified_at': self.now.isoformat(), 'plan_sha256': fingerprint(self.plan), 'generation': 5, 'ci_passed': True, 'candidate_rescan_passed': True, 'service_health_passed': True, 'rollback_verified': True, 'state_preserved': True, 'network_connections_preserved': True, 'target_runtime_verified': True, 'source_fenced': True, 'capacity_reserved': True, 'strategy': 'gvisor_checkpoint_restore', 'cross_version_restore_passed': True}

    def test_exact_verified_migration_passes(self):
        self.assertTrue(assess(self.plan, self.proof, self.policy, self.now)['allowed'])

    def test_cross_version_is_never_assumed(self):
        self.proof.pop('cross_version_restore_passed')
        self.assertIn('cross_version_restore_unverified', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_replaced_binary_is_not_active_runtime_remediation(self):
        self.proof['target_runtime_verified'] = False
        self.assertFalse(assess(self.plan, self.proof, self.policy, self.now)['allowed'])

    def test_dropped_connections_block_live_update(self):
        self.proof['network_connections_preserved'] = False
        self.assertFalse(assess(self.plan, self.proof, self.policy, self.now)['allowed'])

    def test_old_proof_is_rejected(self):
        self.proof['verified_at'] = (self.now - datetime.timedelta(days=2)).isoformat()
        self.assertIn('stale_proof', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_uninventoried_fleet_is_rejected(self):
        self.plan['inventory_complete'] = False
        self.proof['plan_sha256'] = fingerprint(self.plan)
        self.assertIn('inventory_incomplete', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_gpu_is_not_covered_by_cpu_probe(self):
        self.plan['gpu'] = True
        self.proof['plan_sha256'] = fingerprint(self.plan)
        self.assertIn('gpu_state_preservation_required', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_new_generation_cannot_reuse_old_evidence(self):
        self.plan['generation'] = 6
        self.proof['plan_sha256'] = fingerprint(self.plan)
        self.assertIn('workload_generation_changed', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_silent_restart_fallback_is_rejected(self):
        self.proof['restart_fallback'] = True
        self.assertIn('restart_fallback_forbidden', assess(self.plan, self.proof, self.policy, self.now)['reasons'])


class CargoFixTests(unittest.TestCase):
    def test_pick_the_compatible_fix_for_zero_major_versions(self):
        report = {'Results': [{'Type': 'cargo', 'Vulnerabilities': [{'VulnerabilityID': 'GHSA-test', 'PkgName': 'rustls', 'InstalledVersion': '0.23.43', 'FixedVersion': '0.24.1, 0.23.45'}]}]}
        self.assertEqual(fixes(report)[0]['fixed_version'], '0.23.45')

    def test_no_fix_does_not_invent_an_upgrade(self):
        report = {'Results': [{'Type': 'cargo', 'Vulnerabilities': [{'VulnerabilityID': 'GHSA-test', 'PkgName': 'rustls', 'InstalledVersion': '0.23.43', 'FixedVersion': ''}]}]}
        self.assertEqual(fixes(report), [])


class RunningTaskPreservationTests(unittest.TestCase):
    def test_an_added_task_does_not_invalidate_existing_continuity(self):
        self.assertTrue(preserved({'workspace': 123}, {'workspace': 123, 'new-task': 456}))

    def test_same_container_id_with_restarted_pid_is_rejected(self):
        self.assertFalse(preserved({'workspace': 123}, {'workspace': 456}))

    def test_missing_running_task_is_rejected(self):
        self.assertFalse(preserved({'workspace': 123}, {}))


if __name__ == '__main__':
    unittest.main()
