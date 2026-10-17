import datetime
import json
from pathlib import Path
import tempfile
import unittest
import socket
import os

from security_inventory import atomic_json, deployed_images, metrics, metrics_summary, normalize_trivy, safe_trivy_report, scoped_registry_auth, validate_host_os
from security_update_gate import assess, fingerprint
from security_cargo_patch import fixes
from security_containerd_update import preserved
from security_candidate import candidate
from security_gvisor_e2e import continuity
from security_promote import canonical_image, deployment_ready, image_repository, newest_candidate, tenant_identity, validate_identity, verified_fixes
from security_runtime_snapshot import tcp_connections
from security_host_inventory import go_module_records
from security_candidate_needed import new_os_fixes
from security_candidate_baseline import select_release
from security_runtime_restart_host import validate_request
from security_runtime_restart import eligible as restart_eligible, memory_bytes, pod_memory_limit


class InventoryTests(unittest.TestCase):
    def test_image_source_revision_is_retained_without_other_labels(self):
        report = {'Metadata': {'ImageConfig': {'config': {'Labels': {'org.opencontainers.image.revision': 'a' * 40, 'secret-label': 'must-not-persist'}, 'Env': ['PRIVATE=value']}}}}
        safe = safe_trivy_report(report)
        self.assertEqual(safe['Metadata'], {'SourceRevision': 'a' * 40})
        self.assertNotIn('PRIVATE', str(safe))

    def test_incomplete_latest_release_is_not_a_deployment_baseline(self):
        complete = {'tag_name': 'v1', 'assets': [{'name': 'service-release-artifact.json'}]}
        self.assertEqual(select_release([{'tag_name': 'v2', 'assets': []}, complete]), complete)

    def test_go_replacement_does_not_report_unlinked_requested_version(self):
        modules = 'dep\texample.com/old\tv1.0.0\th1:old\n=>\texample.com/fixed\tv1.2.0\th1:new\n\nbuild\tsecret-setting=not-exported\n'
        records = go_module_records(modules, 'runtime')
        self.assertEqual([(p['name'], p['version']) for p in records], [('example.com/fixed', '1.2.0')])
        self.assertNotIn('secret-setting', str(records))

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

    def test_image_environment_and_build_history_are_not_saved(self):
        report = {'Results': [], 'Metadata': {'OS': {'Family': 'ubuntu'}, 'ImageConfig': {'config': {'Env': ['TEST_SECRET=must-not-be-saved']}, 'history': ['private-build-argument']}}}
        safe = safe_trivy_report(report)
        self.assertEqual(safe['Metadata'], {'OS': {'Family': 'ubuntu'}})
        self.assertNotIn('must-not-be-saved', str(safe))

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
        self.policy['require_live_migration'] = True
        self.policy['allow_restart_fallback'] = False
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

    def restart_proof(self):
        self.policy['require_live_migration'] = False
        self.policy['allow_restart_fallback'] = True
        self.proof.update(strategy='bounded_restart', restart_fallback=True,
                          persistent_volumes_retained=True, persistent_data_canary_passed=True,
                          resource_limits_verified=True, same_pod_uid=True,
                          restart_budget_respected=True, recovery_seconds=12.5)
        for field in ('state_preserved', 'network_connections_preserved', 'cross_version_restore_passed'):
            self.proof.pop(field)

    def test_authorized_bounded_restart_does_not_claim_memory_or_socket_continuity(self):
        self.restart_proof()
        self.assertTrue(assess(self.plan, self.proof, self.policy, self.now)['allowed'])

    def test_restart_preserves_persistent_volumes(self):
        self.restart_proof()
        self.proof['persistent_volumes_retained'] = False
        self.assertIn('persistent_volumes_retained_required', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_restart_timeout_is_enforced(self):
        self.restart_proof()
        self.proof['recovery_seconds'] = 181
        self.assertIn('restart_recovery_deadline_exceeded', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_restart_is_not_enabled_merely_by_relaxing_live_migration(self):
        self.restart_proof()
        self.policy['allow_restart_fallback'] = False
        self.assertIn('restart_fallback_forbidden', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_restart_cannot_bypass_target_runtime_acceptance(self):
        self.restart_proof()
        self.proof['target_runtime_verified'] = False
        self.assertIn('target_runtime_verified_required', assess(self.plan, self.proof, self.policy, self.now)['reasons'])

    def test_unknown_strategy_is_not_allowed_after_relaxing_live_migration(self):
        self.restart_proof()
        self.proof['strategy'] = 'just_replace_binary'
        self.assertIn('verified_strategy_required', assess(self.plan, self.proof, self.policy, self.now)['reasons'])


class RestartSafetyTests(unittest.TestCase):
    def setUp(self):
        self.artifact = {'sha256': 'b' * 64, 'sentry_sha256': 'c' * 64}
        self.pod = {'id': 'a' * 64, 'metadata': {'uid': 'uid', 'namespace': 'tenants'}, 'exe_sha256': 'd' * 64}
        self.request = {'artifact_sha256': 'b' * 64, 'sandbox_id': 'a' * 64, 'pod_uid': 'uid', 'source_sha256': 'd' * 64}
        self.policy = {'namespace': 'tenants', 'probe_namespace': 'canaries'}

    def test_exact_sandbox_and_artifact_are_required(self):
        self.assertEqual(validate_request(self.request, self.artifact, [self.pod], self.policy), self.pod)
        self.request['pod_uid'] = 'replacement'
        with self.assertRaisesRegex(RuntimeError, 'Pod UID changed'):
            validate_request(self.request, self.artifact, [self.pod], self.policy)

    def test_source_runtime_cannot_change_between_observation_and_stop(self):
        self.request['source_sha256'] = 'e' * 64
        with self.assertRaisesRegex(RuntimeError, 'source runtime changed'):
            validate_request(self.request, self.artifact, [self.pod], self.policy)

    def test_already_active_users_are_not_restarted(self):
        self.pod['exe_sha256'] = self.request['source_sha256'] = 'c' * 64
        with self.assertRaisesRegex(RuntimeError, 'already active'):
            validate_request(self.request, self.artifact, [self.pod], self.policy)

    def test_probe_flag_cannot_force_restart_of_a_tenant(self):
        self.request['probe'] = True
        with self.assertRaisesRegex(RuntimeError, 'only a canary'):
            validate_request(self.request, self.artifact, [self.pod], self.policy)

    def test_probe_can_verify_an_already_current_runtime(self):
        self.request['probe'] = True
        self.pod['metadata']['namespace'] = 'canaries'
        self.pod['exe_sha256'] = self.request['source_sha256'] = 'c' * 64
        self.assertEqual(validate_request(self.request, self.artifact, [self.pod], self.policy), self.pod)

    def test_resource_limit_accounts_for_sidecars_init_and_overhead(self):
        pod = {'spec': {'containers': [{'resources': {'limits': {'memory': '64Mi'}}}, {'resources': {'limits': {'memory': '16Mi'}}}],
                        'initContainers': [{'resources': {'limits': {'memory': '96Mi'}}}], 'overhead': {'memory': '8Mi'}}}
        self.assertEqual(pod_memory_limit(pod), 104 * 1024 * 1024)
        self.assertEqual(memory_bytes('0.5Gi'), 512 * 1024 * 1024)
        pod['spec']['containers'][0]['resources']['limits'] = {}
        with self.assertRaisesRegex(RuntimeError, 'needs a memory limit'):
            pod_memory_limit(pod)

    def test_master_only_nodes_are_never_runtime_restart_targets(self):
        node = {'metadata': {'labels': {'flash.heterocloud.io/gvisor-ready': 'true'}},
                'spec': {}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        self.assertTrue(restart_eligible(node))
        node['metadata']['labels']['heteronetwork.io/control-plane-only'] = 'true'
        self.assertFalse(restart_eligible(node))
        node['metadata']['labels'].pop('heteronetwork.io/control-plane-only')
        node['metadata']['labels']['node-role.kubernetes.io/control-plane'] = ''
        self.assertTrue(restart_eligible(node))  # Shared control planes host Flash by explicit fleet policy.
        node['spec']['taints'] = [{'key': 'node-role.kubernetes.io/control-plane', 'effect': 'NoSchedule'}]
        self.assertFalse(restart_eligible(node))


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


class CandidateTests(unittest.TestCase):
    def test_release_feed_order_cannot_select_a_superseded_candidate(self):
        old, new = 'a' * 40, 'b' * 40
        tags = ['security-' + old + '-100', 'security-' + new + '-102', 'security-' + new + '-101']
        self.assertEqual(newest_candidate(tags, new), 'security-' + new + '-102')
        self.assertIsNone(newest_candidate(tags, 'c' * 40))

    def test_new_os_fixes_rebuild_unchanged_source_without_looping(self):
        finding = {'id': 'CVE-new', 'package': 'libc6', 'installed_version': '1', 'fixed_version': '2', 'ecosystem': 'debian'}
        self.assertTrue(new_os_fixes([], [finding]))
        self.assertFalse(new_os_fixes([finding], [finding]))
        self.assertFalse(new_os_fixes([], [{**finding, 'fixed_version': ''}]))
        self.assertFalse(new_os_fixes([], [{**finding, 'ecosystem': 'cargo'}]))

    def test_related_repositories_are_separate(self):
        self.assertEqual(image_repository('registry.example:5443/team/app:v1@sha256:abc'), 'registry.example:5443/team/app')
        self.assertNotEqual(image_repository('ghcr.io/org/flow-livekit:1'), image_repository('ghcr.io/org/flow:1'))

    def test_old_rollout_status_cannot_accept_a_new_template(self):
        deployment = {'metadata': {'generation': 2}, 'spec': {'replicas': 2},
                      'status': {'observedGeneration': 1, 'replicas': 2, 'updatedReplicas': 2, 'readyReplicas': 2, 'availableReplicas': 2}}
        self.assertFalse(deployment_ready(deployment))
        deployment['status']['observedGeneration'] = 2
        self.assertTrue(deployment_ready(deployment))
        deployment['status']['replicas'] = 3
        self.assertFalse(deployment_ready(deployment))

    def setUp(self):
        self.repository = 'IPA-CyberLab/IPA-RS-HeteroCloud-Flash'
        self.report = {'Results': [{'Type': 'cargo', 'Packages': [{'Name': 'rustls', 'Version': '0.23.45'}]}]}
        self.value = candidate(self.repository, 'a' * 40, 'ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash@sha256:' + 'b' * 64, 12, self.report, self.report, [])
        self.component = {'repository': self.repository}
        self.run = {'head_sha': 'a' * 40, 'head_branch': 'master', 'status': 'completed', 'conclusion': 'success',
                    'event': 'workflow_dispatch', 'path': '.github/workflows/oss-security.yml'}

    def test_exact_ci_binding_is_accepted(self):
        validate_identity(self.value, self.component, self.run)

    def test_failed_and_untrusted_ci_cannot_promote(self):
        for changed in [{'conclusion': 'failure'}, {'head_sha': 'c' * 40}, {'event': 'pull_request'},
                        {'head_branch': 'untrusted'}, {'path': '.github/workflows/other.yml'}]:
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                validate_identity(self.value, self.component, {**self.run, **changed})

    def test_mutable_or_foreign_images_are_rejected(self):
        for image in ['ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash:latest',
                      'ghcr.io/attacker/flash@sha256:' + 'b' * 64]:
            with self.subTest(image=image), self.assertRaises(ValueError):
                candidate(self.repository, 'a' * 40, image, 12, self.report, self.report, [])

    def test_built_image_with_no_packages_is_not_a_pass(self):
        with self.assertRaises(ValueError):
            candidate(self.repository, 'a' * 40, self.value['image'], 12, self.report, {}, [])

    def test_a_targeted_advisory_must_disappear(self):
        bad = {'Results': [{'Type': 'cargo', 'Vulnerabilities': [{'VulnerabilityID': 'GHSA-target', 'PkgName': 'rustls', 'InstalledVersion': '0.23.43'}]}]}
        with self.assertRaises(ValueError):
            candidate(self.repository, 'a' * 40, self.value['image'], 12, bad, self.report, [{'advisories': ['GHSA-target']}])

    def test_tag_plus_digest_and_bare_digest_refer_to_the_same_artifact(self):
        digest = 'sha256:' + 'b' * 64
        self.assertEqual(canonical_image('registry.example:5443/team/api:v1@' + digest), 'registry.example:5443/team/api@' + digest)

    def test_unfixed_advisories_do_not_count_as_automatic_fixes(self):
        old = [{'id': 'CVE-unfixed', 'package': 'p', 'fixed_version': ''},
               {'id': 'GHSA-fixed', 'package': 'q', 'fixed_version': '2'}]
        self.assertEqual(verified_fixes(old, []), ['GHSA-fixed'])


class LiveAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.before = {'nonce': 'in-memory-only', 'memory_hash': 'hash', 'started_ns': 1, 'guest_pid': 1, 'connections': 1, 'sequence': 1}

    def test_restarts_and_reconnections_cannot_pass_the_migration_probe(self):
        self.assertTrue(continuity(self.before, {**self.before, 'sequence': 2}))
        for change in [{'nonce': 'restarted'}, {'started_ns': 2}, {'connections': 2}, {'sequence': 0}, {'memory_hash': 'lost'}]:
            with self.subTest(change=change):
                self.assertFalse(continuity(self.before, {**self.before, 'sequence': 2, **change}))

    def test_fresh_runtime_observation_detects_a_live_server_connection(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            with socket.create_connection(listener.getsockname()) as client:
                connection, _ = listener.accept()
                with connection:
                    self.assertEqual(tcp_connections(os.getpid())['inbound_connections'], 1)

    def test_kubernetes_container_identity_without_a_runtime_pid_is_rejected(self):
        pods = [{'metadata': {'uid': 'user-pod'}, 'spec': {'nodeName': 'node'},
                 'status': {'phase': 'Running', 'containerStatuses': [
                     {'name': 'workload', 'containerID': 'containerd://cid', 'state': {'running': {}}}]}}]
        with self.assertRaises(RuntimeError):
            tenant_identity(pods, {'node': {'tasks': {}}})
        old = tenant_identity(pods, {'node': {'tasks': {'cid': {'pid': 123, 'exe_sha256': 'a' * 64}}}})
        restarted = tenant_identity(pods, {'node': {'tasks': {'cid': {'pid': 456, 'exe_sha256': 'a' * 64}}}})
        self.assertNotEqual(old, restarted)


if __name__ == '__main__':
    unittest.main()
