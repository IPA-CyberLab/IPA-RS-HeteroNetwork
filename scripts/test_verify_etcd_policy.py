import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('etcd_policy', Path(__file__).with_name('verify-etcd-policy.py'))
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class EtcdPolicyTests(unittest.TestCase):
    def setUp(self):
        self.members = {'members': [{'ID': i, 'clientURLs': [f'https://10.0.0.{i}:2379']} for i in [1, 2, 3]]}
        self.statuses = [{'Status': {'header': {'member_id': i}, 'leader': 1}} for i in [1, 2, 3]]
        self.health = [{'endpoint': f'https://10.0.0.{i}:2379', 'health': True} for i in [1, 2, 3]]

    def test_requires_every_existing_member_healthy_not_just_a_quorum(self):
        self.assertEqual(policy.validate_cluster(self.members, self.statuses, self.health), 1)
        self.health[-1]['health'] = False
        with self.assertRaises(ValueError):
            policy.validate_cluster(self.members, self.statuses, self.health)

    def test_rejects_missing_member_and_divergent_leadership(self):
        with self.assertRaises(ValueError):
            policy.validate_cluster(self.members, self.statuses[:-1], self.health)
        self.statuses[-1]['Status']['leader'] = 2
        with self.assertRaises(ValueError):
            policy.validate_cluster(self.members, self.statuses, self.health)

    def test_rejects_learners_and_failed_endpoints(self):
        self.members['members'][0]['isLearner'] = True
        with self.assertRaises(ValueError):
            policy.validate_cluster(self.members, self.statuses, self.health)
        self.members['members'][0]['isLearner'] = False
        with self.assertRaises(ValueError):
            policy.validate_cluster(self.members, self.statuses, self.health[:-1])

    def test_old_ready_pod_cannot_pass_rollout(self):
        pod = {'spec': {'containers': [{'name': 'etcd', 'command': ['etcd', '--heartbeat-interval=500', '--election-timeout=5000'],
               'resources': {'requests': {'cpu': '500m', 'memory': '512Mi'}},
               'livenessProbe': {'failureThreshold': 30}, 'startupProbe': {'failureThreshold': 180}}]},
               'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        policy.verify_pod(pod)
        old = copy.deepcopy(pod)
        old['spec']['containers'][0]['command'] = ['etcd']
        with self.assertRaises(ValueError):
            policy.verify_pod(old)
        pod['status']['conditions'][0]['status'] = 'False'
        with self.assertRaises(ValueError):
            policy.verify_pod(pod)


if __name__ == '__main__':
    unittest.main()
