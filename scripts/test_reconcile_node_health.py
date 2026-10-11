import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('node_health', Path(__file__).with_name('reconcile-node-health.py'))
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)


class NodeHealthTests(unittest.TestCase):
    def test_preserves_unrelated_arguments_and_is_idempotent(self):
        original = '  - --node-monitor-grace-period=20s\n  - --node-monitor-period=5s\n'
        changed = health.replace_manifest(original, 60)
        self.assertEqual(changed, '  - --node-monitor-grace-period=60s\n  - --node-monitor-period=5s\n')
        self.assertEqual(health.replace_manifest(changed, 60), changed)

    def test_missing_or_ambiguous_setting_fails_closed(self):
        for text in ['', '  - --node-monitor-grace-period=20s\n' * 2]:
            with self.assertRaises(ValueError):
                health.replace_manifest(text, 60)
        with self.assertRaises(ValueError):
            health.replace_cluster_config('controllerManager: {}', 60)

    def test_kubeadm_upgrade_and_join_preserve_policy(self):
        for quote in ['', '"', "'"]:
            text = f'controllerManager:\n  extraArgs:\n  - name: {quote}node-monitor-grace-period{quote}\n    value: {quote}20s{quote}\ndns: {{}}\n'
            changed = health.replace_cluster_config(text, 60)
            self.assertIn('value: 60s\ndns: {}', changed)
            self.assertEqual(health.replace_cluster_config(changed, 60), changed)

    def test_old_ready_pod_does_not_satisfy_rollout(self):
        pod = {'spec': {'nodeName': 'node-a', 'containers': [{'name': 'kube-controller-manager',
               'command': ['kube-controller-manager', '--node-monitor-grace-period=60s']}]},
               'status': {'containerStatuses': [{'name': 'kube-controller-manager', 'ready': True,
                          'state': {'running': {}}}], 'conditions': [{'type': 'Ready', 'status': 'True'}]}}
        health.verify(pod, 'node-a', 60)
        old = copy.deepcopy(pod)
        old['spec']['containers'][0]['command'][-1] = '--node-monitor-grace-period=20s'
        with self.assertRaises(ValueError):
            health.verify(old, 'node-a', 60)
        pod['status']['containerStatuses'][0]['ready'] = False
        with self.assertRaises(ValueError):
            health.verify(pod, 'node-a', 60)


if __name__ == '__main__':
    unittest.main()
