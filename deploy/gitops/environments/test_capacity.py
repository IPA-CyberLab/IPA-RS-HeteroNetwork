import unittest
from decimal import Decimal

import capacity


class CapacityTests(unittest.TestCase):
    def test_quantities(self):
        for raw, value in (('250m', Decimal('.25')), ('1Gi', 1073741824), ('1e3', 1000),
                           ('512Mi', 536870912), ('1.5', Decimal('1.5'))):
            self.assertEqual(capacity.quantity(raw), value)
        for raw in ('-1', '1bad', 'nan', 'inf'):
            with self.assertRaises(ValueError):
                capacity.quantity(raw)

    def test_init_peak_and_limit_default(self):
        pod = {'containers': [{'resources': {'limits': {'cpu': '1', 'memory': '1Gi'}}}],
               'initContainers': [{'resources': {'requests': {'cpu': '2', 'memory': '512Mi'}}}],
               'overhead': {'cpu': '10m'}}
        self.assertEqual(capacity.units(capacity.pod_requests(pod)),
                         {'cpu_millicores': 2010, 'memory_bytes': 1073741824})

    def test_unmodelled_shapes_fail_explicitly(self):
        for pod in ({'resources': {'requests': {'cpu': '1'}}},
                    {'initContainers': [{'restartPolicy': 'Always'}]}):
            with self.assertRaises(ValueError):
                capacity.pod_requests(pod)

    def test_replica_and_job_totals(self):
        pod = {'containers': [{'name': 'worker', 'resources': {'requests': {'cpu': '100m', 'memory': '128Mi'}}}]}
        docs = [{'kind': 'Deployment', 'metadata': {'name': 'api'},
                 'spec': {'replicas': 3, 'template': {'spec': pod}}},
                {'kind': 'Job', 'metadata': {'name': 'migrate'}, 'spec': {'template': {'spec': pod}}}]
        rows = capacity.workloads(docs, 'dev')
        self.assertEqual(rows[0]['total']['cpu_millicores'], 300)
        self.assertFalse(rows[0]['transient'])
        self.assertTrue(rows[1]['transient'])


if __name__ == '__main__':
    unittest.main()
