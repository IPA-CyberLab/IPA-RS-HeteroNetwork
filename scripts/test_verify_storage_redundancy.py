import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('storage_audit', Path(__file__).with_name('verify-storage-redundancy.py'))
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class StorageRedundancyTest(unittest.TestCase):
    def fixture(self):
        condition = [{'type': 'Ready', 'status': 'True'}]
        volumes = {'items': [{'metadata': {'name': 'registry'}, 'spec': {'numberOfReplicas': 3}}]}
        replicas = {'items': [{'metadata': {}, 'spec': {'volumeName': 'registry', 'nodeID': n,
                               'diskID': 'disk', 'healthyAt': '2026-10-01', 'failedAt': ''}}
                             for n in ['a', 'b', 'c']]}
        nodes = {'items': [{'metadata': {'name': n}, 'status': {'conditions': copy.deepcopy(condition)}}
                          for n in ['a', 'b', 'c']]}
        storage = {'items': [{'metadata': {'name': n}, 'status': {'conditions': copy.deepcopy(condition),
                             'diskStatus': {'disk-label': {'diskUUID': 'disk', 'conditions': copy.deepcopy(condition)}}}}
                            for n in ['a', 'b', 'c']]}
        return volumes, replicas, nodes, storage

    def test_three_configured_replicas_do_not_make_one_actual_copy_redundant(self):
        values = self.fixture()
        values[1]['items'] = values[1]['items'][:1]
        report = A.audit(*values)
        self.assertEqual(report['result'], 'failed')
        self.assertEqual(report['critical_volumes'], 1)
        self.assertEqual(report['volumes'][0]['available_copies'], 1)

    def test_explicitly_configuring_one_copy_does_not_hide_a_single_host_dependency(self):
        values = self.fixture()
        values[0]['items'][0]['spec']['numberOfReplicas'] = 1
        values[1]['items'] = values[1]['items'][:1]
        self.assertEqual(A.audit(*values)['critical_volumes'], 1)

    def test_offline_hosts_failed_disks_and_failed_copies_do_not_count(self):
        for index in range(3):
            values = self.fixture()
            if index == 0:
                values[2]['items'][0]['status']['conditions'][0]['status'] = 'False'
            elif index == 1:
                values[3]['items'][0]['status']['diskStatus']['disk-label']['conditions'][0]['status'] = 'False'
            else:
                values[1]['items'][0]['spec']['failedAt'] = '2026-10-25'
            report = A.audit(*values)
            self.assertEqual(report['result'], 'failed')
            self.assertEqual(report['volumes'][0]['available_copies'], 2)

    def test_multiple_copies_on_one_host_are_one_failure_domain(self):
        values = self.fixture()
        for replica in values[1]['items']:
            replica['spec']['nodeID'] = 'a'
        self.assertEqual(A.audit(*values)['critical_volumes'], 1)

    def test_only_a_complete_inventory_with_three_available_hosts_passes(self):
        self.assertEqual(A.audit(*self.fixture())['result'], 'passed')
        self.assertEqual(A.audit(*[{'items': []}] * 4)['result'], 'failed')


if __name__ == '__main__':
    unittest.main()
