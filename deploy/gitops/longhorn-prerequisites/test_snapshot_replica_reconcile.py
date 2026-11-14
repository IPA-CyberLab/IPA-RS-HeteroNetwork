import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('snapshot_replica_reconcile', Path(__file__).with_name('snapshot-replica-reconcile.py'))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class ReplicaTests(unittest.TestCase):
    def replica(self, node, **overrides):
        result={'metadata':{},'spec':{'volumeName':'pvc-test','nodeID':node,'healthyAt':'2026-01-01','failedAt':''},
                'status':{'currentState':'running'}}
        for key,value in overrides.items():result['spec'][key]=value
        return result

    def test_counts_distinct_healthy_running_hosts_only(self):
        values=[self.replica('a'),self.replica('a'),self.replica('b'),self.replica('c',failedAt='bad'),
                self.replica('d',volumeName='other')]
        values.append({**self.replica('e'),'status':{'currentState':'stopped'}})
        values.append({**self.replica('f'),'metadata':{'deletionTimestamp':'now'}})
        self.assertEqual(check.healthy_hosts(values,'pvc-test'),['a','b'])

    def test_query_is_scoped_to_bound_snapshot_volume(self):
        class Api:
            def __init__(self):self.paths=[]
            def get(self,path):
                self.paths.append(path)
                return {'spec':{'volumeName':'pvc-test'}} if len(self.paths)==1 else {'items':[]}
        api=Api()
        self.assertEqual(check.check(api),[])
        self.assertIn('longhornvolume%3Dpvc-test',api.paths[1])


if __name__ == '__main__':
    unittest.main()
