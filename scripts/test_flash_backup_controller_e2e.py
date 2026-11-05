import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('flash_backup_controller_probe', Path(__file__).with_name('flash_backup_controller_e2e.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FixtureCleanupTest(unittest.TestCase):
    def probe(self):
        return module.Probe(SimpleNamespace(kubectl='unused', kubeconfig='unused', image='unused', report='unused'))

    def test_foreign_and_recreated_fixtures_are_never_owned(self):
        probe=self.probe()
        value={'metadata':{'uid':'first','labels':{module.LABEL:probe.nonce}}}
        probe.get=lambda *args,**kwargs:value
        probe.identities[('PersistentVolumeClaim',probe.source)]='first'
        self.assertIs(probe.owned('pvc',probe.source),value)
        value['metadata']['uid']='replacement'
        with self.assertRaises(RuntimeError): probe.owned('pvc',probe.source)
        value['metadata']['uid']='first'
        value['metadata']['labels'][module.LABEL]='another-probe'
        with self.assertRaises(RuntimeError): probe.owned('pvc',probe.source)

    def test_claims_are_retained_if_backup_identity_does_not_match(self):
        probe=self.probe()
        calls=[]
        def get(kind,name,namespace=module.NAMESPACE):
            if kind=='flashbackup': return {'metadata':{'uid':'foreign','labels':{module.LABEL:'another-probe'}}}
            if kind=='pvc': return {'metadata':{'uid':'mine','labels':{module.LABEL:probe.nonce}}}
            return None
        probe.get=get
        probe.call=lambda *args,**kwargs:calls.append(args)
        probe.report['result']='passed'
        probe.cleanup()
        self.assertEqual(calls,[])
        self.assertEqual(probe.report['result'],'failed')
        self.assertIn('claims retained until dependent fixtures are removed',probe.report['cleanup']['failed_stages'])

    def test_volume_with_wrong_claim_uid_is_never_changed(self):
        probe=self.probe()
        calls=[]
        def get(kind,name,namespace=module.NAMESPACE):
            if kind=='pvc' and name==probe.source:
                return {'metadata':{'uid':'mine','labels':{module.LABEL:probe.nonce}},'spec':{'volumeName':'fixture-pv'}}
            if kind=='pv':
                return {'metadata':{'resourceVersion':'1'},'spec':{'claimRef':{'uid':'other','name':probe.source,'namespace':module.NAMESPACE}}}
            return None
        probe.get=get
        probe.call=lambda *args,**kwargs:calls.append(args)
        probe.report['result']='passed'
        probe.cleanup()
        self.assertEqual(calls,[])
        self.assertEqual(probe.report['result'],'failed')
        self.assertIn('claim',probe.report['cleanup']['failed_stages'])


if __name__=='__main__': unittest.main()
