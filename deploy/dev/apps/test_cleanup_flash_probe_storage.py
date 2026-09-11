import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('cleanup', Path(__file__).with_name('cleanup-flash-probe-storage.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class Cleanup(unittest.TestCase):
    def fixture(self):
        return {'metadata': {'name': c.PV, 'uid': c.PV_UID}, 'status': {'phase': 'Released'},
                'spec': {'claimRef': {'namespace': c.NS, 'name': c.CLAIM, 'uid': c.CLAIM_UID},
                         'storageClassName': 'dev-flash-rwx', 'persistentVolumeReclaimPolicy': 'Retain',
                         'csi': {'driver': 'driver.longhorn.io', 'volumeHandle': c.PV}}}

    def test_only_released_exact_fixture(self):
        original = self.fixture()
        c.validate(original, None)
        for path, value in [(('metadata', 'uid'), 'foreign'), (('status', 'phase'), 'Bound'),
                            (('spec', 'storageClassName'), 'dev-app-local')]:
            obj = copy.deepcopy(original)
            obj[path[0]][path[1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                c.validate(obj, None)
        obj = copy.deepcopy(original)
        obj['spec']['claimRef']['namespace'] = 'production'
        with self.assertRaises(ValueError):
            c.validate(obj, None)
        c.validate(None, None)

    def test_attached_or_foreign_volume_rejected(self):
        volume = {'metadata': {'name': c.PV, 'uid': c.VOLUME_UID},
                  'spec': {'nodeID': ''}, 'status': {'currentNodeID': '', 'state': 'detached',
                  'kubernetesStatus': {'namespace': c.NS, 'pvcName': c.CLAIM, 'pvName': c.PV}}}
        c.validate(self.fixture(), volume)
        for section, key, value in [('metadata', 'uid', 'foreign'), ('spec', 'nodeID', 'hetero-dev-1'),
                                     ('status', 'currentNodeID', 'hetero-dev-1'), ('status', 'state', 'attached')]:
            changed = copy.deepcopy(volume)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                c.validate(self.fixture(), changed)


if __name__ == '__main__':
    unittest.main()
