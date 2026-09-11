import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
spec = importlib.util.spec_from_file_location('activation', Path(__file__).with_name('activate-storage.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ActivationTests(unittest.TestCase):
    def test_guard_requires_loaded_dependency_edges_and_mount(self):
        good = {'Requires': 'data.mount', 'BindsTo': 'data.mount', 'After': 'data.mount',
                'DropInPaths': str(app.mount.DROPIN), 'NeedDaemonReload': 'no'}
        for state, active, valid in ((good, 'active', True), ({**good, 'BindsTo': ''}, 'active', False),
                                    ({**good, 'NeedDaemonReload': 'yes'}, 'active', False),
                                    (good, 'inactive', False)):
            with patch.object(app, 'properties', side_effect=[state, {'ActiveState': active}]):
                if valid:
                    app.verify_guard('data.mount')
                else:
                    with self.assertRaises(ValueError):
                        app.verify_guard('data.mount')

    def test_expected_directories_are_separate_from_identity(self):
        for host in app.mount.MACHINES:
            entries = app.expected_directories({'host': host})
            self.assertEqual(len(entries), 6)
            self.assertEqual(sum(int(e['capacity'][:-2]) for e in entries), 35)
            self.assertTrue(all('/' not in e['name'] and 'identity' not in e['name'] for e in entries))

    def test_quoted_systemctl_unit_lists(self):
        name = r'var-lib-heteronetwork\x2ddev\x2dapp\x2dstorage.mount'
        quoted = '"' + name.replace('\\', '\\\\') + '"'
        state = {key: quoted for key in ('Requires', 'BindsTo', 'After')}
        state.update(DropInPaths=str(app.mount.DROPIN), NeedDaemonReload='no')
        with patch.object(app, 'properties', side_effect=[state, {'ActiveState': 'active'}]):
            app.verify_guard(name)

    def test_partial_directory_transaction_never_creates_more(self):
        with patch.object(app.mount, 'exists', side_effect=[True, True, False]), \
                patch.object(Path, 'mkdir') as mkdir, patch.object(app.mount, 'write_new') as write:
            with self.assertRaises(ValueError):
                app.directories({'host': 'hetero-dev-1'}, 'unused', True)
            mkdir.assert_not_called()
            write.assert_not_called()


if __name__ == '__main__':
    unittest.main()
