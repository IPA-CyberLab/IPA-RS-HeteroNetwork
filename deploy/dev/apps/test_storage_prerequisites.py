import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

spec = importlib.util.spec_from_file_location('storage_prerequisites', Path(__file__).with_name('install-storage-prerequisites.py'))
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class Prerequisites(unittest.TestCase):
    def test_real_deb822_parser_ignores_cloud_init_comments(self):
        raw = '# Intro: not a field\n\n'
        for fields in self.sources():
            raw += '# Types: a comment\n' + '\n'.join(f'{key}: {value}' for key, value in fields.items()) + '\n\n'
        self.assertEqual(app.parse_sources(raw.encode()), self.sources())

    def sources(self):
        return [{'Types': 'deb', 'URIs': f'http://{host}/ubuntu', 'Suites': suites,
                 'Components': 'main universe restricted multiverse',
                 'Signed-By': '/usr/share/keyrings/ubuntu-archive-keyring.gpg'}
                for host, suites in [('archive.ubuntu.com', 'noble noble-updates noble-backports'),
                                     ('security.ubuntu.com', 'noble-security')]]

    def test_only_transport_changes_and_repeat_is_stable(self):
        before = self.sources()
        original = copy.deepcopy(before)
        after = app.source_stanzas(before)
        self.assertEqual(before, original)
        for old, new in zip(before, after):
            self.assertEqual(new, {**old, 'URIs': old['URIs'].replace('http:', 'https:', 1)})
        self.assertEqual(app.source_stanzas(after), after)

    def test_foreign_sources_and_trust_changes_are_rejected(self):
        for key, value in [('URIs', 'https://mirror.example/ubuntu'), ('Signed-By', '/tmp/key'),
                           ('Suites', 'jammy'), ('Types', 'deb-src'), ('Trusted', 'yes')]:
            fields = self.sources()
            fields[0][key] = value
            with self.assertRaises(ValueError):
                app.source_stanzas(fields)
        with self.assertRaises(ValueError):
            app.source_stanzas(self.sources()[:1])

    def test_dpkg_requires_installed_status(self):
        for code, output, expected in [(1, '', None), (0, 'config-files 1:2.6.4-3ubuntu5.1', None),
                                        (0, 'installed 1:2.6.4-3ubuntu5.1', app.VERSION)]:
            with patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, output, '')):
                self.assertEqual(app.installed_version(), expected)


if __name__ == '__main__':
    unittest.main()
