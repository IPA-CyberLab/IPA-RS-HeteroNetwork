import unittest
from reconcile_platform_release import override_revision, superseded


class ReleaseOverrideBoundaries(unittest.TestCase):
    def test_release_includes_old_security_fix(self):
        self.assertTrue(superseded('old', 'new', {'status': 'ahead', 'behind_by': 0}))

    def test_newer_and_same_source_security_fixes_are_preserved(self):
        self.assertFalse(superseded('same', 'same', {}))
        self.assertFalse(superseded('newer-security', 'release', {'status': 'behind', 'ahead_by': 0}))

    def test_unrelated_source_cannot_be_overwritten(self):
        for comparison in [{}, {'status': 'diverged'}, {'status': 'ahead', 'behind_by': 1}]:
            with self.assertRaises(RuntimeError):
                superseded('one', 'two', comparison)

    def test_image_identity_must_be_exact_and_supported(self):
        self.assertEqual(override_revision('security-' + 'a'*40 + '-123@sha256:' + 'b'*64), 'a'*40)
        self.assertEqual(override_revision('0.1.105@sha256:' + 'b'*64), 'v0.1.105')
        for invalid in ['latest', 'latest@sha256:'+'b'*64, 'security-'+'a'*40, 'untrusted/other:0.1.105@sha256:'+'b'*64]:
            with self.assertRaises(RuntimeError):
                override_revision(invalid)


if __name__ == '__main__':
    unittest.main()
