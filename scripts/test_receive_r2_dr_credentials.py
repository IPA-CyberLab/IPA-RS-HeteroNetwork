import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


path = Path(__file__).with_name('receive-r2-dr-credentials.py')
spec = importlib.util.spec_from_file_location('receive_r2_dr_credentials', path)
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class FakeS3:
    objects = {}
    requests = []

    def __init__(self, config):
        self.bucket = config['bucket']

    def request(self, method, key, data=None):
        self.requests.append((self.bucket, method, key))
        location = (self.bucket, key)
        if method == 'PUT':
            self.objects[location] = data
        elif method == 'GET':
            return self.objects[location]
        elif method == 'DELETE':
            del self.objects[location]
        else:
            raise AssertionError('unexpected request')


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        FakeS3.objects.clear()
        FakeS3.requests.clear()

    def test_verification_uses_unique_objects_and_removes_them(self):
        receiver.verify_destinations([{'bucket': 'flash'}, {'bucket': 'control'}], FakeS3)
        self.assertEqual(FakeS3.objects, {})
        self.assertEqual([method for _, method, _ in FakeS3.requests],
                         ['PUT', 'GET', 'DELETE', 'PUT', 'GET', 'DELETE'])
        self.assertNotEqual(FakeS3.requests[0][2], FakeS3.requests[3][2])

    def test_verification_removes_uploaded_object_when_readback_fails(self):
        class BadRead(FakeS3):
            def request(self, method, key, data=None):
                if method == 'GET':
                    return b'incorrect'
                return super().request(method, key, data)

        with self.assertRaises(ValueError):
            receiver.verify_destinations([{'bucket': 'flash'}], BadRead)
        self.assertEqual(FakeS3.objects, {})

    def test_files_are_private_and_existing_files_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'credentials'
            configs = {'flash.json': {'secret_key': 'test-only'}, 'control-plane.json': {'secret_key': 'test-only'}}
            receiver.write_configurations(directory, configs)
            self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(directory / 'flash.json').st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                receiver.write_configurations(directory, configs)
            self.assertIn('test-only', (directory / 'flash.json').read_text())

    def test_unprotected_directory_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'credentials'
            directory.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                receiver.write_configurations(directory, {'flash.json': {}})
            os.chmod(directory, 0o700)
            (directory / 'flash.json').symlink_to(Path(tmp) / 'outside')
            with self.assertRaises(ValueError):
                receiver.write_configurations(directory, {'flash.json': {}})


if __name__ == '__main__':
    unittest.main()
