import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("root_storage", Path(__file__).with_name("reconcile-root-storage.py"))
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class RootStorageTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"logical_volume": "/dev/example/root", "filesystem": "ext4", "size_gib": 220}
        self.state = {"logical_volume": "/dev/example/root", "filesystem": "ext4", "lv_bytes": 200 * storage.GIB, "vg_free_bytes": 21 * storage.GIB, "filesystem_bytes": 197 * storage.GIB}

    def test_grows_only_existing_free_extents(self):
        self.assertEqual(storage.plan(self.policy, self.state)["grow_bytes"], 20 * storage.GIB)

    def test_repeat_convergence_does_not_grow_again(self):
        self.state.update(lv_bytes=220 * storage.GIB, filesystem_bytes=216 * storage.GIB)
        self.assertEqual(storage.plan(self.policy, self.state), {"target_bytes": 220 * storage.GIB, "grow_bytes": 0, "filesystem_resize": False})

    def test_refuses_a_shrink(self):
        self.state["lv_bytes"] = 240 * storage.GIB
        with self.assertRaises(ValueError):
            storage.plan(self.policy, self.state)

    def test_refuses_unknown_filesystem_or_device(self):
        for field, value in [("logical_volume", "/dev/other/root"), ("filesystem", "xfs")]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                storage.plan(self.policy, {**self.state, field: value})

    def test_refuses_to_consume_unavailable_extents(self):
        self.state["vg_free_bytes"] = 19 * storage.GIB
        with self.assertRaises(ValueError):
            storage.plan(self.policy, self.state)


if __name__ == "__main__":
    unittest.main()
