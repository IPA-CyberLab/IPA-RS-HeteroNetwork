import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


script = Path(__file__).with_name('reconcile-receive-steering.py')
spec = importlib.util.spec_from_file_location('receive_steering', script)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReceiveSteeringTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.sysfs = Path(self.directory.name)
        online = self.sysfs / 'devices/system/cpu/online'
        online.parent.mkdir(parents=True)
        online.write_text('0-15\n')
        self.interface = self.sysfs / 'class/net/enp6s0'
        (self.interface / 'device').mkdir(parents=True)
        driver = self.sysfs / 'drivers/igb'
        driver.mkdir(parents=True)
        (self.interface / 'device/driver').symlink_to(driver)
        self.queues = []
        for index in range(2):
            queue = self.interface / f'queues/rx-{index}/rps_cpus'
            queue.parent.mkdir(parents=True)
            queue.write_text('0000\n')
            self.queues.append(queue)
        self.config = {'node': 'uc-k8sp5', 'interface': 'enp6s0', 'driver': 'igb',
                       'online_cpus': '0-15', 'queues': 2, 'rps_cpus': 'c3ff'}

    def apply(self, **overrides):
        return module.reconcile({**self.config, **overrides}, self.sysfs, 'uc-k8sp5')

    def test_applies_and_is_idempotent(self):
        self.assertTrue(self.apply()['changed'])
        self.assertEqual([p.read_text() for p in self.queues], ['c3ff', 'c3ff'])
        self.assertFalse(self.apply()['changed'])

    def test_wrong_host_driver_topology_and_queue_count_fail_closed(self):
        for overrides in ({'node': 'another'}, {'driver': 'other'},
                          {'online_cpus': '0-7'}, {'queues': 3}, {'rps_cpus': '10000'}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.apply(**overrides)
        self.assertEqual([p.read_text() for p in self.queues], ['0000\n', '0000\n'])

    def test_refuses_an_unrelated_existing_policy(self):
        self.queues[1].write_text('00000008')
        with self.assertRaisesRegex(ValueError, 'unrelated'):
            self.apply()
        self.assertEqual(self.queues[0].read_text(), '0000\n')
        self.assertEqual(self.queues[1].read_text(), '00000008')

    def test_rolls_back_both_queues_after_a_partial_write_failure(self):
        original = Path.write_text
        failed = False

        def unreliable(path, data, *args, **kwargs):
            nonlocal failed
            if path == self.queues[1] and data == 'c3ff' and not failed:
                failed = True
                original(path, '1')
                raise OSError('simulated interrupted write')
            return original(path, data, *args, **kwargs)

        with mock.patch.object(Path, 'write_text', unreliable), self.assertRaises(OSError):
            self.apply()
        self.assertEqual([p.read_text() for p in self.queues], ['0000', '0000'])

    def test_selected_queues_stay_on_the_nic_numa_node(self):
        (self.sysfs / 'devices/system/cpu/online').write_text('0-103\n')
        cpulist = self.sysfs / 'devices/system/node/node0/cpulist'
        cpulist.parent.mkdir(parents=True)
        cpulist.write_text('0-25,52-77\n')
        (self.interface / 'device/numa_node').write_text('0\n')
        for index in range(2, 26):
            queue = self.interface / f'queues/rx-{index}/rps_cpus'
            queue.parent.mkdir(parents=True)
            queue.write_text('0000\n')
            self.queues.append(queue)
        config = {**self.config, 'online_cpus': '0-103', 'queues': 26,
                  'queue_indices': [0, 2], 'numa_node': 0, 'rps_cpus': '03ffffff'}
        self.assertTrue(module.reconcile(config, self.sysfs, 'uc-k8sp5')['changed'])
        self.assertEqual([self.queues[i].read_text() for i in (0, 2)], ['03ffffff', '03ffffff'])
        self.assertTrue(all(self.queues[i].read_text() == '0000\n' for i in range(26) if i not in (0, 2)))
        self.assertFalse(module.reconcile(config, self.sysfs, 'uc-k8sp5')['changed'])
        with self.assertRaisesRegex(ValueError, 'NUMA'):
            module.reconcile({**config, 'rps_cpus': '04000000'}, self.sysfs, 'uc-k8sp5')
        with self.assertRaisesRegex(ValueError, 'selected'):
            module.reconcile({**config, 'queue_indices': [0, 26]}, self.sysfs, 'uc-k8sp5')


if __name__ == '__main__':
    unittest.main()
