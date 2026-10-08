import importlib.util
from pathlib import Path
import unittest

SOURCE=Path(__file__).resolve().parents[1]/'deploy/gitops/flash-web/gateway_health.py'
spec=importlib.util.spec_from_file_location('gateway_health',SOURCE)
health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)
FIXTURE=b'''# unrelated prefix\n(heterocloud_envoy) {
 reverse_proxy 127.0.0.1:19001 127.0.0.1:19002 {
  lb_policy first
  fail_duration 10s
  max_fails 1
  unhealthy_status 5xx
  health_uri {args[0]}
  health_headers {
   Host {args[1]}
  }
  health_interval 2s
  health_timeout 2s
  health_status 2xx
 }
}
(other) { unhealthy_status 5xx }
# unrelated suffix
'''
class HealthTests(unittest.TestCase):
 def test_application_errors_do_not_withdraw_shared_proxy(self):
  updated=health.update(FIXTURE,'gateway-health.flash.example.org');body=updated.split(b'(other)')[0]
  self.assertNotIn(b'unhealthy_status',body)
  self.assertIn(b'health_uri /healthz',body)
  self.assertIn(b'Host gateway-health.flash.example.org',body)
  self.assertIn(b'health_fails 3',body)
  self.assertIn(b'health_passes 2',body)
  self.assertIn(b'fail_duration 10s',body)
  self.assertEqual(updated[updated.index(b'(other)'):],FIXTURE[FIXTURE.index(b'(other)'):])
  self.assertEqual(health.update(updated,'gateway-health.flash.example.org'),updated)
 def test_canonical_application_health_is_not_used(self):
  updated=health.update(FIXTURE,'gateway-health.flash.example.org')
  self.assertNotIn(b'{args[0]}',updated)
  self.assertNotIn(b'{args[1]}',updated)
 def test_ambiguous_or_incomplete_definitions_fail_before_publication(self):
  for value in [FIXTURE+FIXTURE,FIXTURE.replace(b'health_uri {args[0]}',b'# missing'),FIXTURE.replace(b'health_status 2xx',b'# missing'),FIXTURE.split(b'\n(other)')[0][:-2]]:
   with self.subTest(value=value[:30]),self.assertRaises(ValueError):health.update(value,'gateway-health.flash.example.org')
 def test_hostname_injection_and_operator_stub(self):
  with self.assertRaises(ValueError):health.update(FIXTURE,'bad.example.org\nrespond 200')
  stub=b'(heterocloud_envoy) { respond ok }\n';self.assertEqual(health.update(stub,'gateway-health.flash.example.org'),stub)
if __name__=='__main__':unittest.main()
