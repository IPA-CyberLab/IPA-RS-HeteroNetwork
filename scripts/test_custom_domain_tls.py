"""Exercise custom TLS loading and configuration without touching a real gateway."""
import json
from pathlib import Path
from unittest import mock
import unittest
from test_flash_tls_sync import SyncTests, sync

class CustomDomainTLS(SyncTests):
    def setUp(self):
        super().setUp()
        self.bundle_file=self.work/'bundle.json'
        self.data={'schema_version':1,'hosts':['wrong.example'],'certificates':{'wrong.example':{'certificate':self.pairs[2][0].decode(),'private_key':self.pairs[2][1].decode()}},'acme_upstream':'10.96.0.20:80'}
    def run_custom(self):
        self.bundle_file.write_text(json.dumps(self.data))
        return sync.sync(str(self.host), str(self.secret), str(self.group), str(self.bundle_file))
    def test_custom_add_remove_does_not_modify_unmanaged_content(self):
        self.assertTrue(self.run_custom());before=self.extra.read_bytes()
        self.assertIn(b'https://wrong.example:443 {',before)
        self.assertIn(b'/.well-known/acme-challenge/*',before)
        self.assertFalse(self.run_custom())
        self.data['hosts']=[];self.data['certificates']={}
        self.assertTrue(self.run_custom());after=self.extra.read_bytes()
        self.assertNotIn(b'wrong.example',after)
        start=after.index(sync.BEGIN);end=after.index(sync.END)+len(sync.END)
        self.assertEqual(after[:start]+after[end:],self.original)
    def test_key_mismatch_preserves_previous_gateway_configuration(self):
        self.run_custom();before=self.extra.read_bytes()
        self.data['certificates']['wrong.example']['private_key']=self.pairs[0][1].decode()
        with self.assertRaises(ValueError):self.run_custom()
        self.assertEqual(before,self.extra.read_bytes())
    def test_unverified_hosts_cannot_add_certificates(self):
        self.data['hosts']=[]
        with self.assertRaises(ValueError):self.run_custom()
        self.assertEqual(self.original,self.extra.read_bytes())
    def test_pending_domain_gets_only_http_challenge_route(self):
        self.data['certificates']={};self.run_custom();actual=self.extra.read_bytes()
        self.assertNotIn(b'https://wrong.example:443 {',actual)
        self.assertIn(b'Domain is provisioning',actual)
    def test_retired_keys_are_collected_only_after_reload_grace(self):
        import os,time
        self.run_custom();old_dirs=set((self.host/sync.CERTDIR).iterdir())
        self.data['hosts']=[];self.data['certificates']={};self.run_custom()
        self.assertEqual(old_dirs,set((self.host/sync.CERTDIR).iterdir()))
        before=self.extra.read_bytes()
        for directory in old_dirs:os.utime(directory,(time.time()-7200,time.time()-7200))
        self.run_custom()
        remaining=set((self.host/sync.CERTDIR).iterdir())
        self.assertEqual(len(remaining),1,'only the currently referenced wildcard pair remains')
        self.assertEqual(before,self.extra.read_bytes())
    def test_public_proxy_and_reserved_names_are_rejected(self):
        for address in ['163.220.236.54:80','127.0.0.1:80','10.96.0.20:443']:
            self.data['acme_upstream']=address
            with self.assertRaises(ValueError):self.run_custom()
        self.data['acme_upstream']='10.96.0.20:80'
        self.data['hosts']=[sync.PUBLIC_HOSTS[0]];self.data['certificates']={}
        with self.assertRaises(ValueError):self.run_custom()

if __name__=='__main__':unittest.main()
