import copy
import importlib.util
import json
from pathlib import Path
import unittest
import time
from unittest.mock import patch
import controller as d

HERE=Path(__file__).resolve().parent

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.c=json.loads((HERE/'site.json').read_text())
        self.svc={'metadata':{'uid':'svc-uid'},'spec':{'service_instance_id':'001','organization_id':'org','project_id':'project','workload':{'exposure':{'type':'public','endpoint_mode':'web'}}}}
        self.spec={'hostname':'app.example.org','cname_target':'f-001.'+self.c['public_flash_domain'],'verification_value':'heterocloud-domain=proof','service_uid':'svc-uid','service_instance_id':'001','organization_id':'org','project_id':'project'}
        self.alias={'metadata':{'name':d.digest_name(self.spec['hostname']),'uid':'alias-uid','ownerReferences':[{'uid':'svc-uid','kind':'FlashService'}]},'spec':self.spec}
    def test_scope_requires_original_service_uid_project_and_organization(self):
        self.assertEqual(d.owned_alias(self.alias,self.svc,self.c),'app.example.org')
        for key in ['service_uid','service_instance_id','organization_id','project_id']:
            a=copy.deepcopy(self.alias);a['spec'][key]='foreign'
            with self.subTest(key=key),self.assertRaises(ValueError):d.owned_alias(a,self.svc,self.c)
    def test_private_platform_wildcard_and_caddy_syntax_are_rejected(self):
        for name in ['a.heteronetwork.internal','*.example.org','a.example.org\n{ respond 200 }','UPPER.example.org','127.0.0.1']:
            with self.assertRaises(ValueError):d.hostname(name)
        for name in [self.c['reserved_hostnames'][0],'tenant.'+self.c['public_flash_domain']]:
            a=copy.deepcopy(self.alias);a['spec']['hostname']=name;a['metadata']['name']=d.digest_name(name)
            with self.assertRaises(ValueError):d.owned_alias(a,self.svc,self.c)
    def test_expected_cname_is_service_specific(self):
        a=copy.deepcopy(self.alias);a['spec']['cname_target']='f-foreign.'+self.c['public_flash_domain']
        with self.assertRaises(ValueError):d.owned_alias(a,self.svc,self.c)
    def test_cname_requires_matching_answers_from_both_resolvers(self):
        def answer(name,kind,resolver):return [{'data':self.spec['cname_target']+'.'}] if kind==5 else []
        with patch.object(d,'dns_answers',side_effect=answer):self.assertTrue(d.delegated(self.spec,self.c))
        def inconsistent(name,kind,resolver):return [{'data':self.spec['cname_target']+'.'}] if kind==5 and 'cloudflare' in resolver else []
        with patch.object(d,'dns_answers',side_effect=inconsistent):self.assertFalse(d.delegated(self.spec,self.c))
    def test_apex_requires_txt_and_matching_public_addresses(self):
        def answer(name,kind,resolver):
            if kind==16:return [{'data':'"'+self.spec['verification_value']+'"'}]
            if kind==1:return [{'data':'163.220.236.61'}]
            return []
        with patch.object(d,'dns_answers',side_effect=answer):self.assertTrue(d.delegated(self.spec,self.c))
        def wrong(name,kind,resolver):
            if kind==16:return [{'data':'"wrong"'}]
            return answer(name,kind,resolver)
        with patch.object(d,'dns_answers',side_effect=wrong):self.assertFalse(d.delegated(self.spec,self.c))
    def test_txt_alone_does_not_authorize_unrelated_or_private_destination(self):
        def answer(name,kind,resolver):
            if kind==16:return [{'data':'"'+self.spec['verification_value']+'"'}]
            if kind==1:return [{'data':'10.250.0.10' if name==self.spec['hostname'] else '163.220.236.61'}]
            return []
        with patch.object(d,'dns_answers',side_effect=answer):self.assertFalse(d.delegated(self.spec,self.c))
    def test_unknown_dns_is_not_interpreted_as_proof(self):
        with patch.object(d,'dns_answers',side_effect=TimeoutError),self.assertRaises(TimeoutError):d.delegated(self.spec,self.c)
    def test_certificate_reference_has_canonical_api_defaults(self):
        c=d.certificate(self.alias,self.c)
        self.assertEqual(c['spec']['issuerRef']['group'],'cert-manager.io')
        self.assertEqual(c['spec']['dnsNames'],['app.example.org'])
        self.assertEqual(c['metadata']['labels'][d.LABEL],'alias-uid')
        self.assertEqual(c['spec']['privateKey']['rotationPolicy'],'Always')
    def test_tls_collector_cannot_read_cloudflare_or_user_secret_namespaces(self):
        import yaml
        docs=list(yaml.safe_load_all((HERE/'infrastructure.yaml').read_text()))
        permissions=[x for x in docs if x['kind']=='Role']
        for role in permissions:
            for rule in role['rules']:
                if 'secrets' not in rule['resources']:continue
                if role['metadata']['namespace']=='heterocloud-dns':
                    self.assertEqual(rule['resourceNames'],['public-custom-domain-tls-bundle'])
                    self.assertNotIn('list',rule['verbs'])
                else:self.assertEqual(role['metadata']['namespace'],'heterocloud-custom-domains')
    def test_stale_publisher_cannot_write_after_lease_or_bundle_takeover(self):
        from unittest.mock import Mock
        secret={'metadata':{'uid':'bundle-uid','resourceVersion':'2','labels':{'domains.heterocloud.io/bundle':'true'},'annotations':{d.WRITER:'new'}}}
        api=Mock();api.optional.return_value=secret
        with self.assertRaises(ValueError):d.publish_bundle(api,self.c,[],{},None,'old')
        api.call.assert_not_called()
        secret['metadata']['annotations'][d.WRITER]='old'
        api.call.return_value={'data':{'lease.json':json.dumps({'owner':'new','expires_at':time.time()+120})}}
        with self.assertRaises(ValueError):d.publish_bundle(api,self.c,[],{},None,'old')
        self.assertTrue(all(x.args[0]=='GET' for x in api.call.call_args_list))
    def test_bundle_publication_tests_resource_version_and_uid(self):
        from unittest.mock import Mock
        secret={'metadata':{'uid':'bundle-uid','resourceVersion':'2','labels':{'domains.heterocloud.io/bundle':'true'},'annotations':{d.WRITER:'active'}}}
        api=Mock();api.optional.return_value=secret
        api.call.return_value={'data':{'lease.json':json.dumps({'owner':'active','expires_at':time.time()+120})}}
        d.publish_bundle(api,self.c,[],{},None,'active')
        changes=api.call.call_args.args[2]
        self.assertEqual(changes[0],{'op':'test','path':'/metadata/resourceVersion','value':'2'})
        self.assertEqual(changes[1],{'op':'test','path':'/metadata/uid','value':'bundle-uid'})
    def test_controllers_do_not_run_on_dedicated_secret_manager_masters(self):
        import yaml
        deployment=next(x for x in yaml.safe_load_all((HERE/'infrastructure.yaml').read_text()) if x['kind']=='Deployment')
        pod=deployment['spec']['template']['spec'];nodes=pod['affinity']['nodeAffinity']['requiredDuringSchedulingIgnoredDuringExecution']['nodeSelectorTerms'][0]['matchExpressions'][0]['values']
        self.assertEqual(nodes,['uc-k8sp4','uc-k8sp5'])
        self.assertTrue(pod['containers'][0]['securityContext']['readOnlyRootFilesystem'])

if __name__=='__main__':unittest.main()
