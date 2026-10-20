import copy
import unittest
import flash_oom_inject_host as probe


class MemoryFaultScope(unittest.TestCase):
    def test_host_fence_rejects_every_foreign_or_nonfixture_identity(self):
        run='11111111-1111-4111-8111-111111111111';sid='22222222-2222-4222-8222-222222222222';uid='33333333-3333-4333-8333-333333333333'
        request={'run_id':run,'service_id':sid,'pod_uid':uid}
        pod={'metadata':{'uid':uid,'namespace':'heterocloud-flash-workloads','labels':{'flash.heterocloud.io/instance':sid}},'spec':{'nodeName':'worker','runtimeClassName':'gvisor','containers':[{'name':'workload','resources':{'limits':{'memory':'64Mi'}},'args':['/tmp/force-memory-pressure']}]}}
        service={'spec':{'service_instance_id':sid,'display_name':'operations-e2e-11111111-test','workload':{'metadata':{'run_id':run,'purpose':'isolated-operations-e2e'}}}}
        self.assertEqual(probe.validate(pod,service,request,'worker'),uid)
        for target,key,value in [('metadata','namespace','default'),('metadata','uid','44444444-4444-4444-8444-444444444444'),('metadata','deletionTimestamp','2026-10-20T00:00:00Z'),('spec','nodeName','other'),('spec','runtimeClassName','runc')]:
            changed=copy.deepcopy(pod);changed[target][key]=value
            with self.assertRaises(RuntimeError):probe.validate(changed,service,request,'worker')
        changed=copy.deepcopy(service);changed['spec']['display_name']='production'
        with self.assertRaises(RuntimeError):probe.validate(pod,changed,request,'worker')
        changed=copy.deepcopy(service);changed['spec']['workload']['metadata']['run_id']='another-run'
        with self.assertRaises(RuntimeError):probe.validate(pod,changed,request,'worker')


if __name__=='__main__':unittest.main()
