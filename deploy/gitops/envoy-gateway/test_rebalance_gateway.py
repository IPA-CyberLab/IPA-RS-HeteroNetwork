import copy
import datetime
import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('rebalance',Path(__file__).with_name('rebalance-gateway.py'))
rebal=importlib.util.module_from_spec(spec)
spec.loader.exec_module(rebal)


class RebalanceTests(unittest.TestCase):
    def setUp(self):
        self.now=1800000000.0
        def ts(offset):return datetime.datetime.fromtimestamp(self.now+offset,datetime.timezone.utc).isoformat()
        self.ts=ts
        self.deploy={'metadata':{'name':rebal.DEPLOYMENT,'generation':1},'spec':{'replicas':5,'template':{'spec':{
            'topologySpreadConstraints':[{'topologyKey':'kubernetes.io/hostname','maxSkew':1,
             'whenUnsatisfiable':'DoNotSchedule','nodeTaintsPolicy':'Honor','nodeAffinityPolicy':'Honor'}]}}},
            'status':{'observedGeneration':1,'replicas':5,'readyReplicas':5,'updatedReplicas':5,'availableReplicas':5}}
        self.pdb={'status':{'disruptionsAllowed':2}}
        self.nodes={name:{'metadata':{'labels':{'networking.heteronetwork.io/public-ingress-candidate':'true'}},
            'spec':{},'status':{'conditions':[{'type':'Ready','status':'True','lastTransitionTime':ts(-300)}]}} for name in rebal.NODES}
        self.leases={name:{'spec':{'renewTime':ts(-5)}} for name in rebal.NODES}
        self.quorum={'enabled':True,'observed_at':self.now-3,'fresh_voters':2,'majority_required':2,
            'published_targets':['one','two'],'origins':{name:{'decision':'healthy','active':True} for name in rebal.NODES}}
        self.pods=[]
        for index,name in enumerate([rebal.NODES[0]]*4+[rebal.NODES[1]]):
            self.pods.append({'metadata':{'name':rebal.DEPLOYMENT+'-pod-'+str(index),'uid':str(index),
                'ownerReferences':[{'kind':'ReplicaSet','controller':True,'name':rebal.DEPLOYMENT+'-replicaset'}]},
                'spec':{'nodeName':name},'status':{'phase':'Running','conditions':[{'type':'Ready','status':'True'}]}})

    def select(self):
        return rebal.candidate(self.deploy,self.pdb,self.pods,self.nodes,self.leases,self.quorum,self.now)

    def test_one_pod_is_selected_from_overrepresented_worker(self):
        self.assertEqual(self.select(),{'name':rebal.DEPLOYMENT+'-pod-0','uid':'0'})

    def test_balanced_placement_needs_no_eviction(self):
        self.pods[0]['spec']['nodeName']=rebal.NODES[1]
        self.assertIsNone(self.select())

    def test_refuses_when_quorum_or_one_gateway_is_unhealthy(self):
        for change in ('stale','missing_majority','unhealthy','dns_missing','disabled'):
            original=copy.deepcopy(self.quorum)
            if change=='stale':self.quorum['observed_at']=self.now-31
            elif change=='missing_majority':self.quorum['fresh_voters']=1
            elif change=='unhealthy':self.quorum['origins'][rebal.NODES[0]]['decision']='unknown'
            elif change=='dns_missing':self.quorum['published_targets']=['one']
            else:self.quorum['enabled']=False
            with self.subTest(change=change):self.assertIsNone(self.select())
            self.quorum=original

    def test_refuses_during_node_failure_or_recent_recovery(self):
        for change in ('lease','notready','recent','cordoned','tainted','dedicated'):
            nodes,leases=copy.deepcopy(self.nodes),copy.deepcopy(self.leases)
            name=rebal.NODES[0]
            if change=='lease':self.leases[name]['spec']['renewTime']=self.ts(-31)
            elif change=='notready':self.nodes[name]['status']['conditions'][0]['status']='False'
            elif change=='recent':self.nodes[name]['status']['conditions'][0]['lastTransitionTime']=self.ts(-30)
            elif change=='cordoned':self.nodes[name]['spec']['unschedulable']=True
            elif change=='tainted':self.nodes[name]['spec']['taints']=[{'key':'node.kubernetes.io/not-ready','effect':'NoExecute'}]
            else:self.nodes[name]['metadata']['labels']['heteronetwork.io/control-plane-only']='true'
            with self.subTest(change=change):self.assertIsNone(self.select())
            self.nodes,self.leases=nodes,leases

    def test_refuses_rollout_unhealthy_pod_and_pdb_block(self):
        self.deploy['status']['updatedReplicas']=4
        self.assertIsNone(self.select())
        self.deploy['status']['updatedReplicas']=5
        self.pods[0]['status']['conditions'][0]['status']='False'
        self.assertIsNone(self.select())
        self.pods[0]['status']['conditions'][0]['status']='True'
        self.pdb['status']['disruptionsAllowed']=0
        self.assertIsNone(self.select())

    def test_refuses_without_hard_spread_and_correct_controller(self):
        self.deploy['spec']['template']['spec']['topologySpreadConstraints'][0]['whenUnsatisfiable']='ScheduleAnyway'
        self.assertIsNone(self.select())
        self.deploy['spec']['template']['spec']['topologySpreadConstraints'][0]['whenUnsatisfiable']='DoNotSchedule'
        self.pods[0]['metadata']['ownerReferences'][0]['name']='unrelated'
        self.assertIsNone(self.select())


if __name__=='__main__':unittest.main()
