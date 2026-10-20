#!/usr/bin/env python3
"""Exercise concurrent real kubelet snapshots under a 256 MiB gVisor limit.

Creates only a disposable namespace, read-only RBAC and a short-lived cached-image
probe. No user Pod, disk or Secret is written. Only bounded aggregate evidence is
exported; the snapshot drops environment values and unrelated Pod metadata.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time
import uuid


PROBE = r'''
import concurrent.futures,json,resource,threading,time
from capacity import Guard,Kube
class ReadOnlyKube(Kube):
 def __init__(self):super().__init__();self.node_lists=0;self.counter=threading.Lock()
 def call(self,path,method='GET',value=None):
  assert method=='GET'
  if path=='/api/v1/nodes':
   with self.counter:self.node_lists+=1
  return super().call(path,method,value)
kube=ReadOnlyKube();guard=Guard(kube)
started=time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
 snapshots=list(pool.map(lambda _:guard.snapshot(),range(128)))
assert all(s is snapshots[0] for s in snapshots)
assert kube.node_lists==1
rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024
assert rss<256*1024**2
print(json.dumps({'passed':True,'concurrent_requests':128,'workers':32,'snapshot_refreshes':kube.node_lists,'pod_count':len(snapshots[0][1]),'peak_rss_bytes':rss,'duration_seconds':round(time.monotonic()-started,3)}),flush=True)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--capacity-source", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--node", default="uc-k8sp4")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if "@sha256:" not in args.image:raise SystemExit("A pinned cached image is required")
    nonce = uuid.uuid4().hex
    name = "flash-capacity-e2e-"+nonce[:12]
    label = {"operations-e2e/run": nonce}
    command = [args.kubectl, "--kubeconfig="+args.kubeconfig, "--request-timeout=15s"]
    created = []
    report = {"result": "incomplete", "namespace": name, "cleanup": {}}

    def kube(*parts, value=None):
        result = subprocess.run(command+list(parts), input=json.dumps(value) if value else None, capture_output=True, text=True, timeout=30)
        if result.returncode:raise RuntimeError("isolated_probe_kubernetes_operation_failed")
        return json.loads(result.stdout) if result.stdout.lstrip().startswith("{") else None

    def create(value):
        value["metadata"]["labels"] = label
        result = kube("create", "-f", "-", "-o", "json", value=value)
        created.append((value["kind"], value["metadata"]["name"], value["metadata"].get("namespace"), result["metadata"]["uid"]))

    try:
        node = kube("get", "node", args.node, "-o", "json")
        if node["metadata"]["labels"].get("heteronetwork.io/control-plane-only") == "true":raise RuntimeError("dedicated_master_forbidden")
        if not any(n.endswith(args.image.split('@')[1]) for image in node["status"]["images"] for n in image["names"]):raise RuntimeError("probe_image_not_cached")
        create({"apiVersion":"v1","kind":"Namespace","metadata":{"name":name}})
        create({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":name,"namespace":name}})
        create({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRole","metadata":{"name":name},"rules":[{"apiGroups":[""],"resources":["nodes","pods"],"verbs":["get","list"]},{"apiGroups":[""],"resources":["nodes/proxy"],"verbs":["get"]}]})
        create({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"ClusterRoleBinding","metadata":{"name":name},"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"ClusterRole","name":name},"subjects":[{"kind":"ServiceAccount","name":name,"namespace":name}]})
        create({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":name,"namespace":name},"data":{"capacity.py":args.capacity_source.read_text(),"probe.py":PROBE}})
        create({"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":name},"spec":{"runtimeClassName":"gvisor","serviceAccountName":name,"restartPolicy":"Never","nodeSelector":{"kubernetes.io/hostname":args.node},"containers":[{"name":"probe","image":args.image,"imagePullPolicy":"Never","command":["python3","-B","/probe/probe.py"],"env":[{"name":"FLASH_WORKLOAD_NAMESPACE","value":"heterocloud-flash-workloads"}],"resources":{"requests":{"cpu":"50m","memory":"64Mi","ephemeral-storage":"64Mi"},"limits":{"cpu":"500m","memory":"256Mi","ephemeral-storage":"64Mi"}},"securityContext":{"readOnlyRootFilesystem":True,"allowPrivilegeEscalation":False,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"probe","mountPath":"/probe","readOnly":True}]}],"volumes":[{"name":"probe","configMap":{"name":name}}]}})
        deadline = time.monotonic()+180
        while time.monotonic()<deadline:
            pod = kube("-n", name, "get", "pod", name, "-o", "json")
            phase = pod.get("status", {}).get("phase")
            if phase=="Failed":raise RuntimeError("bounded_probe_failed")
            if phase=="Succeeded":break
            time.sleep(2)
        else:raise RuntimeError("bounded_probe_timed_out")
        result = subprocess.run(command+["-n",name,"logs",name], capture_output=True, text=True, timeout=20)
        metrics = json.loads(result.stdout)
        if not metrics.get("passed"):raise RuntimeError("bounded_probe_did_not_pass")
        report.update(result="passed",metrics=metrics)
    except Exception as error:
        report.update(result="failed",failure=error.args[0] if isinstance(error,RuntimeError) else "probe_operation_failed")
    finally:
        cleaned=True
        for kind, resource, namespace, uid in reversed(created):
            try:
                cmd=["-n",namespace] if namespace else []
                actual=kube(*cmd,"get",kind,resource,"-o","json","--ignore-not-found=true")
                if actual:
                    if actual["metadata"]["uid"]!=uid or any(actual["metadata"].get("labels",{}).get(k)!=v for k,v in label.items()):raise RuntimeError("foreign_cleanup_guard")
                    kube(*cmd,"delete",kind,resource,"--wait=false")
            except Exception:cleaned=False
        if cleaned:
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                if not kube("get","namespace",name,"-o","json","--ignore-not-found=true"):
                    break
                time.sleep(1)
            else:cleaned=False
        report["cleanup"]["namespace_deletion_verified"]=cleaned
        report["cleanup"]["fixture_deletion_submitted"]=cleaned
        if not cleaned:report["result"]="failed"
        descriptor=os.open(args.report,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(descriptor,"w") as output:json.dump(report,output,indent=2)
        print(json.dumps(report))
    return 0 if report["result"]=="passed" else 1


if __name__=="__main__":
    raise SystemExit(main())
