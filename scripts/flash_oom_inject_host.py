#!/usr/bin/env python3
"""Fence swap only on a nonce-owned E2E VM's existing memory cgroup.

Run through the protected E2E SSH driver. This changes no host swap setting,
service configuration, other Pod, volume or application data. The cgroup is
removed automatically with the disposable Pod. It never changes memory.max.
"""
import glob
import json
from pathlib import Path
import socket
import subprocess
import sys
import uuid


def require(value):
    if not value:raise RuntimeError("memory_injection_scope_rejected")


def validate(pod, service, request, hostname):
    run=str(uuid.UUID(request["run_id"]))
    sid=str(uuid.UUID(request["service_id"]))
    uid=str(uuid.UUID(request["pod_uid"]))
    require(pod["metadata"]["uid"]==uid and not pod["metadata"].get("deletionTimestamp"))
    require(pod["metadata"]["namespace"]=="heterocloud-flash-workloads")
    require(pod["metadata"].get("labels",{}).get("flash.heterocloud.io/instance")==sid)
    require(pod["spec"]["nodeName"]==hostname and pod["spec"].get("runtimeClassName")=="gvisor")
    require(service["spec"]["service_instance_id"]==sid)
    workload=service["spec"]["workload"]
    require(service["spec"]["display_name"].startswith("operations-e2e-"+run[:8]+"-"))
    require(workload.get("metadata",{}).get("run_id")==run and workload["metadata"].get("purpose")=="isolated-operations-e2e")
    container=next(c for c in pod["spec"]["containers"] if c["name"]=="workload")
    require(container["resources"]["limits"]["memory"]=="64Mi")
    require(any("/tmp/force-memory-pressure" in arg for arg in container.get("args",[])))
    return uid


def main():
    request=json.loads(sys.stdin.readline(8192))
    sid=str(uuid.UUID(request["service_id"]))
    base=["kubectl","--kubeconfig=/etc/kubernetes/admin.conf","-n","heterocloud-flash-workloads"]
    def get(kind,name):return json.loads(subprocess.check_output(base+["get",kind,name,"-o","json"],text=True,stderr=subprocess.DEVNULL))
    pod=get("pod",request["pod_name"]);service=get("flashservice","flash-"+sid)
    uid=validate(pod,service,request,socket.gethostname())
    suffix=uid.replace('-','_')
    paths=glob.glob('/sys/fs/cgroup/kubepods.slice/kubepods-pod'+suffix+'.slice')+glob.glob('/sys/fs/cgroup/kubepods.slice/kubepods-*.slice/kubepods-*-pod'+suffix+'.slice')
    require(len(paths)==1)
    path=Path(paths[0]);require((path/'memory.max').read_text().strip()==str(64*1024**2))
    before=(path/'memory.swap.max').read_text().strip()
    if request["action"]=="inject":
        # Recheck the API identity immediately before this single scoped write.
        validate(get("pod",request["pod_name"]),service,request,socket.gethostname())
        (path/'memory.swap.max').write_text('0')
    else:require(request["action"]=="observe")
    events=dict(line.split() for line in (path/'memory.events').read_text().splitlines())
    print(json.dumps({"pod_uid":uid,"memory_max_bytes":64*1024**2,"swap_limit_before":before,
                      "swap_limit_now":(path/'memory.swap.max').read_text().strip(),"kernel_oom_kills":int(events.get('oom_kill',0)),
                      "only_disposable_cgroup_modified":True}))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,RuntimeError,StopIteration,subprocess.CalledProcessError):
        raise SystemExit('Owned E2E memory fault injection failed') from None
