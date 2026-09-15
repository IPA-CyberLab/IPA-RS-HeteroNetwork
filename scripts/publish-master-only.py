#!/usr/bin/env python3
"""Build a scoped infrastructure commit and bundle without staging unrelated edits."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def files():
    paths=['.gitignore','scripts/kubeadm-ha-node.sh','scripts/master-only-iac.py',
           'scripts/verify-master-only.py','scripts/publish-master-only.py',
           'deploy/kubernetes/control-plane-only-policy.yaml',
           'deploy/environments/heteronet/values.yaml','deploy/gitops/project.yaml']
    paths += ['deploy/gitops/applications/'+n+'.yaml' for n in
              ['cluster-dns','network-policy-engine','longhorn-prerequisites','flash-web','heterocloud-edge']]
    paths += ['deploy/gitops/cluster-dns/nodelocaldns.yaml','deploy/gitops/cluster-dns/keycloak-ha-connector.yaml',
              'deploy/gitops/cluster-dns/postgres-ha-connector.yaml','deploy/gitops/cluster-dns/service-route.yaml',
              'deploy/gitops/network-policy-engine/kube-router.yaml','deploy/gitops/longhorn-prerequisites/node-prerequisites.yaml',
              'deploy/gitops/flash-web/tls-sync-daemonset.yaml','deploy/gitops/envoy-gateway/redis-primary-proxy.yaml']
    for directory in ['deploy/terraform/master-only','deploy/gitops/control-plane-only']:
        for p in (ROOT/directory).rglob('*'):
            if not p.is_file() or '.terraform' in p.parts or '__pycache__' in p.parts: continue
            if p.suffix in ['.tf','.py','.yaml','.j2','.json','.md'] or p.name=='.terraform.lock.hcl':
                paths.append(str(p.relative_to(ROOT)))
    return sorted(set(paths))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--work-dir',required=True)
    parser.add_argument('--branch',default='codex/master-only-iac-20260915')
    args=parser.parse_args()
    work=Path(args.work_dir).expanduser().resolve()
    work.mkdir(parents=True,exist_ok=True)
    work.chmod(0o700)
    paths=files()
    for path in paths:
        text=(ROOT/path).read_text()
        assert not re.search(r'(?m)^-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----$',text)
    subprocess.run(['python3',str(ROOT/'deploy/terraform/master-only/render.py')],cwd=ROOT,check=True)
    env=os.environ.copy()
    env.update({'GIT_AUTHOR_NAME':'Codex','GIT_AUTHOR_EMAIL':'codex@localhost',
                'GIT_COMMITTER_NAME':'Codex','GIT_COMMITTER_EMAIL':'codex@localhost'})
    def git(*cmd): return subprocess.check_output(['git',*cmd],cwd=ROOT,env=env,text=True).strip()
    ref='refs/heads/'+args.branch
    previous=subprocess.run(['git','rev-parse','--verify',ref],cwd=ROOT,text=True,capture_output=True)
    parent=previous.stdout.strip() if previous.returncode==0 else git('rev-parse','HEAD')
    with tempfile.TemporaryDirectory(prefix='hnn-iac-index-',dir=work) as tmp:
        env['GIT_INDEX_FILE']=str(Path(tmp)/'index')
        git('read-tree',parent)
        git('add','--',*paths)
        tree=git('write-tree')
        if tree==git('rev-parse',parent+'^{tree}'): commit=parent
        else: commit=git('commit-tree',tree,'-p',parent,'-m','Manage dedicated masters with Terraform and Argo CD')
        git('update-ref',ref,commit,previous.stdout.strip() if previous.returncode==0 else '0'*40)
        git('bundle','create',str(work/'infrastructure.bundle'),ref)
    (work/'infrastructure.bundle').chmod(0o600)
    print(json.dumps({'commit':commit,'branch':args.branch,'files':len(paths),'bundle':str(work/'infrastructure.bundle')}))


if __name__=='__main__': main()
