#!/usr/bin/env python3
"""Apply Terraform and reconcile observed host drift through its Ansible resources."""
import argparse
import getpass
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'deploy/terraform/master-only'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action',choices=['plan','apply','check'])
    parser.add_argument('--reconcile-all',action='store_true',help='Reconfigure every host, including cleaned hosts.')
    parser.add_argument('--terraform',default='terraform')
    args=parser.parse_args()
    env=os.environ.copy()
    for key in ['TF_VAR_work_dir','TF_VAR_ssh_private_key_path','TF_VAR_kubeconfig_path']:
        if not env.get(key):
            parser.error(key+' is required')
    env['KUBE_CONFIG_PATH']=env['TF_VAR_kubeconfig_path']
    env.setdefault('HNN_IAC_BECOME_PASSWORD',getpass.getpass('sudo password: ') if not env.get('HNN_IAC_BECOME_PASSWORD') else env['HNN_IAC_BECOME_PASSWORD'])
    work=Path(env['TF_VAR_work_dir']).expanduser().resolve()
    work.mkdir(parents=True,exist_ok=True)
    work.chmod(0o700)
    inventory=work/'inventory.json'
    env['ANSIBLE_CALLBACK_PLUGINS']=str(MODULE/'ansible/callback_plugins')
    env['ANSIBLE_STDOUT_CALLBACK']='hnn_json'
    nodes=json.loads((MODULE/'nodes.json').read_text())
    drift=list(nodes) if args.reconcile_all or not inventory.exists() else []
    git_drift=args.reconcile_all or not inventory.exists()
    if inventory.exists() and not args.reconcile_all:
        for playbook,logname in [('masters.yaml','host-check.log'),('git-source.yaml','git-check.log')]:
            command=['ansible-playbook','-i',str(inventory),'--check',str(MODULE/'ansible'/playbook)]
            result=subprocess.run(command,env=env,text=True,capture_output=True)
            log=work/logname
            log.write_text(result.stdout+result.stderr)
            log.chmod(0o600)
            try:
                report=json.loads(result.stdout.strip().splitlines()[-1])
            except (json.JSONDecodeError,IndexError):
                raise RuntimeError('Ansible check failed; see the private '+logname)
            if result.returncode:
                print(json.dumps(report),file=sys.stderr)
                raise RuntimeError('Host check failed. For cleaned hosts use --reconcile-all.')
            if playbook=='masters.yaml':
                drift=[name for name,stats in report['hosts'].items() if name in nodes and stats['changed']]
            else:
                git_drift=any(stats['changed'] for stats in report['hosts'].values())
        print(json.dumps({'host_drift':drift,'git_source_drift':git_drift}))
    if args.action=='check':
        return 2 if drift or git_drift else 0
    tf=[args.terraform,'-chdir='+str(MODULE)]
    subprocess.run(tf+['init','-input=false'],env=env,check=True)
    replace=['-replace=terraform_data.host_configuration['+json.dumps(name)+']' for name in drift]
    if git_drift:
        replace.append('-replace=terraform_data.git_source')
    plan=work/'master-only.tfplan'
    result=subprocess.run(tf+['plan','-input=false','-parallelism=1','-detailed-exitcode','-out='+str(plan),*replace],env=env)
    if plan.exists():
        plan.chmod(0o600)
    if result.returncode not in [0,2]:
        return result.returncode
    if args.action=='plan':
        return result.returncode
    subprocess.run(tf+['apply','-input=false','-parallelism=1',str(plan)],env=env,check=True)
    return 0


if __name__=='__main__':
    try:
        sys.exit(main())
    except (RuntimeError,subprocess.CalledProcessError) as exc:
        print(str(exc),file=sys.stderr)
        sys.exit(1)
