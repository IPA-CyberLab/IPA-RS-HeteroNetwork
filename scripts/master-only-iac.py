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
    env['KUBECONFIG']=env['TF_VAR_kubeconfig_path']
    env.setdefault('HNN_IAC_BECOME_PASSWORD',getpass.getpass('sudo password: ') if not env.get('HNN_IAC_BECOME_PASSWORD') else env['HNN_IAC_BECOME_PASSWORD'])
    work=Path(env['TF_VAR_work_dir']).expanduser().resolve()
    work.mkdir(parents=True,exist_ok=True)
    work.chmod(0o700)
    inventory=work/'inventory.json'
    env['ANSIBLE_CALLBACK_PLUGINS']=str(MODULE/'ansible/callback_plugins')
    env['ANSIBLE_STDOUT_CALLBACK']='hnn_json'
    nodes=json.loads((MODULE/'nodes.json').read_text())
    standard_nodes=json.loads((MODULE/'standard-nodes.json').read_text())
    drift=list(nodes) if args.reconcile_all or not inventory.exists() else []
    standard_drift=list(standard_nodes) if args.reconcile_all or not inventory.exists() else []
    database_drift=args.reconcile_all or not inventory.exists()
    gpu_host_drift=args.reconcile_all or not inventory.exists()
    gpu_acceptance_drift=args.reconcile_all or not inventory.exists()
    gpu_inventory_drift=args.reconcile_all or not inventory.exists()
    gpu_inventory_acceptance_drift=args.reconcile_all or not inventory.exists()
    flash_crd_acceptance_drift=args.reconcile_all or not inventory.exists()
    git_drift=args.reconcile_all or not inventory.exists()
    console_drift=args.reconcile_all or not inventory.exists()
    onboarding_drift=args.reconcile_all or not inventory.exists()
    if inventory.exists() and not args.reconcile_all:
        inventory_api=subprocess.run(
            ['kubectl','get','crd','flashgpudevices.flash.heterocloud.io','-o','name'],
            env=env,text=True,capture_output=True)
        inventory_playbooks=[]
        if inventory_api.returncode == 0:
            inventory_playbooks=[('gpu-inventory.yaml','gpu-inventory-check.log')]
        elif 'not found' in inventory_api.stderr.lower() or 'notfound' in inventory_api.stderr.lower():
            gpu_inventory_drift=True
            gpu_inventory_acceptance_drift=True
        else:
            raise RuntimeError('Unable to inspect the Flash GPU inventory API: '+inventory_api.stderr.strip())
        for playbook,logname in [('masters.yaml','host-check.log'),('standard.yaml','standard-check.log'),('database-ha.yaml','database-ha-check.log'),('gpu.yaml','gpu-check.log'),*inventory_playbooks,('console/configure.yaml','console-check.log'),('git-source.yaml','git-check.log')]:
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
            elif playbook=='standard.yaml':
                standard_drift=[name for name,stats in report['hosts'].items() if name in standard_nodes and stats['changed']]
            elif playbook=='database-ha.yaml':
                database_drift=any(stats['changed'] for stats in report['hosts'].values())
            elif playbook=='gpu.yaml':
                gpu_host_drift=any(stats['changed'] for stats in report['hosts'].values())
            elif playbook=='gpu-inventory.yaml':
                gpu_inventory_drift=any(stats['changed'] for stats in report['hosts'].values())
            elif playbook=='console/configure.yaml':
                console_drift=any(stats['changed'] for stats in report['hosts'].values())
            else:
                git_drift=any(stats['changed'] for stats in report['hosts'].values())
        result=subprocess.run(['python3',str(ROOT/'scripts/accept-registered-nodes.py'),
                               '--work-dir',str(work),'--branch',env.get('TF_VAR_git_revision','master'),
                               '--check'],env=env,text=True,capture_output=True)
        log=work/'onboarding-check.log'
        log.write_text(result.stdout+result.stderr)
        log.chmod(0o600)
        if result.returncode not in [0,2]:
            raise RuntimeError('Onboarding proof check failed; see private onboarding-check.log')
        onboarding_drift=result.returncode==2
        result=subprocess.run(['python3',str(ROOT/'scripts/verify-gpu-runtime.py'),
                               '--require-node','uc-k8sp5=2',
                               '--require-type','uc-k8sp5=nvidia-geforce-gtx-1080-ti',
                               '--check'],env=env,text=True,capture_output=True)
        log=work/'gpu-acceptance-check.log'
        log.write_text(result.stdout+result.stderr)
        log.chmod(0o600)
        if result.returncode not in [0,2]:
            raise RuntimeError('GPU acceptance check failed; see private gpu-acceptance-check.log')
        gpu_acceptance_drift=result.returncode==2
        if inventory_api.returncode == 0:
            result=subprocess.run(['python3',str(ROOT/'scripts/verify_gpu_inventory.py'),
                                   '--require-node','uc-k8sp5=2',
                                   '--require-type','uc-k8sp5=nvidia-geforce-gtx-1080-ti',
                                   '--check'],env=env,text=True,capture_output=True)
            log=work/'gpu-inventory-acceptance-check.log'
            log.write_text(result.stdout+result.stderr)
            log.chmod(0o600)
            if result.returncode not in [0,2]:
                raise RuntimeError('GPU inventory acceptance check failed; see private gpu-inventory-acceptance-check.log')
            gpu_inventory_acceptance_drift=result.returncode==2
        result=subprocess.run(['python3',str(ROOT/'scripts/verify_flash_crds.py'),'--check'],
                              env=env,text=True,capture_output=True)
        log=work/'flash-crd-acceptance-check.log'
        log.write_text(result.stdout+result.stderr)
        log.chmod(0o600)
        if result.returncode not in [0,2]:
            raise RuntimeError('Flash CRD acceptance check failed; see private flash-crd-acceptance-check.log')
        flash_crd_acceptance_drift=result.returncode==2
        print(json.dumps({'host_drift':drift,'standard_host_drift':standard_drift,'database_ha_drift':database_drift,'gpu_host_drift':gpu_host_drift,'gpu_acceptance_drift':gpu_acceptance_drift,'gpu_inventory_drift':gpu_inventory_drift,'gpu_inventory_acceptance_drift':gpu_inventory_acceptance_drift,'flash_crd_acceptance_drift':flash_crd_acceptance_drift,'console_drift':console_drift,'onboarding_drift':onboarding_drift,'git_source_drift':git_drift}))
    if args.action=='check':
        return 2 if drift or standard_drift or database_drift or gpu_host_drift or gpu_acceptance_drift or gpu_inventory_drift or gpu_inventory_acceptance_drift or flash_crd_acceptance_drift or console_drift or onboarding_drift or git_drift else 0
    tf=[args.terraform,'-chdir='+str(MODULE)]
    subprocess.run(tf+['init','-input=false'],env=env,check=True)
    replace=['-replace=terraform_data.host_configuration['+json.dumps(name)+']' for name in drift]
    replace += ['-replace=terraform_data.standard_host_configuration['+json.dumps(name)+']' for name in standard_drift]
    if database_drift:
        replace.append('-replace=terraform_data.database_ha_configuration')
    if gpu_host_drift:
        replace.append('-replace=terraform_data.gpu_host_configuration')
    if gpu_acceptance_drift:
        replace.append('-replace=terraform_data.gpu_acceptance')
    if gpu_inventory_drift:
        replace.append('-replace=terraform_data.gpu_inventory_configuration')
    if gpu_inventory_acceptance_drift:
        replace.append('-replace=terraform_data.gpu_inventory_acceptance')
    if flash_crd_acceptance_drift:
        replace.append('-replace=terraform_data.flash_crd_acceptance')
    if git_drift:
        replace.append('-replace=terraform_data.git_source')
    if console_drift:
        replace.append('-replace=terraform_data.console_configuration')
    if onboarding_drift:
        replace.append('-replace=terraform_data.onboarding_acceptance')
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
