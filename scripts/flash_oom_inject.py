#!/usr/bin/env python3
"""Protected SSH transport for the nonce-owned E2E memory fault only."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--inventory',required=True)
    parser.add_argument('--key',required=True)
    parser.add_argument('--node',required=True)
    args=parser.parse_args()
    request=json.loads(sys.stdin.readline(8192))
    def find(value):
        if isinstance(value,dict):
            if isinstance(value.get(args.node),dict) and value[args.node].get('ansible_host'):return value[args.node]
            for item in value.values():
                found=find(item)
                if found:return found
        return None
    inventory=json.loads(Path(args.inventory).read_text())
    entry=find(inventory)
    if not entry:raise RuntimeError('unknown_worker')
    password=os.environ['HNN_E2E_SUDO_PASSWORD']
    code=Path(__file__).with_name('flash_oom_inject_host.py').read_text()
    command=['ssh','-i',args.key,'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=7',
             *shlex.split(entry.get('ansible_ssh_common_args',inventory.get('all',{}).get('vars',{}).get('ansible_ssh_common_args',''))),'mizuame@'+entry['ansible_host'],
             'sudo -S -p "" python3 -c '+shlex.quote(code)]
    result=subprocess.run(command,input=password+'\n'+json.dumps(request)+'\n',capture_output=True,text=True,timeout=25)
    if result.returncode:raise RuntimeError('protected_memory_probe_failed')
    receipt=json.loads(result.stdout)
    print(json.dumps(receipt))


if __name__=='__main__':
    try:main()
    except (OSError,KeyError,ValueError,RuntimeError,subprocess.TimeoutExpired):
        raise SystemExit('Protected E2E memory probe failed') from None
