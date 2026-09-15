#!/usr/bin/env python3
"""Issue a short-lived node token using the existing issuer's local credential."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--output',required=True)
args=parser.parse_args()
target=Path(args.output)
target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
target.parent.chmod(0o700)
pid=subprocess.check_output(['systemctl','show','--value','-p','MainPID','heteronetwork-control-plane.service'],text=True).strip()
env=dict(s.split('=',1) for s in Path('/proc/'+pid+'/environ').read_bytes().decode().split('\0') if '=' in s)
credential=Path(env['CREDENTIALS_DIRECTORY'])/'node-enrollment-issuer.key'
with tempfile.TemporaryDirectory(prefix='sign-node-',dir=target.parent) as directory:
    key=Path(directory)/'issuer.key'
    key.write_bytes(credential.read_bytes())
    key.chmod(0o600)
    command=['/opt/heteronetwork/bin/ipars','token','create','--cluster-id',env['HETERONETWORK_CLUSTER_ID'],
             '--issuer-key-id',env['HETERONETWORK_NODE_ENROLLMENT_ISSUER_KEY_ID'],
             '--issuer-private-key-path',str(key),'--role','worker','--ttl-seconds','1800','--max-uses','1',
             '--tag','kubernetes-control-plane','--tag','kubernetes-ha-545a7a1911f9580a']
    for host in ['163.220.236.61','163.220.236.45']:
        command+=['--control-plane-bootstrap','https://'+host,'--signal-bootstrap','https://'+host,
                  '--stun-bootstrap','udp://'+host+':19444','--relay-bootstrap','udp://'+host+':18445',
                  '--web-ui-bootstrap','https://'+host]
    result=subprocess.run(command,capture_output=True,check=True)
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'wb') as output:output.write(result.stdout)
    target.chmod(0o600)
