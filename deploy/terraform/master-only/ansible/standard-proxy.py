#!/usr/bin/env python3
"""Bootstrap a standard host's client proxy from the existing private bundle."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--ip', required=True)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
root = Path('/etc/heteronetwork/postgres-autopilot')
bundle = root / 'bundle'
if not bundle.exists() and args.check:
    print(json.dumps({'changed': True}))
    raise SystemExit(0)
if not bundle.exists():
    with tempfile.TemporaryDirectory(prefix='iac-proxy-', dir=root) as work:
        stage = Path(work) / 'bundle'
        stage.mkdir(mode=0o700)
        with tarfile.open('/var/backups/heteronetwork/iac-standard/database-proxy.tar.gz') as archive:
            archive.extractall(stage, filter='data')
        expected = {'.proxy-only', 'manifest.env', 'cluster-id', 'ca/ca.crt', 'secrets/application.password'}
        assert {str(p.relative_to(stage)) for p in stage.rglob('*') if p.is_file()} == expected
        assert (stage / '.proxy-only').read_text().strip() == '1'
        state = json.loads(Path('/var/lib/heteronetwork/agent.json').read_text())
        assert (stage / 'cluster-id').read_text().strip() == state['registered_node']['cluster_id']
        os.rename(stage, bundle)
if not (bundle / '.proxy-only').exists():
    print(json.dumps({'changed': False, 'mode': 'member'}))
    raise SystemExit(0)
manifest = dict(line.split('=', 1) for line in (bundle / 'manifest.env').read_text().splitlines() if '=' in line)
# Existing members publish authenticated client/health endpoints over the overlay.
# Their underlying database replication and DCS addresses remain in the bundle.
client_addresses = {'db-b': '10.250.0.2', 'db-e': '10.250.0.11'}
backends = ','.join(name + '=' + client_addresses.get(name, address)
                    for name, address in (entry.split('=', 1) for entry in manifest['HETERONETWORK_DB_MEMBERS'].split(',')))
env = os.environ.copy()
env.update(manifest)
env.update(HETERONETWORK_DB_BUNDLE_DIR=str(bundle), HETERONETWORK_DB_PROXY_BACKENDS=backends,
           HETERONETWORK_DB_PROXY_LISTEN_ADDRESS=args.ip)
helper = '/opt/heteronetwork/libexec/postgres-ha-node.sh'
expected = subprocess.check_output([helper, 'render-proxy-config'], env=env)
config = Path('/etc/heteronetwork/postgres-ha/haproxy.cfg')
ca = Path('/etc/heteronetwork/postgres-ha/pki/ca.crt')
changed = (not config.exists() or config.read_bytes() != expected or not ca.exists()
           or ca.read_bytes() != (bundle / 'ca/ca.crt').read_bytes())
if changed and not args.check:
    with Path('/var/backups/heteronetwork/iac-standard/database-proxy.log').open('w') as log:
        os.chmod(log.name, 0o600)
        subprocess.run([helper, 'install-proxy'], env=env,
                       stdout=log, stderr=subprocess.STDOUT, check=True)
print(json.dumps({'changed': changed, 'mode': 'client-proxy'}))
