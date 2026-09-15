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
args = parser.parse_args()
root = Path('/etc/heteronetwork/postgres-autopilot')
bundle = root / 'bundle'
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
    raise SystemExit('A full database member is already configured; client bootstrap is unnecessary')
manifest = dict(line.split('=', 1) for line in (bundle / 'manifest.env').read_text().splitlines() if '=' in line)
# Existing members publish authenticated client/health endpoints over the overlay.
# Their underlying database replication and DCS addresses remain in the bundle.
client_addresses = {'db-a': '10.250.0.10', 'db-b': '10.250.0.2'}
backends = ','.join(name + '=' + client_addresses.get(name, address)
                    for name, address in (entry.split('=', 1) for entry in manifest['HETERONETWORK_DB_MEMBERS'].split(',')))
env = os.environ.copy()
env.update(manifest)
env.update(HETERONETWORK_DB_BUNDLE_DIR=str(bundle), HETERONETWORK_DB_PROXY_BACKENDS=backends,
           HETERONETWORK_DB_PROXY_LISTEN_ADDRESS=args.ip)
with Path('/var/backups/heteronetwork/iac-standard/database-proxy.log').open('w') as log:
    os.chmod(log.name, 0o600)
    subprocess.run(['/opt/heteronetwork/libexec/postgres-ha-node.sh', 'install-proxy'], env=env,
                   stdout=log, stderr=subprocess.STDOUT, check=True)
