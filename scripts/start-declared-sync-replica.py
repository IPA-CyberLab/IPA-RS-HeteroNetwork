#!/usr/bin/env python3
"""Replace only the retired db-a process on its host, retaining its data.

The old service survived a previous DCS-only migration and reappeared at boot.
Its data is moved aside, never deleted, before the declared db-h clones the
current primary. A correctly configured db-h is simply started idempotently.
"""
import datetime
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import yaml


def require(ok):
    if not ok:raise RuntimeError('replica_identity_or_storage_validation_failed')


def main():
    require(os.geteuid()==0)
    bundle=Path('/etc/heteronetwork/postgres-autopilot/bundle')
    manifest=dict(line.split('=',1) for line in (bundle/'manifest.env').read_text().splitlines())
    identities=dict(row.split('=',1) for row in manifest['HETERONETWORK_DB_MEMBER_IDENTITIES'].split(','))
    state=json.loads(Path('/var/lib/heteronetwork/agent.json').read_text())
    require(identities['db-h']==state['node_id'] and state['vpn_ip']=='10.250.0.10')
    config=Path('/etc/heteronetwork/postgres-ha/patroni.yml')
    metadata=config.lstat();require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid==0)
    current=yaml.safe_load(config.read_text())
    require(current['scope']==manifest['HETERONETWORK_DB_CLUSTER_NAME'])
    require(current['postgresql']['connect_address']=='100.65.54.75:55432')
    if current['name']=='db-h':
        subprocess.run(['systemctl','start','heteronetwork-db.service'],check=True)
        print(json.dumps({'result':'already-configured','member':'db-h'}));return
    require(current['name']=='db-a')
    path=Path('/var/lib/heteronetwork-postgres-ha/postgres')
    require(current['postgresql']['data_dir']==str(path))
    if path.exists():require(path.is_dir() and not path.is_symlink())
    subprocess.run(['systemctl','stop','heteronetwork-db.service'],check=True)
    # A retired rewind process must not keep writing the directory being retained.
    processes=subprocess.check_output(['ps','-eo','pid=,comm=,args='],text=True)
    for line in processes.splitlines():
        parts=line.strip().split(None,2)
        if len(parts)==3 and parts[1] in ['pg_rewind','postgres'] and str(path) in parts[2]:
            raise RuntimeError('retired_database_process_has_not_stopped')
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup=Path('/var/backups/heteronetwork')/('retired-db-a-'+stamp)
    backup.mkdir(mode=0o700,parents=True,exist_ok=False)
    shutil.copy2(config,backup/'patroni.yml')
    if path.exists():os.rename(path,path.parent/('retired-db-a-'+stamp))
    env={**os.environ,**manifest,'HETERONETWORK_DB_BUNDLE_DIR':str(bundle),
         'HETERONETWORK_DB_NODE_NAME':'db-h','HETERONETWORK_DB_NODE_ADDRESS':'100.65.54.75',
         'HETERONETWORK_DB_INTERFACE':'tailscale0','HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS':'10.250.0.10',
         'HETERONETWORK_DB_PROXY_LISTEN_ADDRESS':'10.250.0.10','HETERONETWORK_DB_DCS_INITIAL_CLUSTER_STATE':'existing'}
    subprocess.run(['/opt/heteronetwork/libexec/postgres-ha-node.sh','install-node'],env=env,check=True)
    print(json.dumps({'result':'retired-data-preserved','member':'db-h','backup':str(backup)}))


if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('declared_sync_replica_start_failed; protected values withheld')
