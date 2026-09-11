#!/usr/bin/env python3
"""Reclaim only the detached volume from the completed DEV Flash lifecycle fixture."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import time

NS = 'heterocloud-flash-dev-workloads'
INSTANCE = 'da8841e7-5621-4a8f-8730-8754cb321c79'
CLAIM = 'flash-' + INSTANCE + '-home'
CLAIM_UID = '8955ede1-ea4b-40fb-9e9b-a03f9df94c7d'
PV = 'pvc-' + CLAIM_UID
PV_UID = '096e5db3-ce39-4c02-b02f-b12beda86c73'
VOLUME_UID = 'a0e7cf50-18b6-4ffb-b971-09f66251484f'


def require(value):
    if not value:
        raise ValueError('DEV fixture volume cleanup rejected')


def validate(pv, volume):
    if pv:
        require(pv['metadata']['name'] == PV and pv['metadata']['uid'] == PV_UID)
        spec = pv['spec']
        require(spec['claimRef']['namespace'] == NS and spec['claimRef']['name'] == CLAIM
                and spec['claimRef']['uid'] == CLAIM_UID and spec['storageClassName'] == 'dev-flash-rwx'
                and spec['persistentVolumeReclaimPolicy'] in ('Retain', 'Delete')
                and spec['csi']['driver'] == 'driver.longhorn.io' and spec['csi']['volumeHandle'] == PV
                and pv['status']['phase'] == 'Released')
    if volume:
        require(volume['metadata']['name'] == PV and volume['metadata']['uid'] == VOLUME_UID
                and volume['spec']['nodeID'] == '' and volume['status']['currentNodeID'] == ''
                and volume['status']['state'] in ('detached', 'deleting')
                and volume['status']['kubernetesStatus']['namespace'] == NS
                and volume['status']['kubernetesStatus']['pvcName'] == CLAIM
                and volume['status']['kubernetesStatus']['pvName'] == PV)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    path = Path('/opt/heteronetwork-dev-identity/apply.py')
    require(hashlib.sha256(path.read_bytes()).hexdigest() ==
            '0b396e7873f6970433b893c6ab04ea33bddc84bb6bfa02f0e129343dc16ae006')
    spec = importlib.util.spec_from_file_location('identity_apply', path)
    h = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(h)
    h.guard()

    def get(kind, name=None, namespace=None):
        raw = h.run(['get', kind, *([name, '--ignore-not-found'] if name else []),
                     *(['-n', namespace] if namespace else []), '-o', 'json'])
        return json.loads(raw) if raw.strip() else None

    require(get('pvc', CLAIM, NS) is None and get('flashservices.flash.heterocloud.io', 'flash-' + INSTANCE, NS) is None)
    require(not any(p['metadata'].get('labels', {}).get('flash.heterocloud.io/instance') == INSTANCE
                    for p in get('pods', namespace=NS)['items']))
    before = {v['metadata']['uid'] for v in get('volumes.longhorn.io', namespace='longhorn-system')['items']
              if v['metadata']['name'] != PV}
    pv = get('pv', PV)
    volume = get('volumes.longhorn.io', PV, 'longhorn-system')
    validate(pv, volume)
    require(pv is not None or volume is None or volume['metadata'].get('deletionTimestamp'))
    if args.apply and pv and pv['spec']['persistentVolumeReclaimPolicy'] == 'Retain':
        patch = [{'op': 'test', 'path': '/metadata/' + k, 'value': pv['metadata'][k]}
                 for k in ('uid', 'resourceVersion')]
        patch += [{'op': 'test', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Retain'},
                  {'op': 'replace', 'path': '/spec/persistentVolumeReclaimPolicy', 'value': 'Delete'}]
        h.run(['patch', 'pv', PV, '--type=json', '-p', json.dumps(patch)])
    if args.apply:
        deadline = time.monotonic() + 180
        while get('pv', PV) or get('volumes.longhorn.io', PV, 'longhorn-system'):
            require(time.monotonic() < deadline)
            time.sleep(3)
        for kind in ('replicas.longhorn.io', 'engines.longhorn.io'):
            require(not any(r['spec']['volumeName'] == PV for r in get(kind, namespace='longhorn-system')['items']))
        require(before.issubset({v['metadata']['uid'] for v in get('volumes.longhorn.io', namespace='longhorn-system')['items']}))
        h.guard()
    print(json.dumps({'applied': args.apply, 'fixture_pv': PV, 'volume_removed': args.apply,
                      'other_volume_uids_preserved': len(before), 'finalizers_modified': False}), flush=True)


if __name__ == '__main__':
    main()
