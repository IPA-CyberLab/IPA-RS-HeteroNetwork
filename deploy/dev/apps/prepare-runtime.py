#!/usr/bin/env python3
"""Prepare immutable DEV chart manifests offline; never apply Kubernetes resources."""
import argparse
import copy
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'deploy/gitops/environments'))
import render


CLUSTER_SCOPES = {
    ('v1', 'Namespace'), ('v1', 'PersistentVolume'),
    ('apiextensions.k8s.io/v1', 'CustomResourceDefinition'),
    ('rbac.authorization.k8s.io/v1', 'ClusterRole'),
    ('rbac.authorization.k8s.io/v1', 'ClusterRoleBinding'),
    ('node.k8s.io/v1', 'RuntimeClass'), ('storage.k8s.io/v1', 'StorageClass'),
}
NAMESPACED_SCOPES = {
    ('v1', kind) for kind in ('ConfigMap', 'Secret', 'Service', 'ServiceAccount',
                             'PersistentVolumeClaim', 'Endpoints', 'Pod')
} | {
    ('apps/v1', 'Deployment'), ('apps/v1', 'StatefulSet'), ('apps/v1', 'DaemonSet'),
    ('batch/v1', 'Job'), ('batch/v1', 'CronJob'),
    ('rbac.authorization.k8s.io/v1', 'Role'),
    ('rbac.authorization.k8s.io/v1', 'RoleBinding'),
    ('networking.k8s.io/v1', 'NetworkPolicy'), ('networking.k8s.io/v1', 'Ingress'),
    ('policy/v1', 'PodDisruptionBudget'), ('autoscaling/v2', 'HorizontalPodAutoscaler'),
    ('discovery.k8s.io/v1', 'EndpointSlice'),
    ('gateway.networking.k8s.io/v1', 'HTTPRoute'),
    ('monitoring.coreos.com/v1', 'ServiceMonitor'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def read_input(path):
    require(path.is_file() and path.stat().st_size <= 16 * 1024 * 1024,
            'Input must be a bounded regular file')
    with path.open('rb') as stream:
        raw = stream.read(16 * 1024 * 1024 + 1)
    require(len(raw) <= 16 * 1024 * 1024, 'Input exceeds size limit')
    return json.loads(raw), digest(raw)


def normalize(documents, application):
    destination = application['spec']['destination']['namespace']
    allowed = {destination}
    if application['metadata']['name'] == 'heterocloud-flash-dev':
        allowed.add('heterocloud-flash-dev-workloads')
    resources, identities = [], set()
    for document in documents:
        if document is None:
            continue
        require(isinstance(document, dict), 'Resource must be an object')
        item = copy.deepcopy(document)
        scope = (item.get('apiVersion'), item.get('kind'))
        metadata = item.get('metadata')
        require(isinstance(metadata, dict) and isinstance(metadata.get('name'), str)
                and metadata['name'], 'Resource requires an explicit name')
        if scope in CLUSTER_SCOPES:
            require(not metadata.get('namespace'), 'Cluster-scoped resource has a namespace')
            metadata.pop('namespace', None)
            if scope == ('v1', 'Namespace'):
                require(metadata['name'] in allowed, 'Foreign Namespace resource')
        else:
            require(scope in NAMESPACED_SCOPES, 'Unknown resource scope')
            namespace = metadata.get('namespace', destination)
            require(namespace in allowed, 'Foreign resource namespace')
            metadata['namespace'] = namespace
        identity = (*scope, metadata.get('namespace', ''), metadata['name'])
        require(identity not in identities, 'Duplicate resource identity')
        identities.add(identity)
        resources.append(item)
    require(resources, 'Chart rendered no resources')
    return resources


def prepare(site_path, channels_path, repository_root):
    site, site_hash = read_input(site_path)
    state, channels_hash = read_input(channels_path)
    applications = render.render(state, 'dev', site)
    releases = render.selected(state, 'dev')
    require(set(releases) == set(render.COMPONENTS), 'All four DEV chart selections are required')
    collected = {}

    def inspect(application, documents):
        name = application['metadata']['name']
        require(name not in collected, 'Duplicate application')
        collected[name] = normalize(documents, application)

    # The callback precedes the renderer image checks. Publish nothing until
    # every chart, checkout, image and CA/owner validation has completed.
    render.check_helm(applications, state, 'dev', site, repository_root,
                      inspect_documents=inspect)
    files, entries = {}, {}
    require(set(collected) == {a['metadata']['name'] for a in applications},
            'Incomplete chart collection')
    for application in applications:
        name = application['metadata']['name']
        source = application['spec']['source']
        component = next(key for key, (chart, _) in render.COMPONENTS.items()
                         if name == chart + '-dev')
        filename = name + '.json'
        resources = collected[name]
        files[filename] = encode({'apiVersion': 'v1', 'kind': 'List', 'items': resources})
        entries[name] = {
            'file': filename, 'sha256': digest(files[filename]), 'resources': len(resources),
            'destination': application['spec']['destination'],
            'source': source, 'artifact': releases[component],
            'application_sha256': digest(encode(application)),
            'images': sorted({render.canonical_image(image)
                              for image in render.container_images(resources)}),
        }
    files['manifest.json'] = encode({
        'schema_version': 1, 'channel': 'dev', 'revision': state['revision'],
        'site_sha256': site_hash, 'channels_sha256': channels_hash,
        'cluster_uid': site['cluster_uid'], 'production_cluster_uid': site['production_cluster_uid'],
        'files': {name: digest(raw) for name, raw in files.items()},
        'components': releases,
        'applications': entries,
    })
    return files


def verify_existing(output, files):
    require(stat.S_ISDIR(output.lstat().st_mode), 'Output must be a real directory')
    require({p.name for p in output.iterdir()} == set(files), 'Existing output file set differs')
    for name, raw in files.items():
        path = output / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_size == len(raw), 'Existing output is not an exact regular file')
        require(path.read_bytes() == raw, 'Existing output content differs')


def publish(output, files):
    if os.path.lexists(output):
        verify_existing(output, files)
        return False
    require(output.parent.is_dir(), 'Output parent directory must already exist')
    staging = Path(tempfile.mkdtemp(prefix='.prepare-runtime-', dir=output.parent))
    try:
        for name, raw in files.items():
            fd = os.open(staging / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        sync_directory(staging)
        # Linux renameat2 makes directory publication atomic without replacing
        # even an empty output directory created concurrently by another writer.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staging), -100, os.fsencode(output), 1) != 0:
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                verify_existing(output, files)
                return False
            raise OSError(error, 'Exclusive output publication failed')
        sync_directory(output.parent)
        return True
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--site', type=Path, default=ROOT / 'deploy/dev/site.json')
    parser.add_argument('--channels', type=Path, default=ROOT / 'deploy/releases/channels.json')
    parser.add_argument('--repository-root', type=Path, default=ROOT.parent)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        files = prepare(args.site, args.channels, args.repository_root)
        created = publish(args.output.absolute(), files)
    except Exception:
        # Helm diagnostics can contain rendered configuration. Never relay them
        # or credential-bearing input/JSON errors to the console.
        print('Runtime preparation refused; validation or exclusive publication failed.', file=sys.stderr)
        return 1
    print(json.dumps({'created': created, 'verified': True, 'files': len(files),
                      'manifest_sha256': digest(files['manifest.json']), 'applied': False}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
