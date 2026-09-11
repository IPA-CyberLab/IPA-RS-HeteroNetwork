#!/usr/bin/env python3
"""Offline DEV Longhorn preparation, never installation.

Without --image-pins, emit only an image inventory and blocked provenance.
Pins are a JSON object mapping every chart image key (longhorn.engine,
csi.attacher, etc.) to its exact docker.io/repo:tag source plus
@sha256:<64 lowercase hex digits>. Obtain and
validate real digests separately; this program never queries a registry.
With pins, emit a review-only manifest, NOT a deployment approval.
Requires PyYAML and Helm; --output must not exist, even if empty.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

import yaml

CHART_SHA = 'c8cf4b35a9d872cd5f7e44fd26d8e6ac7c2abaee42f4e2f2a0b0ebbc6e3a6116'
# Canonical content hash of the audited, deliberately non-configurable profile.
PROFILE_SHA = '2164b93fc709f6f75d9eca753c6beec877df266a5c2fba87a461dd4f89ea881a'
VALUES = Path(__file__).with_name('longhorn-values.yaml')
NAMESPACE = 'longhorn-system'
KUBE_VERSION = '1.36.4'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def allowed_values(values, defaults, path=''):
    """The pinned chart has no values.schema.json; check its actual keys."""
    if not isinstance(values, dict) or not isinstance(defaults, dict):
        raise ValueError(f'Expected values mapping at {path}')
    for key, value in values.items():
        if key not in defaults:
            raise ValueError(f'Unknown chart value: {path}{key}')
        if isinstance(value, dict):
            allowed_values(value, defaults[key], f'{path}{key}.')


def chart_inputs(raw, values_raw):
    if sha(raw) != CHART_SHA:
        raise ValueError('Unexpected Longhorn 1.12.1 chart SHA256')
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        defaults = yaml.safe_load(archive.extractfile('longhorn/values.yaml'))
        sources = {m.name: sha(archive.extractfile(m).read())
                   for m in archive.getmembers() if m.isfile()}
    values = yaml.safe_load(values_raw)
    allowed_values(values, defaults)
    if sha(encoded(values)) != PROFILE_SHA:
        raise ValueError('Values differ from the allowed bounded DEV profile')
    images = {}
    for group in ('longhorn', 'csi'):
        for name, item in defaults['image'][group].items():
            source = f"docker.io/{item['repository']}:{item['tag']}"
            images[f'{group}.{name}'] = source
    return values, images, sources


def apply_pins(values, images, pins):
    if not isinstance(pins, dict) or set(pins) != set(images):
        raise ValueError('Image pins must cover exactly every inventory source')
    values['image'] = {'longhorn': {}, 'csi': {}}
    for key, source in images.items():
        group, name = key.split('.')
        tag = source.rsplit(':', 1)[1]
        pinned = pins[key]
        if not isinstance(pinned, str) or not re.fullmatch(
                re.escape(source) + r'@sha256:[0-9a-f]{64}', pinned):
            raise ValueError(f'Invalid immutable pin for {source}')
        # Chart templates always join repository + ':' + tag. A tag@digest
        # preserves those templates and pins arguments/env as well as containers.
        values['image'][group][name] = {'tag': tag + '@' + pinned.split('@')[1]}


def validate_render(raw, pins):
    documents = [d for d in yaml.safe_load_all(raw) if d]
    seen = set()

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'namespace' and isinstance(item, str) and item != NAMESPACE:
                    raise ValueError(f'Unexpected source namespace: {item}')
                if key == 'image' and isinstance(item, str) and item not in pins.values():
                    raise ValueError(f'Unpinned container image: {item}')
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            if value in pins.values():
                seen.add(value)
            for pinned in pins.values():
                source = pinned.split('@')[0]
                if source in value and pinned not in value:
                    raise ValueError(f'Unpinned runtime image: {source}')

    walk(documents)
    if seen != set(pins.values()):
        raise ValueError('Not all required image pins reached the render')
    return documents


def installation_objects(documents):
    # Helm hooks are lifecycle commands, not regular desired-state objects.
    # In particular, applying the rendered pre-delete Job would uninstall Longhorn.
    items = []
    for original in documents:
        if original.get('metadata', {}).get('annotations', {}).get('helm.sh/hook'):
            continue
        item = json.loads(json.dumps(original))
        if item['kind'] == 'CustomResourceDefinition':
            item.pop('status', None)
        items.append(item)
    if any(item['kind'] == 'Job' for item in items):
        raise ValueError('Unexpected non-hook Longhorn Job')
    return {'apiVersion': 'v1', 'kind': 'List', 'items': items}


def prepare(chart, output, pins_path=None, helm='helm', values_path=VALUES):
    if output.exists() or output.is_symlink():
        raise ValueError('Output directory must not exist')
    chart_raw, values_raw = chart.read_bytes(), values_path.read_bytes()
    values, images, sources = chart_inputs(chart_raw, values_raw)
    files = {'longhorn-values.yaml': values_raw,
             'image-inventory.json': encoded({key: {'source': source, 'pin': None}
                                              for key, source in images.items()})}
    report = {
        'chart_version': '1.12.1', 'chart_sha256': CHART_SHA,
        'chart_members_sha256': sources, 'namespace': NAMESPACE,
        'target': 'dedicated DEV cluster only', 'cluster_changed': False,
        'deployable': False, 'image_digests_pinned': False,
        'registry_content_validated': False,
        'preparer_sha256': sha(Path(__file__).read_bytes()),
        'kube_version_for_render': KUBE_VERSION,
        'unmet_requirements': [
            'Image digests not yet pinned; no manifest emitted.',
            'Independently validate supplied digests, provenance and target architecture.',
            'Confirm all three DEV guests have 12 CPU and 12 GiB RAM.',
            'Validate dedicated DEV context, host prerequisites and three-node HA capacity.',
            'Confirm no node.longhorn.io/create-default-disk=true labels exist.',
            'Separately review disk enrollment; preserve 35 GiB per existing app disk.',
            'No disks assigned, enrolled or formatted; storage is not ready for workloads.',
            'Review RWX PVC integration and HA/failover before any deployment approval.',
        ],
    }
    if pins_path is not None:
        pins_raw = pins_path.read_bytes()
        pins = json.loads(pins_raw)
        apply_pins(values, images, pins)
        files['image-pins.json'] = pins_raw
        files['render-values.json'] = encoded(values)
        # Render the verified bytes, not an input path that could change later.
        with tempfile.TemporaryDirectory(prefix='prepare-longhorn-') as temp:
            root = Path(temp)
            (root / 'chart.tgz').write_bytes(chart_raw)
            (root / 'values.json').write_bytes(files['render-values.json'])
            command = [str(helm), 'template', 'longhorn', str(root / 'chart.tgz'),
                       '--namespace', NAMESPACE, '--kube-version', KUBE_VERSION,
                       '--include-crds', '--values', str(root / 'values.json')]
            raw = subprocess.run(command, check=True, capture_output=True, timeout=120).stdout
            documents = validate_render(raw, pins)
            files['review-only.yaml'] = raw
            files['install-objects.json'] = encoded(installation_objects(documents))
            report['helm_version'] = subprocess.run(
                [str(helm), 'version', '--short'], check=True, capture_output=True,
                text=True, timeout=10).stdout.strip()
        report['image_digests_pinned'] = True
        report['unmet_requirements'].pop(0)
    report['files_sha256'] = {name: sha(raw) for name, raw in sorted(files.items())}
    files['provenance.json'] = encoded(report)
    # mkdir is the exclusive claim; never reuse or overwrite an existing directory.
    output.mkdir(mode=0o700)
    for name, raw in files.items():
        with (output / name).open('xb') as stream:
            stream.write(raw)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chart', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--image-pins', type=Path)
    parser.add_argument('--helm', default='helm')
    args = parser.parse_args()
    try:
        report = prepare(args.chart, args.output, args.image_pins, args.helm)
    except (ValueError, OSError, subprocess.SubprocessError, yaml.YAMLError) as exc:
        parser.exit(1, f'Preparation failed: {exc}\n')
    print(encoded(report).decode(), end='')


if __name__ == '__main__':
    main()
