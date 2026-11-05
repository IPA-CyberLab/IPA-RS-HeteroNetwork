#!/usr/bin/env python3
"""Keep managed Coder templates' default autostop disabled.

Existing workspace choices are deliberately untouched. For a one-time removal
of existing stop timers, use HeteroCloud's reconcile-coder-scheduling.py.
CODER_SESSION_TOKEN is supplied only in the environment and is not stored.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import uuid

spec = importlib.util.spec_from_file_location(
    'coder_readiness', Path(__file__).with_name('reconcile-coder-workspace-readiness.py'))
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def canonical_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('A canonical UUID is required')
    return value


def reconcile(client, config):
    if config.get('default_ttl_ms') != 0 or config.get('allow_user_autostop') is not True:
        raise ValueError('The managed default must disable autostop and allow user choices')
    owner = canonical_uuid(config['owner_id'])
    organization = canonical_uuid(config['organization_id'])
    identifiers = config['template_ids']
    if not isinstance(identifiers, list) or not identifiers:
        raise ValueError('At least one managed template is required')
    for identifier in identifiers:
        canonical_uuid(identifier)
    if len(set(identifiers)) != len(identifiers):
        raise ValueError('Duplicate templates are not allowed')
    if client.call('/api/v2/users/me')['id'] != owner:
        raise ValueError('The Coder credential does not belong to the configured owner')

    # Check the scope of every template before making any changes.
    templates = []
    for identifier in identifiers:
        template = client.call('/api/v2/templates/' + identifier)
        if template['id'] != identifier or template['organization_id'] != organization:
            raise ValueError('A template is outside the configured organization')
        requirement = template.get('autostop_requirement') or {}
        # Coder can report a default week interval even when no required day
        # is configured. Only a non-empty day set activates the requirement.
        if requirement.get('days_of_week'):
            raise ValueError('A template has a mandatory autostop requirement')
        templates.append(template)

    results = []
    for template in templates:
        identifier = template['id']
        desired = {'default_ttl_ms': 0, 'allow_user_autostop': True}
        changed = any(template.get(key) != value for key, value in desired.items())
        if changed:
            client.call('/api/v2/templates/' + identifier, 'PATCH', desired, statuses=(200, 204))
        actual = client.call('/api/v2/templates/' + identifier)
        if any(actual.get(key) != value for key, value in desired.items()):
            raise RuntimeError('The template scheduling policy could not be verified')
        results.append({'template_id': identifier, 'name': actual['name'], 'changed': changed})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    token = os.environ.get('CODER_SESSION_TOKEN', '')
    if not token or '\n' in token:
        parser.error('A short-lived CODER_SESSION_TOKEN is required')
    client = readiness.Client(config['endpoint'], token)
    print(json.dumps({'templates': reconcile(client, config)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
