#!/usr/bin/env python3
"""Publish an immutable workspace image for future Coder builds, retaining data.

Use a short-lived CODER_SESSION_TOKEN environment variable. Existing template
files, resource sizes and variables are preserved. Running workspaces are not
restarted. Import and validate each version before activating it.
"""
import argparse
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    endpoint = urllib.parse.urlsplit(config['endpoint'])
    if endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.query or endpoint.fragment:
        parser.error('A credential-free HTTPS Coder endpoint is required')
    if not re.fullmatch(r'[a-z0-9.-]+/[a-z0-9._/-]+@sha256:[a-f0-9]{64}', config['image']):
        parser.error('A digest-pinned registry image is required')
    token = os.environ['CODER_SESSION_TOKEN']
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(path, method='GET', body=None, statuses=(200,)):
        request = urllib.request.Request(config['endpoint'].rstrip('/') + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Coder-Session-Token': token, 'Content-Type': 'application/json'})
        try:
            with opener.open(request, timeout=60) as response:
                code, data = response.status, response.read(16 * 1024 * 1024)
        except urllib.error.HTTPError as response:
            code, data = response.code, response.read(65536)
        if code not in statuses:
            raise RuntimeError('Coder API ' + method + ' HTTP ' + str(code) + '; response withheld')
        return json.loads(data) if data else None

    for template_id in config['templates']:
        uuid.UUID(template_id)
        template = call('/api/v2/templates/' + template_id)
        old = template['active_version_id']
        version = call('/api/v2/templateversions/' + old)
        variables = call('/api/v2/templateversions/' + old + '/variables')
        if any(value['sensitive'] for value in variables):
            raise RuntimeError('Sensitive variables require a separate protected reconciliation source')
        variables = [{'name': v['name'], 'value': v['value']} for v in variables]
        image = next(value for value in variables if value['name'] == 'workspace_image')
        if image['value'] == config['image']:
            print(json.dumps({'template': template_id, 'changed': False}), flush=True)
            continue
        image['value'] = config['image']
        created = call('/api/v2/organizations/' + template['organization_id'] + '/templateversions', 'POST', {
            'name': 'image-' + config['image'].split(':')[-1][:12] + '-' + uuid.uuid4().hex[:6],
            'message': 'Use verified platform image republished after the approved registry reset',
            'template_id': template_id, 'storage_method': 'file', 'file_id': version['job']['file_id'],
            'provisioner': 'terraform', 'user_variable_values': variables,
        }, (201,))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            created = call('/api/v2/templateversions/' + created['id'])
            if created['job']['status'] == 'succeeded':
                break
            if created['job']['status'] in ['failed', 'canceled']:
                raise RuntimeError('Template import failed; active version retained')
            time.sleep(3)
        else:
            raise RuntimeError('Template import timed out; active version retained')
        if call('/api/v2/templates/' + template_id)['active_version_id'] != old:
            raise RuntimeError('Template changed concurrently; activation rejected')
        call('/api/v2/templates/' + template_id + '/versions', 'PATCH', {'id': created['id']})
        print(json.dumps({'template': template_id, 'changed': True, 'old_version': old,
                         'version': created['id'], 'image': config['image']}), flush=True)


if __name__ == '__main__':
    main()
