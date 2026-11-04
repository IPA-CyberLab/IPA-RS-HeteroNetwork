#!/usr/bin/env python3
"""Publish reviewed Coder readiness templates without restarting workspaces.

The short-lived owner credential is read from CODER_SESSION_TOKEN and is never
written to Terraform state, a file, a URL, or the command line.
"""
import argparse
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_ARCHIVE = 16 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def variant_main(source, variant):
    if variant == 'standard':
        return source
    if variant != 'big':
        raise ValueError('Unrecognized template variant')
    edits = [(b'workspace_memory_mib = lookup(var.workspace_memory_overrides, data.coder_workspace.me.id, 8192)',
              b'workspace_memory_mib = lookup(var.workspace_memory_overrides, data.coder_workspace.me.id, 16384)'),
             (b'cpu_millis             = 4000', b'cpu_millis             = 8000')]
    for before, after in edits:
        if source.count(before) != 1:
            raise ValueError('Reviewed Big template marker changed')
        source = source.replace(before, after)
    return source


def revised_archive(archive, expected_old, replacement, waiter):
    if len(archive) > MAX_ARCHIVE:
        raise ValueError('Template archive exceeds the size limit')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:*') as original:
        entries = original.getmembers()
        files = {}
        seen = set()
        expanded_size = 0
        for entry in entries:
            path = PurePosixPath(entry.name)
            if path.is_absolute() or '..' in path.parts or not (entry.isfile() or entry.isdir()):
                raise ValueError('Unsafe template archive entry')
            normalized = str(path)
            if normalized in seen:
                raise ValueError('Duplicate template archive entry')
            seen.add(normalized)
            if entry.isfile():
                expanded_size += entry.size
                if entry.size > MAX_ARCHIVE or expanded_size > MAX_ARCHIVE:
                    raise ValueError('Expanded template archive exceeds the size limit')
                files[entry.name] = original.extractfile(entry).read()
        if 'main.tf' not in files:
            raise ValueError('Expected root main.tf is missing')
        if digest(files['main.tf']) == digest(replacement) and files.get('wait-for-flash.sh') == waiter:
            return None
        if digest(files['main.tf']) != expected_old:
            raise ValueError('Active template changed since it was reviewed')
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as revised:
            for entry in entries:
                if entry.name == 'wait-for-flash.sh':
                    continue
                info = copy.copy(entry)
                if entry.isfile():
                    data = replacement if entry.name == 'main.tf' else files[entry.name]
                    info.size = len(data)
                    revised.addfile(info, io.BytesIO(data))
                else:
                    revised.addfile(info)
            info = tarfile.TarInfo('wait-for-flash.sh')
            info.mode = 0o755
            info.size = len(waiter)
            revised.addfile(info, io.BytesIO(waiter))
        return output.getvalue()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Client:
    def __init__(self, endpoint, token):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.query or parsed.fragment:
            raise ValueError('A credential-free HTTPS Coder endpoint is required')
        self.endpoint = endpoint.rstrip('/')
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, path, method='GET', body=None, statuses=(200,), raw=False):
        headers = {'Coder-Session-Token': self.token}
        if isinstance(body, bytes):
            headers['Content-Type'] = 'application/x-tar'
            data = body
        else:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.endpoint + path, method=method, data=data, headers=headers)
        try:
            with self.opener.open(request, timeout=60) as response:
                code, data = response.status, response.read(MAX_ARCHIVE + 1)
        except urllib.error.HTTPError as response:
            code, data = response.code, response.read(1024)
        if code not in statuses or len(data) > MAX_ARCHIVE:
            raise RuntimeError(f'Coder API {method} returned HTTP {code}; body withheld')
        return data if raw else json.loads(data) if data else None


def load_source(config, name):
    repository = config['source_repository']
    commit = config['source_commit']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('Source repository and immutable commit are required')
    if name not in ('main.tf', 'wait-for-flash.sh'):
        raise ValueError('Unexpected source file')
    url = f'https://raw.githubusercontent.com/{repository}/{commit}/examples/coder/{name}'
    with urllib.request.urlopen(url, timeout=30) as response:
        data = response.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024 or digest(data) != config['source_sha256'][name]:
        raise ValueError('Pinned template source digest does not match')
    return data


def reconcile(client, config, main_source, waiter):
    owner = config['owner_id']
    uuid.UUID(owner)
    template_ids = {item['id'] for item in config['templates']}
    if len(template_ids) != len(config['templates']):
        raise ValueError('Duplicate templates are not allowed')
    for item in config['templates']:
        uuid.UUID(item['id'])
        if not re.fullmatch(r'[a-f0-9]{64}', item['expected_old_main_sha256']):
            raise ValueError('Reviewed template digest is required')
    workspaces = []
    for workspace in config['auto_update_workspaces']:
        uuid.UUID(workspace['id'])
        if workspace['template_id'] not in template_ids:
            raise ValueError('Workspace template is outside the configured scope')
        actual = client.call('/api/v2/workspaces/' + workspace['id'])
        if actual['owner_id'] != owner or actual['template_id'] != workspace['template_id']:
            raise ValueError('Workspace owner or template does not match the configured scope')
        workspaces.append(actual)

    for item in config['templates']:
        template_id = item['id']
        template = client.call('/api/v2/templates/' + template_id)
        old = template['active_version_id']
        version = client.call('/api/v2/templateversions/' + old)
        variables = client.call('/api/v2/templateversions/' + old + '/variables')
        if any(value['sensitive'] for value in variables):
            raise ValueError('Sensitive template variables need a protected reconciliation source')
        values = [{'name': value['name'], 'value': value['value']} for value in variables]
        image = next((value['value'] for value in values if value['name'] == 'workspace_image'), None)
        if image != config['expected_workspace_image']:
            raise ValueError('Active workspace image changed since review')
        archive = client.call('/api/v2/files/' + version['job']['file_id'], raw=True)
        replacement = variant_main(main_source, item['variant'])
        revised = revised_archive(archive, item['expected_old_main_sha256'], replacement, waiter)
        if revised is None:
            print(json.dumps({'template': template_id, 'changed': False}), flush=True)
            continue
        uploaded = client.call('/api/v2/files', 'POST', revised, statuses=(200, 201))
        created = client.call('/api/v2/organizations/' + template['organization_id'] + '/templateversions', 'POST', {
            'name': 'flash-ready-' + uuid.uuid4().hex[:12],
            'message': 'Wait for the current Flash revision before marking the workspace running',
            'template_id': template_id, 'storage_method': 'file',
            'file_id': uploaded.get('id', uploaded.get('hash')),
            'provisioner': 'terraform', 'user_variable_values': values,
        }, statuses=(201,))
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            created = client.call('/api/v2/templateversions/' + created['id'])
            if created['job']['status'] == 'succeeded':
                break
            if created['job']['status'] in ('failed', 'canceled'):
                raise RuntimeError('Template import failed; previous active version retained')
            time.sleep(3)
        else:
            raise RuntimeError('Template import timed out; previous active version retained')
        actual = client.call('/api/v2/templateversions/' + created['id'] + '/variables')
        if {v['name']: v['value'] for v in actual} != {v['name']: v['value'] for v in values}:
            raise RuntimeError('Imported template variables differ; activation refused')
        if client.call('/api/v2/templates/' + template_id)['active_version_id'] != old:
            raise RuntimeError('Active template changed concurrently; activation refused')
        client.call('/api/v2/templates/' + template_id + '/versions', 'PATCH', {'id': created['id']})
        if client.call('/api/v2/templates/' + template_id)['active_version_id'] != created['id']:
            raise RuntimeError('Template activation could not be verified')
        print(json.dumps({'template': template_id, 'changed': True, 'old_version': old,
                          'version': created['id'], 'variant': item['variant']}), flush=True)

    for workspace in workspaces:
        path = '/api/v2/workspaces/' + workspace['id']
        current = client.call(path)
        if current['owner_id'] != owner or current['template_id'] != workspace['template_id']:
            raise RuntimeError('Workspace ownership changed during reconciliation')
        changed = current.get('automatic_updates') != 'always'
        if changed:
            client.call(path + '/autoupdates', 'PUT', {'automatic_updates': 'always'}, statuses=(200, 204))
        current = client.call(path)
        if current.get('automatic_updates') != 'always':
            raise RuntimeError('Workspace automatic update policy was not applied')
        print(json.dumps({'workspace': workspace['id'], 'updates_on_next_start': True,
                          'policy_changed': changed}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    token = os.environ.get('CODER_SESSION_TOKEN', '')
    if not token or '\n' in token:
        parser.error('A short-lived CODER_SESSION_TOKEN is required')
    reconcile(Client(config['endpoint'], token), config,
              load_source(config, 'main.tf'), load_source(config, 'wait-for-flash.sh'))


if __name__ == '__main__':
    main()
