#!/usr/bin/env python3
"""Republish verified cached Linux image content after an approved registry reset.

Run on a storage/worker host as root. Credentials stay in memory and are sent
only to the image's HTTPS registry. An index with lost attestations is not
fabricated: the verified platform manifest is published under a new tag/digest.
Running containers and their original image cache are never changed.
"""
import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--kubeconfig', default='/etc/kubernetes/admin.conf')
    parser.add_argument('--namespace', default='heterocloud-registry')
    args = parser.parse_args()
    match = re.fullmatch(r'([a-z0-9.-]+)/([a-z0-9._/-]+)@(sha256:[a-f0-9]{64})', args.image)
    if not match or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', args.tag):
        parser.error('Use a pinned registry/repository image and a new recovery tag')
    host, repository, original = match.groups()
    ctr = ['ctr', '-n', 'k8s.io', 'content', 'get']

    def metadata(digest):
        raw = subprocess.check_output(ctr + [digest], stderr=subprocess.DEVNULL)
        if len(raw) > 4 * 1024 * 1024 or 'sha256:' + hashlib.sha256(raw).hexdigest() != digest:
            raise RuntimeError('cached_manifest_invalid')
        return raw, json.loads(raw)

    _, root = metadata(original)
    if 'manifests' in root:
        candidates = [d for d in root['manifests'] if d.get('platform', {}) == {'os': 'linux', 'architecture': 'amd64'}]
        if len(candidates) != 1:
            raise RuntimeError('unique_cached_linux_amd64_manifest_required')
        digest = candidates[0]['digest']
    else:
        digest = original
    manifest_raw, manifest = metadata(digest)
    descriptors = [manifest['config']] + manifest['layers']
    if any(not re.fullmatch(r'sha256:[a-f0-9]{64}', d['digest']) or not 0 < d['size'] <= 8 * 1024 ** 3 for d in descriptors):
        raise RuntimeError('invalid_blob_descriptor')
    _, config = metadata(manifest['config']['digest'])
    if config.get('os') != 'linux' or config.get('architecture') != 'amd64':
        raise RuntimeError('unsupported_cached_platform')
    secret = json.loads(subprocess.check_output(['kubectl', '--kubeconfig=' + args.kubeconfig,
        '-n', args.namespace, 'get', 'secret', 'heterocloud-registry-admin', '-o', 'json']))
    password = base64.b64decode(secret['data']['HARBOR_ADMIN_PASSWORD']).decode()
    basic = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
    del password, secret
    connection = http.client.HTTPSConnection(host, timeout=60)

    def request(method, path, body=None, headers=None, statuses=(200,)):
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme and (parsed.scheme != 'https' or parsed.netloc != host):
            raise RuntimeError('registry_redirect_or_upload_origin_rejected')
        target = urllib.parse.urlunsplit(('', '', parsed.path, parsed.query, ''))
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        data = response.read()
        if response.status not in statuses:
            raise RuntimeError('registry_' + method.lower() + '_http_' + str(response.status))
        return response.status, dict((k.lower(), v) for k, v in response.getheaders()), data

    query = urllib.parse.urlencode({'service': 'harbor-registry', 'scope': 'repository:' + repository + ':pull,push'})
    _, _, response = request('GET', '/service/token?' + query, headers={'Authorization': basic})
    del basic
    token_response = json.loads(response)
    auth = {'Authorization': 'Bearer ' + (token_response.get('token') or token_response['access_token'])}
    prefix = '/v2/' + repository
    try:
        with tempfile.TemporaryDirectory(prefix='registry-cache-recovery-') as directory:
            for descriptor in descriptors:
                blob = descriptor['digest']
                code, _, _ = request('HEAD', prefix + '/blobs/' + blob, headers=auth, statuses=(200, 404))
                if code == 200:
                    continue
                path = Path(directory) / blob.replace(':', '-')
                with path.open('wb') as output:
                    subprocess.run(ctr + [blob], stdout=output, stderr=subprocess.DEVNULL, check=True)
                hasher = hashlib.sha256()
                with path.open('rb') as stream:
                    while chunk := stream.read(8 * 1024 * 1024):
                        hasher.update(chunk)
                if path.stat().st_size != descriptor['size'] or 'sha256:' + hasher.hexdigest() != blob:
                    raise RuntimeError('cached_blob_digest_or_size_mismatch')
                _, headers, _ = request('POST', prefix + '/blobs/uploads/', body=b'', headers=auth, statuses=(202,))
                upload = headers['location']
                try:
                    with path.open('rb') as stream:
                        while chunk := stream.read(8 * 1024 * 1024):
                            _, headers, _ = request('PATCH', upload, body=chunk,
                                headers={**auth, 'Content-Type': 'application/octet-stream'}, statuses=(202,))
                            upload = headers['location']
                    separator = '&' if '?' in upload else '?'
                    _, headers, _ = request('PUT', upload + separator + urllib.parse.urlencode({'digest': blob}),
                        body=b'', headers=auth, statuses=(201,))
                    if headers.get('docker-content-digest') != blob:
                        raise RuntimeError('pushed_blob_digest_mismatch')
                    upload = None
                finally:
                    if upload:
                        request('DELETE', upload, headers=auth, statuses=(204, 404))
                    path.unlink()
                print(json.dumps({'uploaded_blob': blob, 'bytes': descriptor['size']}), flush=True)
            _, headers, _ = request('PUT', prefix + '/manifests/' + args.tag, body=manifest_raw,
                headers={**auth, 'Content-Type': manifest['mediaType']}, statuses=(201,))
            if headers.get('docker-content-digest') != digest:
                raise RuntimeError('pushed_manifest_digest_mismatch')
            _, _, pulled = request('GET', prefix + '/manifests/' + digest,
                headers={**auth, 'Accept': manifest['mediaType']})
            if pulled != manifest_raw:
                raise RuntimeError('registry_manifest_round_trip_mismatch')
            # Read every byte back through the public registry. A 401 /v2/
            # challenge or successful manifest alone does not verify data reads.
            for descriptor in descriptors:
                target = prefix + '/blobs/' + descriptor['digest']
                connection.request('GET', target, headers=auth)
                response = connection.getresponse()
                if response.status != 200:
                    raise RuntimeError('registry_blob_read_http_' + str(response.status))
                hasher, size = hashlib.sha256(), 0
                while chunk := response.read(8 * 1024 * 1024):
                    hasher.update(chunk); size += len(chunk)
                if size != descriptor['size'] or 'sha256:' + hasher.hexdigest() != descriptor['digest']:
                    raise RuntimeError('registry_blob_round_trip_mismatch')
            print(json.dumps({'result': 'passed', 'image': host + '/' + repository + '@' + digest,
                'tag': args.tag, 'original_index_retained_in_local_cache': True,
                'all_blobs_verified_through_public_registry': True}), flush=True)
    finally:
        connection.close()


if __name__ == '__main__':
    main()
