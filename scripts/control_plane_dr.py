#!/usr/bin/env python3
"""Create authenticated, independently restorable control-plane recovery sets.

Each trusted source program writes one consistent backup to stdout. Restic
encrypts it before storage. A recovery set is committed only after every source
has succeeded and every uploaded object has been read back and checked against
its source digest. This tool never initializes, replaces or restores a live
database or cluster.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid

NAME = re.compile(r'^[a-z][a-z0-9-]{0,63}$')
SNAPSHOT = re.compile(r'^[0-9a-f]{8,64}$')
HEX = re.compile(r'^[0-9a-f]{64}$')
REQUIRED = frozenset({'postgres', 'etcd', 'secret-manager', 'flash-catalog', 'registry', 'syouyu'})
MAX_MANIFEST = 256 * 1024
BUFFER = 1024 * 1024
MAX_BACKUP_BYTES = 4 * 1024**4


def private_file(path, *, executable=False):
    path = Path(path)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError('A non-symlink absolute private file path is required')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('A private file owned by the current user is required')
    parent = path.parent.stat()
    if parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise ValueError('The private file directory must not be writable by other users')
    if executable and not info.st_mode & stat.S_IXUSR:
        raise ValueError('The source program is not executable')
    return path


def read_config(path, allow_local=False, require_sources=True):
    config = json.loads(private_file(path).read_text())
    if set(config) - {'repository', 'password_file', 'sources', 'timeout_seconds',
                      'max_component_bytes', 'max_total_bytes'}:
        raise ValueError('Unexpected recovery configuration field')
    repository = config.get('repository')
    if not isinstance(repository, str) or not repository:
        raise ValueError('A recovery repository is required')
    if repository.startswith('s3:'):
        parsed = urllib.parse.urlsplit(repository[3:])
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
                or parsed.query or parsed.fragment or not parsed.path.strip('/')):
            raise ValueError('The S3 repository must use a credential-free HTTPS URL')
    elif not (allow_local and Path(repository).is_absolute()):
        raise ValueError('A private S3 HTTPS repository is required')
    private_file(config['password_file'])
    sources = config.get('sources')
    if sources is None and not require_sources:
        sources = []
        config['sources'] = sources
    if not isinstance(sources, list) or (require_sources and not sources) or len(sources) > 32:
        raise ValueError('One to 32 explicitly named recovery sources are required')
    seen = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {'name', 'executable'}:
            raise ValueError('Each source requires only a name and executable')
        name = source['name']
        if not isinstance(name, str) or not NAME.fullmatch(name) or name in seen:
            raise ValueError('Invalid or duplicate recovery source')
        seen.add(name)
        if require_sources:
            private_file(source['executable'], executable=True)
    timeout = config.get('timeout_seconds', 3600)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 10 <= timeout <= 86400:
        raise ValueError('Invalid recovery timeout')
    config['timeout_seconds'] = timeout
    for key in ('max_component_bytes', 'max_total_bytes'):
        value = config.get(key, 40 * 1024**3)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= MAX_BACKUP_BYTES:
            raise ValueError('An explicit bounded backup size is required')
        config[key] = value
    return config


def restic_env(config):
    # An inherited restic password/repository/command must never override the
    # reviewed recovery configuration. A CA bundle may be intentionally set
    # for an internal HTTPS S3 endpoint.
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('RESTIC_') or key == 'RESTIC_CACERT'}
    env['RESTIC_REPOSITORY'] = config['repository']
    env['RESTIC_PASSWORD_FILE'] = config['password_file']
    credential_file = env.get('AWS_SHARED_CREDENTIALS_FILE')
    if credential_file:
        private_file(credential_file)
    return env


def stream_process(arguments, env, timeout, *, stdin=None, consume=None):
    proc = subprocess.Popen(arguments, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
                            start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    if stdin is not None:
        selector.register(proc.stdin, selectors.EVENT_WRITE)
    offset = 0
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Recovery operation timed out')
            events = selector.select(remaining)
            if not events:
                raise TimeoutError('Recovery operation timed out')
            for key, _ in events:
                if key.fileobj is proc.stdout:
                    chunk = os.read(proc.stdout.fileno(), BUFFER)
                    if not chunk:
                        selector.unregister(proc.stdout)
                        proc.stdout.close()
                    elif consume is not None:
                        consume(chunk)
                else:
                    if offset < len(stdin):
                        offset += os.write(proc.stdin.fileno(), stdin[offset:offset + 65536])
                    if offset == len(stdin):
                        selector.unregister(proc.stdin)
                        proc.stdin.close()
        if proc.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise RuntimeError('Recovery operation failed; no recovery set was committed')
    except BaseException:
        # Let source programs remove private temporary files before forcing a
        # stuck process group down. The restic parent can exit before a source
        # has finished cleanup, so wait for the whole group, not just restic.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            grace_deadline = time.monotonic() + 2
            while time.monotonic() < grace_deadline:
                proc.poll()
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        raise
    finally:
        selector.close()
        if proc.stdout and not proc.stdout.closed:
            proc.stdout.close()
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()


def invoke(arguments, env, timeout, *, stdin=None):
    output = bytearray()
    def consume(chunk):
        if len(output) + len(chunk) > MAX_MANIFEST:
            raise RuntimeError('Recovery operation returned too much metadata')
        output.extend(chunk)
    stream_process(arguments, env, timeout, stdin=stdin, consume=consume)
    return bytes(output)


def stream_source(executable, report_path, max_bytes):
    """Run a trusted source without exposing storage credentials to it."""
    private_file(executable, executable=True)
    digest = hashlib.sha256()
    size = 0
    source_env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                  'LANG': 'C', 'LC_ALL': 'C'}
    source = subprocess.Popen([executable], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, env=source_env)
    try:
        while chunk := source.stdout.read(BUFFER):
            size += len(chunk)
            if size > max_bytes:
                raise RuntimeError('Recovery source exceeds its size budget')
            sys.stdout.buffer.write(chunk)
            digest.update(chunk)
        sys.stdout.buffer.flush()
        if source.wait() != 0 or size == 0:
            raise RuntimeError('Recovery source did not complete successfully')
        report = {'size': size, 'sha256': digest.hexdigest()}
        descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            json.dump(report, output)
    except BaseException:
        source.terminate()
        try:
            source.wait(timeout=2)
        except subprocess.TimeoutExpired:
            source.kill()
            source.wait()
        raise


def summary(output):
    try:
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]
        matches = [row['snapshot_id'] for row in rows if row.get('message_type') == 'summary']
    except (ValueError, KeyError, TypeError):
        raise RuntimeError('Invalid recovery snapshot metadata') from None
    if len(matches) != 1 or not isinstance(matches[0], str) or not SNAPSHOT.fullmatch(matches[0]):
        raise RuntimeError('Missing recovery snapshot identifier')
    return matches[0]


def dump(restic, env, timeout, snapshot, name, target=None, max_bytes=MAX_BACKUP_BYTES):
    if not SNAPSHOT.fullmatch(snapshot) or not NAME.fullmatch(name):
        raise ValueError('Invalid recovery snapshot reference')
    digest = hashlib.sha256()
    size = 0
    def consume(chunk):
        nonlocal size
        size += len(chunk)
        if size > max_bytes:
            raise RuntimeError('Recovery component exceeds its expected size')
        digest.update(chunk)
        if target is not None:
            target.write(chunk)
    stream_process([restic, 'dump', snapshot, '/' + name], env, timeout, consume=consume)
    return {'size': size, 'sha256': digest.hexdigest()}


def backup(config, restic, require_complete=False):
    names = {source['name'] for source in config['sources']}
    if require_complete and not REQUIRED <= names:
        raise ValueError('A complete recovery set is missing required sources')
    env = restic_env(config)
    timeout = config['timeout_seconds']
    run_id = uuid.uuid4().hex
    components = []
    total = 0
    with tempfile.TemporaryDirectory(prefix='hc-dr-', dir='/dev/shm') as private:
        os.chmod(private, 0o700)
        for source in config['sources']:
            name = source['name']
            report = str(Path(private) / name)
            command = [restic, '--json', '--quiet', 'backup', '--stdin-from-command',
                       '--stdin-filename', name, '--tag', 'hc-dr-component', '--tag', 'run-' + run_id,
                       '--', sys.executable, str(Path(__file__).resolve()), '_source',
                       source['executable'], report,
                       str(min(config['max_component_bytes'], config['max_total_bytes'] - total))]
            snapshot = summary(invoke(command, env, timeout))
            expected = json.loads(private_file(report).read_text())
            if dump(restic, env, timeout, snapshot, name, max_bytes=expected['size']) != expected:
                raise RuntimeError('Uploaded recovery component verification failed')
            components.append({'name': name, 'snapshot': snapshot, **expected})
            total += expected['size']
        manifest = {'schema_version': 1, 'run_id': run_id, 'created_at': int(time.time()),
                    'required_components_present': REQUIRED <= names, 'components': components}
        payload = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
        committed = summary(invoke([restic, '--json', '--quiet', 'backup', '--stdin',
                                    '--stdin-filename', 'manifest', '--tag', 'hc-dr-commit',
                                    '--tag', 'run-' + run_id], env, timeout, stdin=payload))
        expected = {'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
        if dump(restic, env, timeout, committed, 'manifest', max_bytes=len(payload)) != expected:
            raise RuntimeError('Recovery manifest verification failed')
        return {'run_id': run_id, 'snapshot': committed,
                'required_components_present': manifest['required_components_present'],
                'components': [item['name'] for item in components]}


def load_manifest(config, restic, snapshot):
    if not SNAPSHOT.fullmatch(snapshot):
        raise ValueError('An explicit recovery snapshot is required')
    env = restic_env(config)
    output = invoke([restic, 'dump', snapshot, '/manifest'], env, config['timeout_seconds'])
    try:
        value = json.loads(output)
    except ValueError:
        raise ValueError('Invalid recovery manifest') from None
    if (value.get('schema_version') != 1 or not re.fullmatch(r'[0-9a-f]{32}', value.get('run_id', ''))
            or not isinstance(value.get('components'), list) or not value['components']
            or len(value['components']) > 32):
        raise ValueError('Invalid recovery manifest')
    names = set()
    for item in value['components']:
        if (not isinstance(item, dict) or not NAME.fullmatch(item.get('name', ''))
                or item['name'] in names or not SNAPSHOT.fullmatch(item.get('snapshot', ''))
                or not HEX.fullmatch(item.get('sha256', ''))
                or not isinstance(item.get('size'), int) or isinstance(item.get('size'), bool)
                or not 0 < item['size'] <= MAX_BACKUP_BYTES):
            raise ValueError('Invalid recovery component')
        names.add(item['name'])
    if value.get('required_components_present') is not (REQUIRED <= names):
        raise ValueError('Recovery completeness does not match the components')
    return env, value


def verify(config, restic, snapshot):
    env, manifest = load_manifest(config, restic, snapshot)
    for item in manifest['components']:
        actual = dump(restic, env, config['timeout_seconds'], item['snapshot'], item['name'],
                      max_bytes=item['size'])
        if actual != {'size': item['size'], 'sha256': item['sha256']}:
            raise RuntimeError('Recovery component checksum mismatch')
    return {'run_id': manifest['run_id'],
            'required_components_present': manifest['required_components_present'],
            'components_verified': len(manifest['components'])}


def restore(config, restic, snapshot, target):
    env, manifest = load_manifest(config, restic, snapshot)
    path = Path(target)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError('A private absolute recovery directory is required')
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = []
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077 or os.listdir(directory):
            raise ValueError('Recovery requires an empty owner-only directory')
        for item in manifest['components']:
            name = item['name']
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            created.append(name)
            with os.fdopen(descriptor, 'wb') as output:
                actual = dump(restic, env, config['timeout_seconds'], item['snapshot'], name, output,
                              max_bytes=item['size'])
                output.flush()
                os.fsync(output.fileno())
            if actual != {'size': item['size'], 'sha256': item['sha256']}:
                raise RuntimeError('Restored recovery component checksum mismatch')
        os.fsync(directory)
        return {'run_id': manifest['run_id'],
                'required_components_present': manifest['required_components_present'],
                'components_restored': len(created)}
    except BaseException:
        for name in created:
            try:
                os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(directory)


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '_source':
        stream_source(sys.argv[2], sys.argv[3], int(sys.argv[4]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['backup', 'verify', 'restore'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--restic', default='restic')
    parser.add_argument('--snapshot')
    parser.add_argument('--target')
    parser.add_argument('--require-complete', action='store_true')
    parser.add_argument('--allow-local-test-repository', action='store_true')
    args = parser.parse_args()
    config = read_config(args.config, args.allow_local_test_repository, args.command == 'backup')
    if args.command == 'backup':
        result = backup(config, args.restic, args.require_complete)
    elif args.command == 'verify':
        if not args.snapshot:
            parser.error('An explicit --snapshot is required')
        result = verify(config, args.restic, args.snapshot)
    else:
        if not args.snapshot or not args.target:
            parser.error('An explicit --snapshot and --target are required')
        result = restore(config, args.restic, args.snapshot, args.target)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
