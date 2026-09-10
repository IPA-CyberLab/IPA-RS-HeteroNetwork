#!/usr/bin/env python3
"""Place verified dev6 sudo bytes on a pinned DEV guest without activation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

sys.dont_write_bytecode = True
BUNDLE = Path('/opt/heteronetwork-dev-sudo-companion')
DEST = Path('/opt/heteronetwork/sudo-v2/artifacts/0.1.15-dev.6')
ARCHIVE_SHA = '0a1d2c9c0d39435e53777557a859a734ef0d1af7d5cc07e0de27d673a8cba569'
COMMIT = '22c4e3baf5de53f70bbac08f5fe62a0590e24526'


def require(value):
    if not value:
        raise ValueError('DEV inactive sudo installation rejected')


def trusted(path, directory=False):
    for parent in reversed(path.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022)
    info = path.lstat()
    require(info.st_uid == 0 and not info.st_mode & 0o022)
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return info


def load(path, name, digest):
    trusted(path)
    require(hashlib.sha256(path.read_bytes()).hexdigest() == digest)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snapshot():
    for path in ('/etc/ipars-sudo-v2', '/run/ipars-sudo-v2', '/var/lib/ipars-sudo-v2'):
        require(not os.path.lexists(path))
    paths = [Path('/etc/sudoers'), Path('/etc/sudo.conf')]
    directory = Path('/etc/sudoers.d')
    if directory.exists():
        trusted(directory, directory=True)
        paths.extend(sorted(directory.iterdir()))
    result = {}
    for path in paths:
        if not os.path.lexists(path):
            result[str(path)] = None
            continue
        info = trusted(path)
        require(info.st_size <= 1048576)
        raw = path.read_bytes()
        if path == Path('/etc/sudo.conf'):
            require(all(value not in raw for value in (b'quorum_v2_gate', b'local-sudo-v2', b'ipars-sudo-v2')))
        result[str(path)] = (info.st_ino, info.st_uid, info.st_gid, info.st_mode, hashlib.sha256(raw).hexdigest())
    return result


def verify(artifact, payloads, manifest):
    trusted(DEST, directory=True)
    require({str(p.relative_to(DEST)) for p in DEST.rglob('*')} ==
            {'bin', 'lib', artifact.MANIFEST, *artifact.FILES})
    for name, data in payloads.items():
        path = DEST / name
        info = trusted(path)
        require(stat.S_IMODE(info.st_mode) == artifact.FILES[name] and path.read_bytes() == data)
    trusted(DEST / artifact.MANIFEST)
    require(json.loads((DEST / artifact.MANIFEST).read_bytes()) == manifest)


def main():
    require(len(sys.argv) == 1 and os.getuid() == 0 and os.geteuid() == 0)
    dkg = load(Path('/opt/heteronetwork-dev-sudo-dkg/dev-sudo-dkg.py'), 'dev_dkg',
               '0fc2ac15c65cb2a69fee5a15157d02476afdc0284629c44d45f299d4d48c7cfe')
    member = dkg.check_identity()
    before = snapshot()
    artifact = load(BUNDLE / 'sudo-quorum-v2-artifact.py', 'sudo_artifact',
                    'f5bcd1bbe4a985b4a62d6f228c4a8d5ffcb0ec949de7384436d18c0c7620b322')
    archive = BUNDLE / 'sudo-dev6.tar.gz'
    trusted(archive)
    raw = artifact.regular(archive, artifact.MAX_TOTAL)
    payloads, manifest = artifact.decode_archive(raw, ARCHIVE_SHA)
    artifact.release_contract(raw, COMMIT, '0.1.15-dev.6')
    for parent in [Path('/opt/heteronetwork'), Path('/opt/heteronetwork/sudo-v2'), DEST.parent]:
        try:
            parent.mkdir(mode=0o755)
        except FileExistsError:
            pass
        trusted(parent, directory=True)
    created = not os.path.lexists(DEST)
    if created:
        contents = {name: (data, artifact.FILES[name]) for name, data in payloads.items()}
        contents[artifact.MANIFEST] = ((json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode(), 0o644)
        artifact.publish_directory(DEST, contents)
    verify(artifact, payloads, manifest)
    require(snapshot() == before)
    print(json.dumps({'guest': f'hetero-dev-{member}', 'version': '0.1.15-dev.6',
                      'source_commit': COMMIT, 'archive_sha256': ARCHIVE_SHA,
                      'destination': str(DEST), 'created': created, 'bytes_verified': True,
                      'sudo_configuration_unchanged': True, 'payload_executed': False,
                      'service_installed': False, 'activation_performed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('DEV sudo companion stopped; preserve existing bytes and inspect prerequisites', file=sys.stderr)
        sys.exit(1)
