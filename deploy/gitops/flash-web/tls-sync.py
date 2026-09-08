#!/usr/bin/env python3
"""Publish a projected cert-manager Secret to the existing host gateway only."""

import argparse
import contextlib
import datetime
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid


EXTRA = "public-gateway-extra.Caddyfile"
CERTDIR = "flash-web-certs"
HOST = "*.flash.heterocloud.mizuame.app"
BEGIN = b"# BEGIN managed flash-web TLS\n"
END = b"# END managed flash-web TLS\n"
LIMIT = 256 * 1024
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def require(condition, message):
    if not condition:
        raise ValueError(message)


def secure(st, directory=False):
    require((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))
            and st.st_uid == 0 and not st.st_mode & 0o022,
            "expected root-owned non-writable regular file/directory")
    if not directory:
        require(st.st_nlink == 1, "hard-linked file refused")


@contextlib.contextmanager
def directory(path):
    # Walk from / using directory FDs: no symlinked or writable ancestors.
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "invalid host path")
    fd = os.open("/", FLAGS | os.O_DIRECTORY)
    try:
        secure(os.fstat(fd), True)
        for part in path.parts[1:]:
            child = os.open(part, FLAGS | os.O_DIRECTORY, dir_fd=fd)
            os.close(fd)
            fd = child
            secure(os.fstat(fd), True)
        yield fd
    finally:
        os.close(fd)


def read_file(parent, name, trusted=True):
    fd = os.open(name, FLAGS, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if trusted:
            secure(st)
        require(stat.S_ISREG(st.st_mode), "not a regular file")
        data = stream.read(LIMIT + 1)
        require(len(data) <= LIMIT, "file exceeds size limit")
        return data, st


def host_gid(group_file):
    with directory(str(Path(group_file).parent)) as parent:
        data, _ = read_file(parent, Path(group_file).name)
    rows = [line.split(":") for line in data.decode("ascii").splitlines()
            if line.startswith("heteronetwork-gateway:")]
    require(len(rows) == 1 and len(rows[0]) == 4 and rows[0][2].isdigit(),
            "host gateway group missing or ambiguous")
    gid = int(rows[0][2])
    require(0 < gid < 2**32 - 1, "invalid host gateway GID")
    return gid


def secret_pair(secret):
    # Pin one Kubernetes AtomicWriter generation, never read the two top-level
    # symlinks independently while kubelet may be switching ..data.
    fd = os.open(str(Path(secret) / "..data"), os.O_RDONLY | os.O_DIRECTORY)
    try:
        cert, _ = read_file(fd, "tls.crt", trusted=False)
        key, _ = read_file(fd, "tls.key", trusted=False)
        return cert, key
    finally:
        os.close(fd)


def openssl(*args, data=None):
    result = subprocess.run(["openssl", *args], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15, check=False,
                            env={**os.environ, "LC_ALL": "C"})
    # Never forward OpenSSL output/errors into logs; they may contain secrets.
    require(result.returncode == 0, "certificate validation failed")
    return result.stdout


def validate(cert, key):
    require(re.match(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\r?\n", key) is not None
            and b"ENCRYPTED" not in key, "encrypted or unsupported private key")
    with tempfile.TemporaryDirectory(prefix="flash-tls-") as tmp:
        cert_path, key_path = Path(tmp) / "tls.crt", Path(tmp) / "tls.key"
        for path, data in ((cert_path, cert), (key_path, key)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        san = openssl("x509", "-in", str(cert_path), "-noout", "-ext", "subjectAltName")
        require(HOST.encode() in re.findall(rb"DNS:([^,\s]+)", san),
                "required wildcard SAN missing")
        openssl("x509", "-in", str(cert_path), "-noout", "-checkhost",
                "sync-probe.flash.heterocloud.mizuame.app")
        dates = openssl("x509", "-in", str(cert_path), "-noout", "-dates")
        parsed = dict(line.split("=", 1) for line in dates.decode("ascii").splitlines())
        def timestamp(name):
            return datetime.datetime.strptime(parsed[name], "%b %d %H:%M:%S %Y GMT").replace(
                tzinfo=datetime.timezone.utc).timestamp()
        now = time.time()
        require(timestamp("notBefore") <= now and timestamp("notAfter") > now + 3600,
                "certificate not valid now or expires within one hour")
        # Parse every PEM in the supplied chain before Caddy receives it.
        openssl("crl2pkcs7", "-nocrl", "-certfile", str(cert_path))
        cert_pub = openssl("x509", "-in", str(cert_path), "-pubkey", "-noout")
        key_pub = openssl("pkey", "-in", str(key_path), "-passin", "pass:", "-pubout")
        openssl("pkey", "-in", str(key_path), "-passin", "pass:", "-check", "-noout")
        require(cert_pub == key_pub, "certificate and key mismatch")


def route(generation):
    base = f"/etc/heteronetwork/{CERTDIR}/{generation}"
    return BEGIN + f"""http://{HOST}:80 {{
    redir https://{{host}}{{uri}} 308
}}
https://{HOST}:443 {{
    tls {base}/tls.crt {base}/tls.key
    import heterocloud_envoy /api/v1/health/live heterocloud.mizuame.app
}}
""".encode() + END


def update_content(old, generation):
    old.decode("utf-8")
    require(b"\0" not in old, "NUL in extra file")
    require(bool(re.search(rb"(?m)^\s*\(heterocloud_envoy\)\s*\{", old)),
            "canonical heterocloud_envoy snippet missing")
    require(old.count(BEGIN) == old.count(END) <= 1, "ambiguous managed markers")
    if BEGIN in old:
        start, end = old.index(BEGIN), old.index(END)
        require(start < end and (start == 0 or old[start - 1:start] == b"\n"),
                "invalid managed block")
        unmanaged = old[:start] + old[end + len(END):]
        new = old[:start] + route(generation) + old[end + len(END):]
    else:
        unmanaged = old
        new = old + b"\n" + route(generation)
    require(HOST.encode() not in unmanaged, "unmanaged wildcard route already exists")
    require(len(new) <= LIMIT, "updated extra exceeds Agent size limit")
    return new


def write_new(parent, name, data, gid, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fchown(stream.fileno(), 0, gid)
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def publish_pair(root, generation, cert, key, gid):
    try:
        os.mkdir(CERTDIR, 0o750, dir_fd=root)
        os.chown(CERTDIR, 0, gid, dir_fd=root, follow_symlinks=False)
    except FileExistsError:
        pass
    parent = os.open(CERTDIR, FLAGS | os.O_DIRECTORY, dir_fd=root)
    try:
        secure(os.fstat(parent), True)
        require(os.fstat(parent).st_gid == gid and
                stat.S_IMODE(os.fstat(parent).st_mode) == 0o750,
                "certificate directory has unexpected permissions")
        try:
            existing = os.open(generation, FLAGS | os.O_DIRECTORY, dir_fd=parent)
        except FileNotFoundError:
            temporary = ".new-" + uuid.uuid4().hex
            os.mkdir(temporary, 0o750, dir_fd=parent)
            stage = os.open(temporary, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            try:
                os.fchown(stage, 0, gid)
                os.fchmod(stage, 0o750)
                write_new(stage, "tls.crt", cert, gid, 0o640)
                write_new(stage, "tls.key", key, gid, 0o640)
                os.fsync(stage)
                os.rename(temporary, generation, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                os.fsync(root)
            finally:
                os.close(stage)
                # Only remove this invocation's unpublished staging files.
                if os.path.exists(f"/proc/self/fd/{parent}/{temporary}"):
                    for name in ("tls.crt", "tls.key"):
                        try:
                            os.unlink(f"{temporary}/{name}", dir_fd=parent)
                        except FileNotFoundError:
                            pass
                    os.rmdir(temporary, dir_fd=parent)
            return
        try:
            st = os.fstat(existing)
            secure(st, True)
            require(st.st_gid == gid and stat.S_IMODE(st.st_mode) == 0o750,
                    "generation directory permissions changed")
            for name, expected in (("tls.crt", cert), ("tls.key", key)):
                data, st = read_file(existing, name)
                require(data == expected and st.st_gid == gid and
                        stat.S_IMODE(st.st_mode) == 0o640, "immutable pair changed")
        finally:
            os.close(existing)
    finally:
        os.close(parent)


def fingerprint(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_uid, st.st_gid, st.st_mode)


def sync(host="/etc/heteronetwork", secret="/var/run/flash-web-tls",
         group_file="/host-group"):
    gid = host_gid(group_file)
    cert, key = secret_pair(secret)
    validate(cert, key)
    generation = hashlib.sha256(len(cert).to_bytes(8, "big") + cert + key).hexdigest()
    with directory(host) as root:
        host_st = os.fstat(root)
        require(host_st.st_mode & 0o001 or (host_st.st_gid == gid and host_st.st_mode & 0o010),
                "host certificate parent is not traversable by Caddy group")
        lock = os.open(".flash-web-tls.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
                       | os.O_NONBLOCK, 0o600, dir_fd=root)
        try:
            secure(os.fstat(lock))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            old, st = read_file(root, EXTRA)
            new = update_content(old, generation)
            publish_pair(root, generation, cert, key, gid)
            if old == new:
                return False
            temporary = ".flash-extra-" + uuid.uuid4().hex
            try:
                write_new(root, temporary, new, st.st_gid, stat.S_IMODE(st.st_mode))
                current, current_st = read_file(root, EXTRA)
                require(current == old and fingerprint(current_st) == fingerprint(st),
                        "extra file changed concurrently; retry later")
                os.replace(temporary, EXTRA, src_dir_fd=root, dst_dir_fd=root)
                os.fsync(root)
            finally:
                try:
                    os.unlink(temporary, dir_fd=root)
                except FileNotFoundError:
                    pass
            return True
        finally:
            os.close(lock)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=int, default=60)
    args = parser.parse_args()
    require(args.interval >= 10, "interval must be at least 10 seconds")
    os.umask(0o027)
    while True:
        try:
            changed = sync()
            Path("/tmp/last-success").touch(mode=0o600)
            print("flash TLS: published" if changed else "flash TLS: unchanged", flush=True)
        except Exception:
            # Do not log exceptions, PEM, subprocess output, or private key paths.
            print("flash TLS: sync failed; check last published state", flush=True)
            if args.once:
                return 1
        else:
            if args.once:
                return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
