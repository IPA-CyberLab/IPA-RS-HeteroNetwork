#!/usr/bin/env python3
"""Backport DB-outage Agent retention to the verified older bootstrap host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


ORIGINAL = 'b571093d6ec8aa0f5e0b1a071f73db4bc02d2bc5af8ad3eb6998a4ea4e3d87a6'
PATCHED = 'e47db39acfa9258cf6fb483281e7f4097ba8e09ad1054c8e57b1f154683febd8'
DEDUPED = '45de7141c1fcfb8c44f90a810be9f17693ce57f213e7ab76d12ac954aa5f0e66'

URL_DEDUPE_HELPER = '''dedupe_control_plane_urls() {
  dedupe_csv_value=$1
  dedupe_csv_result=
  dedupe_csv_old_ifs=$IFS
  IFS=,
  set -- $dedupe_csv_value
  IFS=$dedupe_csv_old_ifs
  for dedupe_csv_entry do
    while [ "${dedupe_csv_entry%/}" != "$dedupe_csv_entry" ]; do
      dedupe_csv_entry=${dedupe_csv_entry%/}
    done
    [ -n "$dedupe_csv_entry" ] || return 1
    case ",$dedupe_csv_result," in
      *,"$dedupe_csv_entry",*) continue ;;
    esac
    if [ -n "$dedupe_csv_result" ]; then
      dedupe_csv_result="$dedupe_csv_result,$dedupe_csv_entry"
    else
      dedupe_csv_result=$dedupe_csv_entry
    fi
  done
  [ -n "$dedupe_csv_result" ] || return 1
  printf '%s' "$dedupe_csv_result"
}
'''

REPLACEMENTS = (
    ('''    if ! unit_is_active "$control_plane_service"; then
      systemctl start "$control_plane_service" >/dev/null 2>&1 ||
        log "unable to restore Control Plane while retaining promoted services"
    fi
''', '''    if ! unit_is_active "$control_plane_service"; then
      if postgres_proxy_is_ready; then
        systemctl start "$control_plane_service" >/dev/null 2>&1 ||
          log "unable to restore Control Plane while retaining promoted services"
      else
        log "not starting Control Plane while the PostgreSQL HA proxy is unavailable"
      fi
    fi
'''),
    ('''  "$agent_status_url" >"$status_file"; then
  demote_and_exit "local Agent status is unavailable"
''', '''  "$agent_status_url" >"$status_file"; then
  if retain_existing_public_services "local Agent status is unavailable"; then
    reconcile_finished=1
    exit 0
  fi
  demote_and_exit "local Agent status is unavailable"
'''),
    ('''if ! postgres_proxy_is_ready; then
  demote_control_and_exit "local PostgreSQL HA proxy is unavailable"
fi
''', '''if ! postgres_proxy_is_ready; then
  # Withdraw the stateless Control Plane but keep established VPN/DNS paths.
  if existing_public_services_are_staged &&
    [ -f "$agent_gateway_drop_in" ] && [ ! -L "$agent_gateway_drop_in" ]; then
    if stop_unit "$control_plane_service"; then
      log "local PostgreSQL HA proxy is unavailable; retaining Agent and staged configuration"
      reconcile_finished=1
      exit 0
    fi
  fi
  demote_control_and_exit "local PostgreSQL HA proxy is unavailable"
fi
'''),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def transform(data):
    if digest(data) != ORIGINAL:
        raise ValueError('legacy public-services source does not match the reviewed version')
    result = data.decode('utf-8')
    for old, new in REPLACEMENTS:
        if result.count(old) != 1:
            raise ValueError('legacy public-services patch did not match exactly once')
        result = result.replace(old, new, 1)
    return result.encode('utf-8')


def transform_signal_urls(data):
    if digest(data) != PATCHED:
        raise ValueError('legacy public-services source does not match the reviewed DB backport')
    result = data.decode('utf-8')
    replacements = (
        ('valid_url_csv() {', URL_DEDUPE_HELPER + '\nvalid_url_csv() {'),
        ('  signal_control_plane_urls="http://$vpn_ip:19088,$signal_control_plane_seed_urls"',
         '  signal_control_plane_urls=$(dedupe_control_plane_urls "http://$vpn_ip:19088,$signal_control_plane_seed_urls") ||\n'
         '    demote_and_exit "unable to normalize Signal Control Plane URLs"'),
        ('signal_control_plane_urls="http://$vpn_ip:19088,$bootstrap_control_plane_urls"',
         'signal_control_plane_urls=$(dedupe_control_plane_urls "http://$vpn_ip:19088,$bootstrap_control_plane_urls") ||\n'
         '  demote_control_and_exit "unable to normalize Signal Control Plane URLs"'),
    )
    for old, new in replacements:
        if result.count(old) != 1:
            raise ValueError('legacy Signal URL patch did not match exactly once')
        result = result.replace(old, new, 1)
    return result.encode('utf-8')


def require_private_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.is_symlink()
            or info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise ValueError('a protected operator directory is required')


def apply(path, backup_dir):
    path, backup_dir = Path(path), Path(backup_dir)
    if not path.is_absolute() or not backup_dir.is_absolute():
        raise ValueError('absolute paths are required')
    require_private_directory(path.parent)
    require_private_directory(backup_dir)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as current:
        info = os.fstat(current.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o022 or info.st_nlink != 1 or info.st_size > 1024 * 1024):
            raise ValueError('the existing public-services helper is unsafe')
        data = current.read()
    source_digest = digest(data)
    if source_digest == DEDUPED:
        return {'changed': False, 'sha256': DEDUPED}
    base = transform(data) if source_digest == ORIGINAL else data
    updated = transform_signal_urls(base)
    if digest(updated) != DEDUPED:
        raise ValueError('legacy Signal URL patch checksum differs from the reviewed result')
    backup = backup_dir / ('public-services-autopilot.' + source_digest + '.sh')
    try:
        backup_fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if backup.is_symlink() or digest(backup.read_bytes()) != source_digest:
            raise ValueError('existing backup does not match the reviewed source')
    else:
        with os.fdopen(backup_fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    fd, temporary = tempfile.mkstemp(prefix='.public-services-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode))
            os.fchown(output.fileno(), info.st_uid, info.st_gid)
            output.write(updated)
            output.flush()
            os.fsync(output.fileno())
        subprocess.run(['/bin/sh', '-n', temporary], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        now = path.stat(follow_symlinks=False)
        if (now.st_ino, now.st_mtime_ns, now.st_size) != (info.st_ino, info.st_mtime_ns, info.st_size):
            raise ValueError('public-services helper changed during the update')
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {'changed': True, 'sha256': DEDUPED}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--file', required=True, type=Path)
    parser.add_argument('--backup-dir', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(apply(args.file, args.backup_dir)))


if __name__ == '__main__':
    main()
