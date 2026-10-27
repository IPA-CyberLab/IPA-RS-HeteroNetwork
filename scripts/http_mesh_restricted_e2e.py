#!/usr/bin/env python3
"""Run the compiled HTTP mesh acceptance test without root, UDP or TUN setup.

The filter is inherited by all Go threads and Rust fixture processes. Only
ordinary HTTP/TCP sockets and the in-process VPN stack remain available.
"""
import ctypes
import errno
import os
from pathlib import Path
import sys


class Comparison(ctypes.Structure):
    _fields_ = [('argument', ctypes.c_uint), ('operation', ctypes.c_uint),
                ('value_a', ctypes.c_uint64), ('value_b', ctypes.c_uint64)]


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: http_mesh_restricted_e2e.py COMPILED_TEST [ARGS...]')
    library = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                              ctypes.c_int, ctypes.c_uint,
                                              ctypes.POINTER(Comparison)]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    context = library.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError('cannot allocate seccomp filter')

    def deny(name, comparisons):
        syscall = library.seccomp_syscall_resolve_name(name.encode())
        if syscall < 0:
            raise RuntimeError(f'unknown syscall: {name}')
        values = (Comparison * len(comparisons))(*comparisons)
        result = library.seccomp_rule_add_array(context, 0x00050000 | errno.EPERM,
                                                syscall, len(comparisons), values)
        if result < 0:
            raise OSError(-result, f'cannot restrict {name}')

    for family in (2, 10):  # AF_INET / AF_INET6; mask SOCK_NONBLOCK/CLOEXEC
        deny('socket', [Comparison(0, 4, family, 0), Comparison(1, 7, 15, 2)])
    deny('ioctl', [Comparison(1, 4, 0x400454CA, 0)])  # TUNSETIFF
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'cannot set no_new_privs')
    if library.seccomp_load(context) < 0:
        raise RuntimeError('cannot install seccomp filter')
    library.seccomp_release(context)
    if os.geteuid() == 0:
        for capability in range(int(Path('/proc/sys/kernel/cap_last_cap').read_text()) + 1):
            libc.prctl(24, capability, 0, 0, 0)  # PR_CAPBSET_DROP
        os.setgroups([])
        os.setgid(65534)
        os.setuid(65534)
    os.environ['HETERONETWORK_HTTP_MESH_RESTRICTED'] = '1'
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == '__main__':
    main()
