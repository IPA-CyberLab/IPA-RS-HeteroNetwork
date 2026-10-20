#!/usr/bin/env python3
"""Prompt privately for the bounded own-VM fault probe, then run the live test."""
import getpass
import os
from pathlib import Path
import subprocess
import sys

if __name__=='__main__':
    password=os.environ.get('HNN_E2E_SUDO_PASSWORD') or getpass.getpass('E2E fixture sudo password: ')
    raise SystemExit(subprocess.run(['node',str(Path(__file__).with_name('flash_operations_live_e2e.mjs')),*sys.argv[1:]],
        env=dict(os.environ,HNN_E2E_SUDO_PASSWORD=password)).returncode)
