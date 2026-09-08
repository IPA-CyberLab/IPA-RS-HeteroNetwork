#!/usr/bin/env python3
"""Bounded, credential-free login-page monitoring; does not create accounts."""

import argparse
import json
import pathlib
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=600)
    args = parser.parse_args()
    if not 60 <= args.duration_seconds <= 1800:
        parser.error("duration-seconds must be between 60 and 1800")
    script = pathlib.Path(__file__).with_name("keycloak-ha-e2e.sh")
    start = time.monotonic()
    failures = 0
    attempts = 0
    while time.monotonic() - start < args.duration_seconds:
        attempts += 1
        try:
            result = subprocess.run(
                ["bash", str(script), "--public-only", "--attempts", "1"],
                capture_output=True, text=True, timeout=60,
            )
            passed = result.returncode == 0
            detail = (result.stdout + result.stderr)[-1200:]
        except subprocess.TimeoutExpired:
            passed, detail = False, "Login-page check exceeded 60 seconds"
        failures += not passed
        print(json.dumps({"attempt": attempts, "passed": passed,
                          "elapsed_seconds": round(time.monotonic() - start),
                          "detail": detail}), flush=True)
        remaining = args.duration_seconds - (time.monotonic() - start)
        if remaining > 0:
            time.sleep(min(15, remaining))
    print(json.dumps({"attempts": attempts, "failures": failures,
                      "duration_seconds": round(time.monotonic() - start)}), flush=True)
    raise SystemExit(1 if failures else 0)


if __name__ == "__main__":
    main()
