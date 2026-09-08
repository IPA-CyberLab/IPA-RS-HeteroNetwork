#!/usr/bin/env python3
"""Verify Flash's public portless HTTP redirect and trusted HTTPS response."""

import argparse
import ipaddress
import json
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


def request(host, scheme, origin=None):
    with tempfile.TemporaryDirectory(prefix="flash-web-preflight-") as directory:
        headers = Path(directory) / "headers"
        command = [
            "curl", "--silent", "--show-error", "--noproxy", "*",
            "--connect-timeout", "10", "--max-time", "20",
            "--dump-header", str(headers), "--output", "/dev/null",
            "--write-out", "%{json}",
        ]
        if origin:
            address = str(ipaddress.ip_address(origin))
            if ":" in address:
                address = f"[{address}]"
            port = 443 if scheme == "https" else 80
            command.extend(["--resolve", f"{host}:{port}:{address}"])
        command.append(f"{scheme}://{host}/")
        result = subprocess.run(command, capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError(f"{scheme} via {origin or 'DNS'}: {result.stderr.strip()}")
        metrics = json.loads(result.stdout)
        locations = [line.split(":", 1)[1].strip() for line in
                     headers.read_text().splitlines() if line.lower().startswith("location:")]
        return metrics, locations[-1] if locations else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--origin", action="append", default=[],
                        help="Also verify an individual public gateway with correct TLS SNI")
    parser.add_argument("--expected-status", type=int, default=200)
    args = parser.parse_args()
    if len(args.host) > 253 or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+",
        args.host,
    ):
        parser.error("--host must be a DNS hostname without scheme or port")
    for origin in [None, *args.origin]:
        http, location = request(args.host, "http", origin)
        target = urlsplit(location or "")
        if http["http_code"] not in (301, 302, 307, 308) or (
            target.scheme, target.netloc, target.path
        ) != ("https", args.host, "/"):
            raise SystemExit(f"Invalid portless HTTPS redirect via {origin or 'DNS'}")
        https, _ = request(args.host, "https", origin)
        if https["http_code"] != args.expected_status or https["ssl_verify_result"] != 0:
            raise SystemExit(f"HTTPS check failed via {origin or 'DNS'}: {https['http_code']}")
        print(json.dumps({"origin": origin or "DNS", "host": args.host,
                          "http": http["http_code"], "https": https["http_code"],
                          "tls_verified": True, "seconds": https["time_total"]}))


if __name__ == "__main__":
    main()
