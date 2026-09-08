#!/usr/bin/env python3
"""Check external TCP/UDP delivery to the disposable Flash autoscaling fixture.

Run outside the VPN/cluster to verify the public ingress path. Responses must
identify Flash fixture Pods; do not point this at arbitrary tenant applications.
"""

import argparse
from collections import Counter
import http.client
import ipaddress
import json
import socket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    parser.add_argument("--requests", type=int, default=10)
    parser.add_argument("--expect-backends", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.requests <= 50:
        parser.error("invalid port or request count (maximum 50 per ingress)")
    if not 1 <= args.expect_backends <= args.requests:
        parser.error("expect-backends must be within the request count")
    addresses = sorted({entry[4][0] for entry in socket.getaddrinfo(
        args.hostname, args.port, socket.AF_INET, socket.SOCK_STREAM
    )})
    if not addresses or len(addresses) > 16 or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        parser.error("expected 1..16 public ingress addresses")
    failures = []
    for address in addresses:
        backends = Counter()
        for _ in range(args.requests):
            try:
                if args.protocol == "tcp":
                    connection = http.client.HTTPConnection(address, args.port, timeout=3)
                    try:
                        connection.request("GET", "/", headers={"Host": args.hostname})
                        response = connection.getresponse()
                        if response.status != 200:
                            raise ValueError(f"HTTP {response.status}")
                        body = response.read(256).decode().strip()
                    finally:
                        connection.close()
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
                        connection.settimeout(3)
                        connection.connect((address, args.port))
                        connection.send(b"flash-e2e".ljust(128, b"."))
                        body = connection.recv(256).decode().strip()
                if not body.startswith("flash-") or any(char.isspace() for char in body):
                    raise ValueError("response is not a Flash fixture Pod name")
                backends[body] += 1
            except (OSError, ValueError, http.client.HTTPException) as error:
                failures.append({"ingress": address, "error": str(error)})
        print(json.dumps({"ingress": address, "protocol": args.protocol,
                          "responses": sum(backends.values()), "backends": dict(backends)}), flush=True)
        if len(backends) < args.expect_backends:
            failures.append({"ingress": address, "error": "too few distinct backend Pods"})
    if failures:
        raise SystemExit(json.dumps({"failures": failures}))


if __name__ == "__main__":
    main()
