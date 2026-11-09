#!/usr/bin/env python3
"""Expose only aggregate local PostgreSQL DCS health on the private overlay."""
import argparse
import http.server
import ipaddress
import math
import re
import threading
import urllib.request


UPSTREAM = 'http://127.0.0.1:12381/metrics'
MAX_BODY = 1024 * 1024
NUMBER = r'([-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?)'
SCALAR = re.compile(r'^(etcd_server_has_leader|etcd_server_leader_changes_seen_total)\s+' + NUMBER + r'$')
PEER = re.compile(r'^etcd_network_active_peers(\{[^\r\n]*\})\s+' + NUMBER + r'$')


def project(body):
    if len(body) > MAX_BODY:
        raise ValueError('metrics are oversized')
    scalars = {}
    peers = 0
    seen_peers = set()
    for line in body.decode('utf-8').splitlines():
        match = SCALAR.fullmatch(line)
        if match:
            name, raw = match.groups()
            value = float(raw)
            if name in scalars or not math.isfinite(value) or value < 0:
                raise ValueError('invalid local DCS metric')
            scalars[name] = value
            continue
        match = PEER.fullmatch(line)
        if match:
            labels, raw = match.groups()
            value = float(raw)
            if labels in seen_peers or value not in (0, 1):
                raise ValueError('invalid peer health metric')
            seen_peers.add(labels)
            peers += int(value)
        elif line.startswith(('etcd_server_has_leader ',
                              'etcd_server_leader_changes_seen_total ',
                              'etcd_network_active_peers{')):
            raise ValueError('invalid local DCS metric')
    leader = scalars.get('etcd_server_has_leader')
    changes = scalars.get('etcd_server_leader_changes_seen_total')
    if leader not in (0, 1) or changes is None:
        raise ValueError('required DCS metrics are missing')
    return (f'heteronetwork_postgres_dcs_has_leader {int(leader)}\n'
            f'heteronetwork_postgres_dcs_active_peers {peers}\n'
            f'heteronetwork_postgres_dcs_leader_changes_total {changes:.17g}\n').encode()


def collect():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(UPSTREAM, timeout=2) as response:
        if response.status != 200:
            raise ValueError('local DCS metrics unavailable')
        return project(response.read(MAX_BODY + 1))


def handler(allowed, collector=collect):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            try:
                source = ipaddress.ip_address(self.client_address[0])
                if not any(source in network for network in allowed):
                    self.send_error(403)
                    return
                if self.path != '/metrics':
                    self.send_error(404)
                    return
                body = collector()
            except Exception:
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            request.settimeout(3)
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listen', required=True)
    parser.add_argument('--port', type=int, default=19181)
    parser.add_argument('--allow', action='append', required=True)
    args = parser.parse_args()
    address = ipaddress.ip_address(args.listen)
    overlay = ipaddress.ip_network('10.250.0.0/16')
    networks = [ipaddress.ip_network(item) for item in args.allow]
    if (address not in overlay or not 1024 <= args.port <= 65535
            or not 1 <= len(networks) <= 16
            or any(network.version != 4 or not network.subnet_of(overlay) for network in networks)):
        raise ValueError('DCS metrics must use the declared private overlay')
    with Server((str(address), args.port), handler(networks)) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
