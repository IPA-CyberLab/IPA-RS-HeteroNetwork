#!/usr/bin/env python3
"""Exercise the real identity connector with a disposable local backend."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.error
import urllib.request


CONFIG = Path(__file__).resolve().parents[1] / "deploy/gitops/cluster-dns/keycloak-haproxy.cfg"


class Backend(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def request(path):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open("http://127.0.0.1:18079" + path, timeout=2) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, ""


def main():
    backend = ThreadingHTTPServer(("127.0.0.1", 18080), Backend)
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    worker.start()
    env = os.environ.copy()
    env["NODE_IP"] = "127.0.0.1"
    subprocess.run(["haproxy", "-c", "-f", str(CONFIG)], env=env, check=True)
    process = subprocess.Popen(["haproxy", "-f", str(CONFIG)], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if request("/connector-ready")[0] == 200:
                    break
            except urllib.error.URLError:
                pass
            time.sleep(0.25)
        else:
            raise RuntimeError("connector did not become ready")
        for path in ("/realms/heteronetwork/device", "/resources/theme/login.css", "/robots.txt"):
            status, body = request(path)
            if status != 200 or body != path:
                raise RuntimeError("private identity request did not reach the backend: " + path)
        for path in ("/admin/", "/metrics"):
            if request(path)[0] != 404:
                raise RuntimeError("connector exposed an unrelated endpoint: " + path)
        print("private identity connector: realm and assets reachable; unrelated paths denied")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        backend.shutdown()
        worker.join()
        backend.server_close()


if __name__ == "__main__":
    main()
