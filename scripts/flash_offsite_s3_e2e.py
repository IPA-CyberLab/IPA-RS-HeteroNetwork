#!/usr/bin/env python3
"""Real S3 copy/delete/recovery test using three new, size-limited private buckets.

This proves S3 protocol and data integrity; the test buckets share Garage and do
NOT represent an independent production backup failure domain. No existing
bucket, object, workload or credential is modified. Credential values stay in
memory and never appear in arguments, reports or logs.
"""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubectl", required=True)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--provider-ops", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.provider_ops.resolve()))
    import offsite

    run = uuid.uuid4().hex
    report = {"run_id": run, "result": "incomplete", "scope": "real_s3_synthetic_objects_same_failure_domain", "checks": {}, "cleanup": {}}
    prefix = "flash-offsite-e2e-"+run[:12]
    command = [args.kubectl, "--kubeconfig="+args.kubeconfig, "-n", "heterocloud-syouyu"]
    forwards, buckets, key = [], [], None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), offsite.NoRedirect())
    stage = "configuration"
    admin_token = None

    def admin(operation, body=None, **query):
        suffix = "?"+urllib.parse.urlencode(query) if query else ""
        data = json.dumps(body).encode() if body is not None else (b"" if operation.startswith("Delete") else None)
        request = urllib.request.Request(admin_url+"/v2/"+operation+suffix, data=data,
            headers={"Authorization": "Bearer "+admin_token, "Content-Type": "application/json"})
        with opener.open(request, timeout=20) as response:
            data = response.read(2*1024**2)
            return json.loads(data) if data else None

    def tunnel(remote):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); port = sock.getsockname()[1]
        process = subprocess.Popen(command+["port-forward", "pod/heterocloud-syouyu-garage-0", "--address=127.0.0.1", f"{port}:{remote}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        forwards.append(process)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return f"http://127.0.0.1:{port}"
            except OSError:
                if process.poll() is not None:raise RuntimeError("private_tunnel_failed")
                time.sleep(.1)
        raise RuntimeError("private_tunnel_timeout")

    try:
        result = subprocess.run(command+["get", "secret", "heterocloud-syouyu-secrets", "-o", "json"], capture_output=True, text=True, timeout=30)
        if result.returncode:raise RuntimeError("protected_admin_access_failed")
        admin_token = base64.b64decode(json.loads(result.stdout)["data"]["garage-admin-token"]).decode()
        admin_url, endpoint = tunnel(3903), tunnel(3900)
        existing = admin("ListBuckets")
        aliases = {a for bucket in existing for a in bucket.get("globalAliases", [])}
        if any(prefix+"-"+name in aliases for name in ("source", "copy", "recovery")):
            raise RuntimeError("fresh_bucket_identity_required")
        stage = "private_fixtures"
        key = admin("CreateKey", {"name": prefix, "expiration": None, "neverExpires": True})
        stores = []
        for name in ("source", "copy", "recovery"):
            bucket = admin("CreateBucket", {"globalAlias": prefix+"-"+name})
            buckets.append(bucket)
            admin("UpdateBucket", {"quotas": {"maxSize": 16*1024**2, "maxObjects": 100}}, id=bucket["id"])
            admin("AllowBucketKey", {"bucketId": bucket["id"], "accessKeyId": key["accessKeyId"], "permissions": {"read": True, "write": True, "owner": False}})
            stores.append(offsite.S3({"endpoint": endpoint, "bucket": prefix+"-"+name, "region": "heteronet-global", "access_key": key["accessKeyId"], "secret_key": key["secretAccessKey"], "private_source": True}))
        source, destination, recovery = stores
        payload = secrets.token_bytes(2*1024**2)
        expected = {"volumes/test/blocks/payload": payload, "volumes/test/backup.cfg": json.dumps({"run_id": run}).encode()}
        for name, value in expected.items():source.request("PUT", name, value)
        signing_key = secrets.token_bytes(32)
        stage = "copy_and_verify_real_s3"
        catalog, _ = offsite.copy_generation(source, destination, signing_key, {"backups": [], "fixture": run}, max_bytes=4*1024**2, max_destination_bytes=8*1024**2)
        report["checks"]["signed_catalog_committed_after_object_verification"] = True
        for item in list(source.listing()):source.request("DELETE", item["key"])
        if list(source.listing()):raise RuntimeError("fixture_source_not_deleted")
        stage = "restore_after_original_objects_deleted"
        offsite.restore_generation(destination, recovery, catalog, signing_key)
        if {item["key"] for item in recovery.listing()} != set(expected):raise RuntimeError("recovered_inventory_mismatch")
        for name, value in expected.items():
            if recovery.request("GET", name) != value:raise RuntimeError("recovered_bytes_mismatch")
        report["checks"]["recovered_original_bytes_after_source_deletion"] = True
        try:offsite.restore_generation(destination, recovery, catalog, signing_key)
        except RuntimeError:report["checks"]["nonempty_recovery_destination_refused"] = True
        else:raise RuntimeError("nonempty_restore_was_allowed")
        for store in stores:
            try:
                with opener.open(store.config["endpoint"]+"/"+store.config["bucket"]+"?list-type=2", timeout=10):
                    raise RuntimeError("fixture_bucket_is_public")
            except urllib.error.HTTPError as error:
                if error.code not in (403,404):raise
        report["checks"]["anonymous_bucket_listing_refused"] = True
        report["result"] = "passed"
    except Exception:
        report["result"] = "failed"
        report["failure_stage"] = stage
    finally:
        cleaned = True
        for bucket in buckets:
            try:
                current = admin("GetBucketInfo", id=bucket["id"])
                if not all(a.startswith(prefix+"-") for a in current["globalAliases"]):raise RuntimeError("foreign_cleanup_guard")
                store = offsite.S3({"endpoint": endpoint, "bucket": current["globalAliases"][0], "region": "heteronet-global", "access_key": key["accessKeyId"], "secret_key": key["secretAccessKey"], "private_source": True})
                for item in list(store.listing()):store.request("DELETE", item["key"])
                admin("DeleteBucket", id=bucket["id"])
            except Exception:cleaned = False
        if key:
            try:admin("DeleteKey", id=key["accessKeyId"])
            except Exception:cleaned = False
        report["cleanup"]["all_fixture_objects_buckets_and_key_removed"] = cleaned
        if not cleaned:report["result"] = "failed"
        for process in forwards:
            process.terminate()
            process.wait(timeout=10)
        descriptor = os.open(args.report, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o600)
        with os.fdopen(descriptor,"w") as output:json.dump(report,output,indent=2)
        print(json.dumps(report))
    return 0 if report["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
