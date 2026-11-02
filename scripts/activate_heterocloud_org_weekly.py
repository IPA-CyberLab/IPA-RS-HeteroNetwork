#!/usr/bin/env python3
"""Enable the Flash organization weekly meter after verifying both rollouts.

This validates actual running images and provider policy propagation. Database
credentials are transported through stdin and are never printed or stored.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
from urllib.parse import unquote, urlsplit

FLASH_COMPONENTS = {"api", "controller", "activator", "capacity", "backup-verifier"}
LIMITS = ("max_weekly_cpu_millicore_seconds", "max_weekly_memory_mib_seconds", "max_weekly_gpu_seconds")
SUPPORTED_CLOUD_DIGESTS = {"sha256:6e93235aac7732f99aa85f76f67aae88f7b216e159fe943be61e34d2f803e66a"}
SUPPORTED_FLASH_DIGESTS = {"sha256:1b996062281da5c7562f41c8793cf3a5743d98778297e182f0d63cd27cc13520"}


def verify_flash(data, crd, digest, replicas):
    items = data.get("items", [])
    if not digest.startswith("sha256:") or len(digest) != 71 or any(c not in "0123456789abcdef" for c in digest[7:]):
        raise ValueError("invalid Flash image digest")
    errors = []
    verified = {}
    for component in FLASH_COMPONENTS:
        name = "heterocloud-flash-" + component
        ds = [d for d in items if d.get("kind") == "Deployment" and d.get("metadata", {}).get("name") == name]
        if len(ds) != 1:
            errors.append(f"missing deployment {name}")
            continue
        deployment = ds[0]
        status = deployment.get("status", {})
        containers = deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        if (deployment.get("spec", {}).get("replicas") != replicas or status.get("updatedReplicas", 0) != replicas
                or status.get("readyReplicas", 0) != replicas or status.get("availableReplicas", 0) != replicas
                or status.get("observedGeneration", 0) < deployment.get("metadata", {}).get("generation", 1)
                or len(containers) != 1 or not containers[0].get("image", "").endswith("@" + digest)):
            errors.append(f"{name} rollout is not complete")
        pods = [p for p in items if p.get("kind") == "Pod" and not p.get("metadata", {}).get("deletionTimestamp")
                and p.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name") == "heterocloud-flash"
                and p.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component") == component]
        if len(pods) != replicas:
            errors.append(f"{name} has {len(pods)} active pods, expected {replicas}")
        ready_names = set()
        for pod in pods:
            pod_name = pod["metadata"]["name"]
            states = pod.get("status", {}).get("containerStatuses", [])
            pod_containers = pod.get("spec", {}).get("containers", [])
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in pod.get("status", {}).get("conditions", []))
            if (len(states) != 1 or len(pod_containers) != 1 or not ready or not states[0].get("ready")
                    or not states[0].get("imageID", "").endswith("@" + digest)
                    or not pod_containers[0].get("image", "").endswith("@" + digest)):
                errors.append(f"{pod_name} is not ready on the expected image")
            else:
                ready_names.add(pod_name)
        verified[component] = ready_names
    slices = [i for i in items if i.get("kind") == "EndpointSlice" and i.get("metadata", {}).get("labels", {}).get("kubernetes.io/service-name") == "heterocloud-flash-api"]
    endpoints = [e for s in slices for e in s.get("endpoints", []) if e.get("conditions", {}).get("ready") is True]
    if len(endpoints) != replicas or {e.get("targetRef", {}).get("name") for e in endpoints} != verified.get("api", set()):
        errors.append("Flash API endpoints do not match the verified pods")
    try:
        versions = crd["spec"]["versions"]
        storage = next(v for v in versions if v.get("storage"))
        fields = storage["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["policy"]["properties"]
        if "cloud_organization" not in fields:
            errors.append("Flash CRD does not support the organization policy")
    except (KeyError, StopIteration, TypeError):
        errors.append("cannot validate the Flash CRD schema")
    return errors


def verify_policies(snapshot, provider, require_policy):
    services = snapshot.get("services", [])
    provider_services = [i.get("spec", {}) for i in provider.get("items", [])]
    actual = {i.get("service_instance_id"): i for i in provider_services}
    problems = []
    if None in actual or len(actual) != len(provider_services):
        problems.append("provider has missing or duplicate Flash service identities")
    expected_ids = {s["id"] for s in services}
    if set(actual) - expected_ids:
        problems.append(f"{len(set(actual) - expected_ids)} provider services have no active control-plane record")
    if snapshot.get("pending") != 0:
        problems.append(f"{snapshot.get('pending', 'unknown')} Flash policy refreshes remain queued")
    for service in services:
        service_id = service["id"]
        actual_service = actual.get(service_id)
        if not actual_service:
            problems.append(f"Flash service {service_id} is absent from the provider")
            continue
        if actual_service.get("organization_id") != service["account_id"]:
            problems.append(f"Flash service {service_id} belongs to an unexpected account")
            continue
        accounts = service.get("accounts") or []
        limits = service.get("limits") or {}
        if not accounts or service["account_id"] not in accounts or any(k not in limits for k in LIMITS):
            problems.append(f"Flash service {service_id} has incomplete organization quota metadata")
            continue
        if require_policy:
            policy = actual_service.get("policy", {}).get("cloud_organization") or {}
            if (len(policy.get("account_ids", [])) != len(accounts)
                    or set(policy.get("account_ids", [])) != set(accounts)
                    or any(policy.get(k) != limits[k] for k in LIMITS)):
                problems.append(f"Flash service {service_id} has a stale organization quota policy")
    return problems


def run_json(args, timeout=30):
    return json.loads(subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cloud-digest", required=True)
    p.add_argument("--flash-digest", required=True)
    p.add_argument("--replicas", type=int, default=2)
    p.add_argument("--cloud-desired-replicas", type=int, default=3)
    p.add_argument("--ssh-key", required=True)
    p.add_argument("--known-hosts", required=True)
    p.add_argument("--jump-host", required=True)
    p.add_argument("--wait-seconds", type=int, default=240)
    args = p.parse_args()
    kubectl = os.environ.get("KUBECTL", "kubectl")
    try:
        if args.cloud_digest not in SUPPORTED_CLOUD_DIGESTS or args.flash_digest not in SUPPORTED_FLASH_DIGESTS:
            raise RuntimeError("the release digests are not approved for organization weekly quotas")
        module_path = Path(__file__).with_name("verify-heterocloud-iam-rollout.py")
        spec = importlib.util.spec_from_file_location("verify_heterocloud_iam_rollout", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cloud = run_json([kubectl, "-n", "heterocloud", "get", "deployments,pods,endpointslices", "-o", "json"])
        problems = module.verify(cloud, args.cloud_digest, args.replicas, args.cloud_desired_replicas)
        flash = run_json([kubectl, "-n", "heterocloud-flash", "get", "deployments,pods,endpointslices", "-o", "json"])
        crd = run_json([kubectl, "get", "crd", "flashservices.flash.heterocloud.io", "-o", "json"])
        problems += verify_flash(flash, crd, args.flash_digest, args.replicas)
        if problems:
            raise RuntimeError("; ".join(problems))
        secret = subprocess.run([kubectl, "-n", "heterocloud", "exec", "deployment/heterocloud-heterocloud", "-c", "api", "--", "cat", "/var/run/secrets/runtime/database-url"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        parsed = urlsplit(secret)
        if parsed.scheme not in ("postgres", "postgresql") or parsed.hostname != "127.0.0.1" or parsed.port != 25432 or parsed.path != "/heterocloud" or parsed.query:
            raise RuntimeError("unexpected database connection target")
        credential = {"user": unquote(parsed.username or ""), "password": unquote(parsed.password or ""), "database": parsed.path[1:]}
        sql = """SET jit = off; SELECT json_build_object(
          'enabled',a.organization_flash_weekly_quotas_enabled,
          'pending',(SELECT count(*) FROM outbox_events WHERE topic='service-instance.flash-quota' AND delivered_at IS NULL),
          'services',COALESCE((SELECT json_agg(json_build_object(
            'id',s.id,'account_id',s.organization_id,
            'accounts',(SELECT json_agg(ca2.account_id ORDER BY ca2.account_id) FROM cloud_organization_accounts ca2 WHERE ca2.organization_id=ca.organization_id),
            -- Match FlashQuotaLimits' serde defaults for older quota rows.
            'limits',jsonb_build_object('max_weekly_cpu_millicore_seconds',3245760000,
                    'max_weekly_memory_mib_seconds',2836280317,'max_weekly_gpu_seconds',40320)
                    || (COALESCE(q.limits,d.limits)->'flash')) ORDER BY s.id)
            FROM service_instances s LEFT JOIN cloud_organization_accounts ca ON ca.account_id=s.organization_id
            LEFT JOIN cloud_organizations c ON c.id=ca.organization_id
            LEFT JOIN organization_resource_quotas q ON q.organization_id=c.management_account_id
            WHERE s.provider='flash' AND s.state <> 'deleting'), '[]'::json))
          FROM cloud_security_activation a CROSS JOIN resource_quota_defaults d WHERE a.singleton AND d.singleton"""
        remote = ("import json,os,sys; c=json.load(sys.stdin); e=os.environ.copy(); "
                  "e.update(PGHOST='127.0.0.1',PGPORT='25432',PGUSER=c['user'],PGPASSWORD=c['password'],"
                  "PGDATABASE=c['database'],PGCONNECT_TIMEOUT='10'); "
                  "os.execvpe('psql',['psql','-XqAt','--set','ON_ERROR_STOP=1','-c',c['sql']],e)")
        def snapshot():
            data = {**credential, "sql": sql}
            result = subprocess.run(["ssh", "-i", args.ssh_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={args.known_hosts}", "-o", "ConnectTimeout=8", args.jump_host, "python3 -c " + shlex.quote(remote)], input=json.dumps(data), check=True, capture_output=True, text=True, timeout=30)
            return json.loads(result.stdout)
        def provider():
            return run_json([kubectl, "get", "flashservices.flash.heterocloud.io", "-A", "-o", "json"])
        before = snapshot()
        problems = verify_policies(before, provider(), before.get("enabled") is True)
        if problems:
            raise RuntimeError("pre-activation: " + "; ".join(problems))
        deployment = next(i for i in cloud["items"] if i.get("kind") == "Deployment" and i.get("metadata", {}).get("name") == "heterocloud-heterocloud-worker")
        container = next(c for c in deployment["spec"]["template"]["spec"]["containers"] if c["name"] == "worker")
        command = container.get("command", []) + container.get("args", [])
        if not command or command[0] != "/usr/local/bin/heterocloud-worker":
            raise RuntimeError("unexpected worker command")
        subprocess.run([kubectl, "-n", "heterocloud", "exec", "deployment/heterocloud-heterocloud-worker", "-c", "worker", "--", *command, "--enable-organization-flash-weekly-quotas"], check=True, capture_output=True, text=True, timeout=60)
        deadline = time.monotonic() + args.wait_seconds
        while True:
            current = snapshot()
            problems = verify_policies(current, provider(), True)
            if current.get("enabled") is True and not problems:
                # Detect a quota/account change between reading the database and
                # inspecting provider resources. Such a change enqueues another
                # refresh and must be observed before we report convergence.
                if snapshot() == current:
                    print(f"Verified organization weekly policies for {len(current['services'])} Flash services; refresh queue is empty.")
                    return 0
                problems = ["quota state changed during verification"]
            if time.monotonic() >= deadline:
                raise RuntimeError("activation completed, but verification did not converge: " + "; ".join(problems))
            time.sleep(3)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError, KeyError, StopIteration, TypeError) as error:
        if isinstance(error, RuntimeError):
            print(f"Weekly quota activation refused: {error}", file=sys.stderr)
        else:
            print(f"Weekly quota activation failed: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
