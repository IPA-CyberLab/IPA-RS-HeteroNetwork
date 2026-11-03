#!/usr/bin/env python3
"""Activate IAM time conditions only after verifying every serving replica."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from urllib.parse import unquote, urlsplit


SUPPORTED_DIGESTS = {"sha256:6e93235aac7732f99aa85f76f67aae88f7b216e159fe943be61e34d2f803e66a", "sha256:557302cf2facc153795328921729efbbaab9a310eb54ce440a0a9dfd78cdd1af", "sha256:8d27f736bd182a5d5ebb36f59d18c0551e9b4bde49b590bbf8ebbb365c898e1b", "sha256:f1fa2604777714325289ecf5ee8c743d0dda8f3a424415b2706ac0ee95d1ff16", "sha256:1346a90187cc39926c5df2b36ed9093528e8fe0e1b65f3ab8177a635ec1a729f", "sha256:691e7ed9143b873fd3d7e5bab2d6e777d1ba3ef6b6c9aaf71fc71c6eeed2f137", "sha256:0a5a0c71297f36b56ebde70feb9a36fee68274e42348c974d971683ce99067df"}


def verify_rollout(data, digest, replicas, desired_replicas):
    if digest not in SUPPORTED_DIGESTS:
        raise RuntimeError("the release digest is not approved for IAM conditions")
    path = Path(__file__).with_name("verify-heterocloud-iam-rollout.py")
    spec = importlib.util.spec_from_file_location("verify_heterocloud_iam_rollout", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    problems = module.verify(data, digest, replicas, desired_replicas)
    if problems:
        raise RuntimeError("; ".join(problems))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--replicas", type=int, default=2)
    parser.add_argument("--desired-replicas", type=int)
    parser.add_argument("--ssh-key", required=True)
    parser.add_argument("--known-hosts", required=True)
    parser.add_argument("--jump-host", required=True)
    args = parser.parse_args()
    kubectl = os.environ.get("KUBECTL", "kubectl")
    try:
        result = subprocess.run(
            [kubectl, "-n", "heterocloud", "get", "deployments,pods,endpointslices", "-o", "json"],
            check=True, capture_output=True, text=True, timeout=30,
        )
        verify_rollout(json.loads(result.stdout), args.digest, args.replicas, args.desired_replicas)
        # The credential is transferred only through process stdin. It is not
        # put in the command line, Terraform state, or logs.
        secret = subprocess.run(
            [kubectl, "-n", "heterocloud", "exec", "deployment/heterocloud-heterocloud", "-c", "api", "--", "cat", "/var/run/secrets/runtime/database-url"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        parsed = urlsplit(secret)
        if (parsed.scheme not in ("postgres", "postgresql") or parsed.hostname != "127.0.0.1"
                or parsed.port != 25432 or parsed.path != "/heterocloud" or parsed.query):
            raise RuntimeError("unexpected database connection target")
        credential = {"user": unquote(parsed.username or ""), "password": unquote(parsed.password or ""), "database": parsed.path[1:]}
        sql = ("BEGIN; SELECT pg_advisory_xact_lock(hashtextextended('heterocloud-iam-conditions', 0)); "
               "UPDATE cloud_security_activation SET iam_conditions_enabled=true WHERE singleton=true; "
               "DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM cloud_security_activation WHERE singleton=true AND iam_conditions_enabled) "
               "THEN RAISE EXCEPTION 'IAM condition activation failed'; END IF; END $$; COMMIT;")
        remote = ("import json,os,sys; c=json.load(sys.stdin); e=os.environ.copy(); "
                  "e.update(PGHOST='127.0.0.1',PGPORT='25432',PGUSER=c['user'],PGPASSWORD=c['password'],"
                  "PGDATABASE=c['database'],PGCONNECT_TIMEOUT='10'); "
                  "os.execvpe('psql',['psql','-XqAt','--set','ON_ERROR_STOP=1','-c',c['sql']],e)")
        credential["sql"] = sql
        subprocess.run(
            ["ssh", "-i", args.ssh_key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
             "-o", f"UserKnownHostsFile={args.known_hosts}", "-o", "ConnectTimeout=8", args.jump_host,
             "python3 -c " + shlex.quote(remote)],
            input=json.dumps(credential), check=True, capture_output=True, text=True, timeout=60,
        )
        print(f"Activated IAM time conditions after verifying {args.replicas} serving replicas per component.")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        # Provider/database diagnostics may contain secrets; expose only the
        # locally constructed rollout verification errors.
        if isinstance(error, RuntimeError):
            print(f"IAM condition activation refused: {error}", file=sys.stderr)
        else:
            print(f"Organization IAM condition activation failed: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
