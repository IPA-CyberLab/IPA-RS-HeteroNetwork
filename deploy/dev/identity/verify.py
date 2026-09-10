#!/usr/bin/env python3
"""Read-only runtime checks for the dedicated DEV identity database."""
import importlib.util
import json
from pathlib import Path


def main():
    spec = importlib.util.spec_from_file_location("identity_apply", Path(__file__).with_name("apply.py"))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.guard()
    run, require = helper.run, helper.require
    namespace = "hetero-dev-identity"

    def get(kind, name):
        return json.loads(run(["get", kind, name, "-n", namespace, "-o", "json"]))

    cluster = get("cluster.postgresql.cnpg.io", "dev-identity-postgres")
    require(cluster["status"].get("readyInstances") == 3)
    primary = cluster["status"]["currentPrimary"]
    names = [f"dev-identity-postgres-{i}" for i in range(1, 4)]
    require(primary in names)
    results = []
    for number, name in enumerate(names, 1):
        pod = get("pod", name)
        require(pod["spec"]["nodeName"] == f"hetero-dev-{number}")
        require(any(c["type"] == "Ready" and c["status"] == "True"
                    for c in pod["status"].get("conditions", [])))
        claim = get("pvc", name)
        require(claim["status"]["phase"] == "Bound")
        require(claim["spec"]["volumeName"] == f"dev-identity-postgres-local-{number}")
        query = """SELECT json_build_object(
            'recovery', pg_is_in_recovery(),
            'synchronous_commit', current_setting('synchronous_commit'),
            'synchronous_standby_names', current_setting('synchronous_standby_names'),
            'replication', (SELECT coalesce(json_agg(json_build_object(
                'application', application_name, 'state', state, 'sync_state', sync_state)), '[]')
                FROM pg_stat_replication));"""
        sql = json.loads(run(["exec", "-n", namespace, name, "-c", "postgres", "--",
                              "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                              "-U", "postgres", "-d", "keycloak", "-c", query]))
        require(sql["recovery"] == (name != primary))
        require(sql["synchronous_commit"] == "on")
        if name == primary:
            peers = sql["replication"]
            require(len(peers) == 2)
            require({p["application"] for p in peers} == set(names) - {primary})
            require(all(p["state"] == "streaming" and p["sync_state"] == "quorum" for p in peers))
            require(sql["synchronous_standby_names"].upper().startswith("ANY 1 ("))
        results.append({"pod": name, "node": pod["spec"]["nodeName"], **sql})
    print(json.dumps({"cluster_uid": helper.UID, "read_only_checks_passed": True,
                      "primary": primary, "instances": results,
                      "write_recovery_tested": False, "physical_ha": False}))


if __name__ == "__main__":
    main()
