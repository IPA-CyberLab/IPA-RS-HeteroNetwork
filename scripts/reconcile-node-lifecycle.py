#!/usr/bin/env python3
"""Apply declared node stops through the shared control-plane ACL store.

Run as the database operator. Credentials stay in a protected file and the
child's environment. This preserves registration, IP assignments and disks.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from urllib.parse import parse_qsl, unquote, urlsplit

from node_lifecycle import stopped_hosts


def sql_literal(value):
    return "'" + value.replace("'", "''") + "'"


def database_environment(url):
    parsed = urlsplit(url)
    options = {"sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
               "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY",
               "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME"}
    environment = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    environment.update(PGHOST=parsed.hostname, PGPORT=str(parsed.port or 5432),
                       PGUSER=unquote(parsed.username or ""), PGPASSWORD=unquote(parsed.password or ""),
                       PGDATABASE=unquote(parsed.path.lstrip("/")), PGCONNECT_TIMEOUT="10")
    for key, value in parse_qsl(parsed.query, strict_parsing=True):
        if key not in options:
            raise ValueError("unsupported PostgreSQL connection option")
        environment[options[key]] = value
    return environment


def statements(roster):
    stopped_hosts(roster)  # Validate every declaration before any mutation.
    states = roster.get("node_states", {})
    peers = {peer["node_id"]: peer for peer in roster["peers"]}
    rows = []
    for host, declaration in states.items():
        node_id = roster["hosts"][host]
        if not re.fullmatch(r"node-[0-9a-f]{32}", node_id):
            raise ValueError("invalid lifecycle node identity")
        peer = peers[node_id]
        rows.append({"node_id": node_id, "vpn_ip": peer["vpn_ip"], "state": declaration["state"]})
    if not rows:
        raise ValueError("no lifecycle declarations")
    cluster = roster["cluster_id"]
    if str(uuid.UUID(cluster)) != cluster:
        raise ValueError("invalid lifecycle cluster identity")
    lock = f"ipars-control-plane:{len(cluster)}:{cluster}"
    deny = [dict(id="operator-stopped-" + direction, from_roles=[], to_roles=[],
                 from_tags=["heteronetwork-stopped"] if direction == "from" else [],
                 to_tags=["heteronetwork-stopped"] if direction == "to" else [],
                 routes=[], protocol="any", action="deny") for direction in ("from", "to")]
    allow = [dict(id="operator-lifecycle-default-allow", from_roles=[], to_roles=[],
                  from_tags=[], to_tags=[], routes=[], protocol="any", action="allow")]
    return f"""BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '15s';
SELECT pg_advisory_xact_lock(hashtextextended({sql_literal(lock)}, 0));
CREATE TEMP TABLE lifecycle_input ON COMMIT DROP AS
SELECT * FROM jsonb_to_recordset({sql_literal(json.dumps(rows))}::jsonb)
AS x(node_id text, vpn_ip text, state text);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM lifecycle_input i LEFT JOIN nodes n USING(node_id)
 WHERE n.node_id IS NULL OR n.record_json->>'vpn_ip' <> i.vpn_ip
 OR n.record_json->>'cluster_id' <> {sql_literal(cluster)}) THEN
 RAISE EXCEPTION 'lifecycle identity mismatch'; END IF;
 IF NOT EXISTS(SELECT 1 FROM cluster_policies WHERE cluster_id={sql_literal(cluster)}) THEN
 RAISE EXCEPTION 'lifecycle cluster policy missing'; END IF;
END $$;
UPDATE nodes n SET record_json=jsonb_set(n.record_json, '{{tags}}',
 COALESCE((SELECT jsonb_agg(tag) FROM jsonb_array_elements(n.record_json->'tags') tag
 WHERE tag <> '"heteronetwork-stopped"'::jsonb), '[]'::jsonb)
 || CASE WHEN i.state='stopped' THEN '["heteronetwork-stopped"]'::jsonb ELSE '[]'::jsonb END)
FROM lifecycle_input i WHERE n.node_id=i.node_id;
UPDATE cluster_policies SET record_json=jsonb_set(record_json, '{{acl_rules}}',
 CASE WHEN jsonb_array_length(COALESCE(record_json->'acl_rules','[]'::jsonb))=0
 THEN {sql_literal(json.dumps(allow))}::jsonb
 ELSE COALESCE((SELECT jsonb_agg(rule) FROM jsonb_array_elements(record_json->'acl_rules') rule
 WHERE rule->>'id' NOT IN ('operator-stopped-from','operator-stopped-to')), '[]'::jsonb) END
 || {sql_literal(json.dumps(deny))}::jsonb)
WHERE cluster_id={sql_literal(cluster)};
INSERT INTO overlay_routing_epochs(cluster_id,epoch) VALUES({sql_literal(cluster)},1)
ON CONFLICT(cluster_id) DO UPDATE SET epoch=overlay_routing_epochs.epoch+1;
SELECT jsonb_build_object('node_id',n.node_id,'state',i.state,'vpn_ip',i.vpn_ip)
FROM lifecycle_input i JOIN nodes n USING(node_id);
COMMIT;
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--roster", required=True, type=Path)
    parser.add_argument("--database-url-file", required=True, type=Path)
    args = parser.parse_args()
    info = args.database_url_file.lstat()
    root_read_group = os.geteuid() == info.st_uid == info.st_gid == 0
    forbidden = 0o037 if root_read_group else 0o077
    if not stat.S_ISREG(info.st_mode) or info.st_mode & forbidden or info.st_uid != os.geteuid():
        raise SystemExit("Database credential file must be private and owned by the operator")
    url = args.database_url_file.read_text().strip()
    if not url.startswith(("postgres://", "postgresql://")):
        raise SystemExit("A PostgreSQL control-plane credential is required")
    sql = statements(json.loads(args.roster.read_text()))
    result = subprocess.run(["psql", "-XqAt", "--set", "ON_ERROR_STOP=1"],
                            input=sql, text=True, capture_output=True, timeout=30,
                            env=database_environment(url))
    if result.returncode:
        raise SystemExit("Node lifecycle transaction failed; protected diagnostics withheld")
    for line in result.stdout.splitlines():
        if line.startswith("{"):
            print(json.dumps(json.loads(line)))


if __name__ == "__main__":
    main()
