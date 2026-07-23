# HeteroNetwork PostgreSQL HA

HeteroNetwork stores node identity records, endpoint candidates, health,
service leases, routes, client gateway selections, and the join-token ledger in
PostgreSQL. Public reachability is not required for database members. The
supported self-hosted topology uses exactly three mutually reachable private
addresses:

- one PostgreSQL and Patroni process per failure domain;
- a separate three-member etcd cluster used only for database leader election;
- PostgreSQL synchronous streaming replication to at least one standby;
- a local HAProxy listener on every Control Plane host that forwards only to
  the Patroni member currently holding the primary lock;
- TLS verification for PostgreSQL, Patroni health checks, and etcd client and
  peer traffic.

With three healthy members, an acknowledged transaction is present on the
primary and at least one standby. Losing any one member leaves two-member
consensus and one writable PostgreSQL primary. Losing two members intentionally
stops automatic writes because a safe majority no longer exists.

Replication addresses must remain available while the database primary is
unavailable. They can be HeteroNetwork addresses when the hosts retain a
bootstrap path that does not require a database read, or another dedicated
private management interface. Do not expose ports `55432`, `18008`, `12379`, or
`12380` to the Internet.

## Create The Offline Bundle

Run this once on a trusted administrator machine. The output contains the
cluster CA private key and all database passwords.

```bash
export HETERONETWORK_DB_MEMBERS='db-a=10.250.0.1,db-b=10.250.0.2,db-c=10.250.0.3'
sudo -E scripts/postgres-ha-node.sh init-bundle /root/heteronetwork-db-bundle
```

Keep `ca/ca.key` offline. Copy the bundle over an authenticated administrative
channel for installation, then remove the copied CA private key from every
database and Control Plane host. `install-node` copies only the local member
certificate and shared runtime secrets.

## Install Three Private Members

Run the following on each member, changing the local name and address. Include
every Control Plane proxy source address in `HETERONETWORK_DB_CLIENT_CIDRS`.

```bash
export HETERONETWORK_DB_MEMBERS='db-a=10.250.0.1,db-b=10.250.0.2,db-c=10.250.0.3'
export HETERONETWORK_DB_CLIENT_CIDRS='10.250.0.1/32,10.250.0.2/32,10.250.0.3/32'
export HETERONETWORK_DB_NODE_NAME='db-a'
export HETERONETWORK_DB_NODE_ADDRESS='10.250.0.1'
export HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS='100.64.0.11'
export HETERONETWORK_DB_BUNDLE_DIR='/root/heteronetwork-db-bundle'
sudo -E scripts/postgres-ha-node.sh install-node
```

`HETERONETWORK_DB_CLIENT_LISTEN_ADDRESS` is optional. Set it when a Control
Plane proxy reaches this member through a second private management address,
such as a Tailscale address. PostgreSQL binds only the replication and
explicit management addresses. The installer exposes the local Patroni health
endpoint on that same management address through TLS passthrough; it does not
bind either service to every interface. Include every remote proxy source in
`HETERONETWORK_DB_CLIENT_CIDRS`.

The installer pins Patroni and etcd releases, verifies the etcd artifact
digest, creates dedicated users and owner-only state directories, and installs
the public database CA at
`/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt`. It also installs three
hardened systemd services:

```text
heteronetwork-db-dcs.service
heteronetwork-db.service
heteronetwork-db-proxy.service
```

## Install Control Plane Proxies

A Control Plane that is not itself a database member only needs HAProxy and the
CA certificate. Its backend addresses may differ from the PostgreSQL
replication addresses, but they must reach the same three Patroni members.

```bash
export HETERONETWORK_DB_MEMBERS='db-a=10.250.0.1,db-b=10.250.0.2,db-c=10.250.0.3'
export HETERONETWORK_DB_PROXY_BACKENDS='db-a=100.64.0.11,db-b=100.64.0.12,db-c=100.64.0.13'
export HETERONETWORK_DB_BUNDLE_DIR='/root/heteronetwork-db-bundle'
sudo -E scripts/postgres-ha-node.sh install-proxy
```

Use the replication member list as the proxy backend list when the Control
Plane can reach those addresses directly. Otherwise, use each member's
explicit client-listen address as shown above.

Store the complete application connection URL in
`/etc/credstore/database-url`, owned by `root:root` with mode `0400`:

```text
postgresql://heteronetwork:PASSWORD@postgres.heteronetwork.internal:25432/heteronetwork?sslmode=verify-full&sslrootcert=/etc/ssl/certs/heteronetwork-postgres-ha-ca.crt
```

The packaged Control Plane unit imports this as a systemd credential. Remove
`HETERONETWORK_DATABASE_URL` from `/etc/ipars/public-node.env`, reload systemd,
and restart the Control Plane.

## Migrate An Existing Database

Quiesce every Control Plane before taking the final dump so no acknowledged
write is omitted:

```bash
pg_dump --format=custom --file=/root/heteronetwork.dump OLD_DATABASE_URL
pg_restore \
  --clean --if-exists --no-owner --no-privileges \
  --dbname=NEW_DATABASE_URL \
  /root/heteronetwork.dump
```

Compare every application table count before switching the Control Planes.
Retain the old database read-only until the new cluster has passed the failure
test and every former primary has rejoined as a streaming replica.

## Verify And Fail Over

On any database member:

```bash
sudo -E scripts/postgres-ha-node.sh verify
sudo -E scripts/postgres-ha-node.sh status
```

The verification requires three healthy DCS members, exactly one PostgreSQL
primary, two streaming replicas, and at least one synchronous replica.

To test failure, stop both database services on the current primary:

```bash
sudo systemctl stop heteronetwork-db.service heteronetwork-db-dcs.service
```

The remaining two members must elect a primary and accept a new write through
their local proxy. Restart the stopped services, then require `verify` to pass
again and confirm the returning member replayed that write.

Synchronous replication is not a backup. Keep encrypted base backups and WAL
archives in an independently administered object store so accidental deletion,
corruption, and loss of all three failure domains remain recoverable.
