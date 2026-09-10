# Flow Recovery Evidence, 2026-09-10

All times below are UTC. Read-only observations were collected through the
existing administrator context on uc-k8sp2. No Redis promotion, data edit,
container restart, SQL update, or credential bypass was performed during this
investigation. No key names, key values, tokens, or credentials are recorded.

## HCloud Fixture

- Organization: `01a089a1-fdd5-77c1-9d28-2f36d0e4dc26`.
- Flow service: `01a089a3-568f-7220-9aec-e420aa0f5a76`.
- Outbox event: `01a089a3-56a3-7162-b543-8a4220d4aac4`.
- Worker logs at 04:46:24.647790 and 04:46:48.948918 reported request failures
  to the expected internal Flow service-instance route, at attempts 3 and 5.
- Read-only SQL subsequently showed service state `ready`, generation 1,
  updated at 04:55:04.722946.
- The outbox event had 9 attempts, available_at 04:55:04.480138,
  delivered_at 04:55:04.739424, and no remaining locked_at.
- An operations query scoped to this organization and resource_id returned no
  rows. A separate operations row is therefore not asserted.
- Worker source uses competing outbox claims, not a singleton leader. Retry
  delay saturates at 256 seconds; abandoned locks expire after two minutes.

The fixture completed normal reconciliation. These SQL observations are
separate from the Redis data-continuity question below.

## Redis Before Election

Earlier read-only INFO replication observations during recovery:

| Node | Role | Master link | Replica offset | Replication ID |
| --- | --- | --- | --- | --- |
| node-0 | replica of node-1 | down | 36410150377 | 9675ddba78312c468273e3c9a1ac28a5edb898fe |
| node-2 | replica of node-1 | down | 1 | f243e2835cd2acbc29782ac6dcc99b618171b628 |

At that time node-2 also reported master_repl_offset 36404935780. The replica
offset of 1 alone does not establish an empty database.

Retained node-2 Redis lifecycle logs showed:

- 03:14:32.170: loading RDB, age 13743 seconds.
- 03:14:32.269: RDB load completed, 705 keys loaded and 0 expired.
- 03:14:32.269: base AOF RDB loaded.
- 03:14:33.569: incremental AOF loaded.
- 03:14:33.569: append-only load completed successfully.

The filtered retained history retrieved with a 6 MB bound did not show a
successful pre-election full or partial resynchronization. This is an absence
of evidence in the retrieved logs, not proof that no catch-up ever occurred.

## Election And Synchronization

Sentinel node-0 logs:

- 04:47:13.890: master node-1 objectively down, quorum 3/3, new epoch 37.
- 04:47:13.976: Sentinel elected leader.
- 04:47:14.054: node-2 selected; promotion command sent.
- 04:47:15.081: node-2 promotion observed.
- 04:47:15.124: node-0 reconfiguration sent.
- 04:47:21.736: node-0 reconfiguration completed.
- 04:47:21.792: failover completed; master switched from node-1 to node-2.

Node-2 Redis logs:

- 04:47:14.133: secondary replication ID set to
  f243e2835cd2acbc29782ac6dcc99b618171b628, valid through offset 36404935781;
  new ID ceb63ca6f2b85cfd604ef025d474a2bcbcc6e0e3.
- 04:47:14.142: master mode enabled by a Sentinel client.
- 04:47:15.170: partial resync rejected because node-0 requested ID
  9675ddba78312c468273e3c9a1ac28a5edb898fe, which did not match either ID.
- 04:47:15.170: new backlog ID 890f971f3a1a5c67a37abba3cf00d8a7dd0d419b.
- 04:47:15.175: full resync requested by node-0.

Node-0 Redis logs:

- 04:47:20.940: RDB load completed, 37 keys loaded and 0 expired.
- 04:47:20.940: master/replica synchronization finished successfully.
- 04:47:20.942: replication buffer streaming completed, 0 bytes.

The observed full resync direction was node-2 to node-0, not node-0 to node-2.
At approximately 04:55, node-2 DBSIZE returned 696. A later non-simultaneous
node-0 DBSIZE returned 704. These changing counts are not a consistency test.

## Recovery And Limits

- At 04:52:06, Flow API, signaling, LiveKit, and matchmaker were each 7/7 Ready.
- Redis was 4/5 Ready; Sentinel reported 4 usable voters with quorum and
  failover authorization reachable.
- Node-2 was master with node-0, node-1, and node-3 online, each reporting lag 0.
- Redis node-4 remained Terminating on uc-k8sp1. Redis data uses emptyDir,
  not a PVC; persistence on a container restart must not be confused with
  persistence across pod deletion.
- Coturn deployments were each 3/4; Grafana and Prometheus each 2/3, with
  scheduler placement, host-port, and resource constraints.
- uc-k8sp2 was Ready with pressure flags false, but memory requests were 96%
  of allocatable, available RAM 842 MiB, swap used 489 MiB, and memory PSI
  full avg10 5.90%. It is not spare capacity.

Redis application-data continuity remains unverified. The evidence does not
justify claiming no loss, nor a specific loss count: there is no comparable
pre-election key snapshot, and expiration and post-recovery writes can change
counts. SQL fixture readiness does not prove Redis continuity. No claim about
durable SQL data loss follows from these Redis observations.
