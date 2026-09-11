# DEV LiveKit Configuration

`livekit_config.py` builds the config Secret expected by the selected Flow chart,
`heterocloud-flow-dev/heterocloud-flow-dev-livekit-config`, key `livekit.yaml`.
The JSON document is valid YAML. It contains Redis credentials and must never be
committed or printed; only the generating code belongs in the repository.

The selected companion builds LiveKit commit
`3b9f118327b257301083a7c4aa46076c8012918a`. Its
[module dependencies](https://github.com/livekit/livekit/blob/3b9f118327b257301083a7c4aa46076c8012918a/go.mod)
pin protocol commit `28e604c046c6`. The
[Redis configuration implementation](https://github.com/livekit/protocol/blob/28e604c046c6/redis/redis.go)
accepts distinct `password` and `sentinel_password` fields and passes both to
the Redis client. Both fields use the saved DEV Redis password because the
selected Bitnami chart enables authentication for Redis and Sentinel with that
same Secret key.

The config lists exactly three DEV Sentinel Pod FQDNs, master set `flowmaster`,
and no static master address. RTC uses TCP 7881, UDP 7882 and the DEV TURN/STUN
hostname `turn.dev.heterocloud.mizuame.app:13478`. TURN authentication reads the
existing mounted secret file, not an embedded new key. Native DEV STUN's
3478/3479 listeners are not reused. These are the current fixed DEV chart
settings; changes require reviewing both the chart values and this generator.

`provision-livekit-config.py` repeats the identity foundation's live DEV guard,
reads the existing root-only seed state and verifies the Redis, TURN and LiveKit
credentials against the managed Flow Secret. It does not generate keys. Existing
config must match its ownership markers and complete data; differences cause
refusal, not rotation or overwrite. Missing config uses server dry-run, create
and readback.

## Actual Execution: 2026-09-11

First invocation created the config Secret and confirmed it matches existing
Flow credentials. The second reported `created: false` and the same successful
readback. Neither invocation changed workloads. Three focused tests cover
Sentinel authentication/addresses, DEV TURN settings and deterministic Secret
encoding/private-key exclusion.

Tools on DEV1: `/opt/heteronetwork-dev-livekit-config-46d24b67`.
Archive SHA256:
`46d24b679d5efd7acbfddfd1a11d022fafb9a5c36561b4339ae5eb939c09edd2`.
Provisioner SHA256:
`14f398591eab1279308e1d8160cf00304201fed0cec91c4eed6357b0acd278e2`.

## Unverified Runtime

Secret creation is not LiveKit startup, Redis authentication or Sentinel failover
evidence. Redis and LiveKit workloads are not yet deployed. DEV TURN DNS/public
routing, reachability, media sessions and full resource admission also remain
required. No external endpoint readiness or production HA is claimed here.
