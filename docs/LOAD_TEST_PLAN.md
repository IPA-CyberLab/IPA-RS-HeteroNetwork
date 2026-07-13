# Load Test Plan

The `ipars-load` harness is the executable load plan for 3-node, 10-node, and 1000-node scenarios.

## Scenarios

| Scenario | Nodes | Relay nodes | Route providers | Active pair samples |
| --- | ---: | ---: | ---: | ---: |
| `three` | 3 | 1 | 1 | 6 |
| `ten` | 10 | 2 | 2 | 30 |
| `thousand` | 1000 | 10 | 25 | 2000 |

The 1000-node scenario samples active pairs rather than negotiating every possible pair, preserving the lazy-connect design assumption while still measuring peer-map fanout and path-state propagation.

Daemon transport can launch fewer Agents than the scenario's design node count. Its executed active-pair count is `min(scenario samples, agents * (agents - 1))`; reports and retained manifests preserve both the scenario sample count and this executed workload count.

## Transports

- `in-memory`: exercises control-plane and signal services without HTTP.
- `http`: drives loopback HTTP control-plane and signal endpoints.
- `relay-udp`: adds Bearer-authenticated relay HTTP admission and UDP forwarding throughput checks.
- `daemon`: spawns separate `iparsd` control-plane, signal, STUN, relay, and dry-run agent processes with inherited environment variables cleared and only a fixed system `PATH` plus `C` locale restored. Multiple control-plane processes share one run-scoped SQLite store by default. Set `IPARS_LOAD_DAEMON_DATABASE_URL` or pass `--daemon-database-url` to run the same HA workload against PostgreSQL; the URL is passed to control-plane children only through their environment and reports record only the backend kind. Relay and Agents read a generated run-scoped admission credential from one owner-only file, and the harness removes that file after readiness. After agent path convergence, the harness uses each persisted agent identity to sign a baseline negotiation and path-quality observation for every active pair, then validates the Signal disposition counter deltas.

## Required Success Gates

Each report is validated before command success. The harness rejects:

- missing registrations;
- missing agent status endpoint coverage;
- missing endpoint candidates;
- missing reachable agent runtime path state;
- missing control-plane path-state or signed `/v1/paths/query` propagation;
- unauthenticated or unavailable control-plane operator metrics during HTTP/daemon runs;
- unauthenticated or unavailable Signal operator metrics during HTTP/daemon runs;
- missing signed path-quality observations for reachable active pairs, or any Signal `stale`, `path_mismatch`, or `rejected` observation disposition;
- unauthenticated or unavailable STUN operator metrics during daemon runs;
- unauthenticated or unavailable Relay operator metrics during relay/daemon runs;
- unavailable Bearer-authenticated Relay admission during relay/daemon runs;
- peer-map edge loss or cross-control-plane inconsistency;
- relay-candidate loss;
- relay packet loss, payload corruption, or relay counter skew;
- relay admission failure reasons in success scenarios;
- retained runtime manifest, child process, log, permission, owner, binary identity, or secret residue mismatches;
- missing failover survivor peer-map, health, relay-candidate, path-state, path-status, agent-status, or existing relay dataplane coverage.

## Commands

```bash
cargo run -p ipars-load -- --scenario three
cargo run -p ipars-load -- --scenario ten
cargo run -p ipars-load -- --scenario thousand
cargo run -p ipars-load -- --transport http --scenario ten
cargo run -p ipars-load -- --transport relay-udp --scenario ten --relay-packets-per-session 16 --relay-payload-bytes 1200
cargo build -p ipars-daemon
cargo run -p ipars-load -- --transport daemon --scenario three --iparsd-bin target/debug/iparsd --daemon-agent-processes 3 --daemon-control-plane-processes 2 --daemon-agent-readiness-timeout-seconds 30
IPARS_LOAD_DAEMON_DATABASE_URL='postgresql://ipars:password@127.0.0.1:5432/ipars?sslmode=disable' cargo run -p ipars-load -- --transport daemon --scenario three --iparsd-bin target/debug/iparsd --daemon-agent-processes 3 --daemon-control-plane-processes 2 --daemon-agent-readiness-timeout-seconds 30
```

For a repeatable local smoke that also builds the daemon transport binary:

```bash
IPARS_LOAD_SMOKE_BUILD_DAEMON=1 scripts/load-smoke.sh
```

## Capacity Indicators

Track these fields across runs:

- registration count and registration time;
- peer-map edge count and per-control-plane endpoint min/max;
- selected path-state totals;
- submitted and Signal-accepted path-quality observation totals, including non-accepted disposition counters;
- relay-candidate count and relay capacity counters;
- relay UDP packet and byte throughput;
- daemon child process count, readiness time, and failure phase;
- failover survivor path-state/path-status min/max and relay dataplane counters.

## Production Ramp

1. Run `three` on every change that touches join, signal, path, relay, agent, or store logic.
2. Run `ten` before merging operational changes, Docker/Kubernetes chart changes, or metrics changes.
3. Run `thousand` before release tags and after control-plane/store/schema changes.
4. Run `daemon` with at least two control-plane processes before HA or failover changes.
5. Retain daemon runtime directories only for failure analysis; retained manifests are token-redacted but still operationally sensitive.
