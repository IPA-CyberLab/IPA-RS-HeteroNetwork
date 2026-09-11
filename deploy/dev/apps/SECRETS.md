# DEV Service Credentials

`provision-app-secrets.py` uses the pinned identity foundation guard on DEV1,
including the live Kubernetes UID, before provisioning service credentials.
It reads only the three DEV CNPG credential/CA Secrets and constructs verified
target URLs through `database_credentials.py`. Production credentials are not
imported. Namespaces must carry the DEV channel label; the otherwise absent
Flash DEV namespace can be created explicitly, without workloads.

Fresh random material is written and fsynced before any service Secret creation
to `/var/lib/heteronetwork-dev-app-credentials/seeds.json` on DEV1. The directory
is root-only 0700 and file root-only 0600. Private keys are never sent to this
repository or printed. Preserve this state: a partial/corrupt file or directory
causes refusal, not key regeneration. A directory lock serializes invocations.

Seven complete authentication Secrets are constructed:

| Namespace | Secret | Purpose |
| --- | --- | --- |
| heterocloud-dev | heterocloud-dev-runtime | DB URL and CSRF key |
| heterocloud-dev | heterocloud-dev-provider-signing | Ed25519 private key |
| heterocloud-dev | heterocloud-dev-flow-access | Shared Flow principal HMAC |
| heterocloud-dev | heterocloud-dev-syouyu-access | Shared Syouyu principal HMAC |
| heterocloud-flow-dev | heterocloud-flow-dev-secrets | DB, provider public key, HMAC, LiveKit, TURN and Redis credentials |
| heterocloud-flash-dev | heterocloud-flash-dev-provider-auth | Provider public key only |
| heterocloud-syouyu-dev | heterocloud-syouyu-dev-secrets | DB, provider public key, HMAC, receipt encryption and Garage credentials |

Only Cloud receives the provider private key. Downstream services receive the
same public key under `heterocloud-dev-provider-1`. Flow and Syouyu share their
respective HMAC with Cloud; unrelated credentials are independently generated.
The generated LiveKit key file is JSON, which is also accepted as YAML.

All existing target Secrets must have the expected DEV UID/managed-by metadata
and exact data before any missing Secret is created. Missing Secrets use
server dry-run, create and readback. Unknown ownership or differing data is not
adopted or overwritten. This is creation/verification, not rotation. A failure
can leave a subset created, but rerunning with the same saved seed state can
finish it; do not delete private state to retry.

## Actual Execution: 2026-09-11

The first DEV invocation reported seven Secrets created and verified, with new
seed state. The second reported zero created, no new state, and seven verified.
Both reported no rotation and no workload changes. Eight focused tests cover
key distribution/signature consistency, shared HMACs, existing ownership/data
checks, seed-state identity, and database connection conversion.

Tools on DEV1: `/opt/heteronetwork-dev-app-secrets-e5d8da58`.
Archive SHA256:
`e5d8da58c0776732a59187610a91446004e4582c6564f3b5d2a67b05fa34713b`.
Provisioner SHA256:
`2c0f6588b10c48b1b76ab13bea2ade5af04c540922d2dc7dcf3311d41ea45b58`.
Credential mapping module SHA256:
`0e06bce343297b6fff1887aec03cb56e434b1f440a76f6b02ada8d2bfb4e4c5d`.

## Remaining Boundaries

These Secrets are not proof that applications run or authenticate. OIDC is
provisioned separately by the identity helper. LiveKit's authenticated
Redis/Sentinel configuration has now been created and verified; see
[LIVEKIT.md](LIVEKIT.md). Cloud serving TLS remains to be provisioned. App
migrations, network-policy access checks, end-user login and functional tests
are still required. No credential rotation, replica failover or loss-of-DEV1
recovery has been demonstrated by this provisioning step.
