# Majority-Approved Administration

This feature protects HeteroNetwork management API mutations. It does not
provide an arbitrary remote shell, replace Unix sudo, or prevent a host root
or database administrator from modifying that host or its database directly.

## Security Model

Each enrolled voting VM holds one FROST signing share. The approved membership
manifest fixes the cluster, epoch, voter identities, signer endpoints and
public key package. Its threshold must be `floor(N / 2) + 1`. An unavailable
voter remains in the denominator: six voters require four signatures, not a
majority of whichever machines happen to respond.

Key generation uses a distributed key generation ceremony. Secret packages
must travel over authenticated, confidential channels to the intended voter.
Do not collect secret packages on a central coordinator or substitute a
trusted-dealer example for the production ceremony. All participants must
verify the same roster and resulting public manifest before activation.

Issuance requires the configured owner's existing OIDC authentication at each
signer, pinned to the issuer and immutable subject as well as the configured
email. Automated approval means each signer independently validates the
authorization policy; it is not multiple human approvals. A compromised IdP
can therefore compromise the owner authentication boundary. Signing shares
provide a different boundary: a single stolen share cannot authorize a token.

## Capabilities

An issued capability authorizes one exact HTTP mutation, including its target
path and request-body digest. It binds the cluster, manifest epoch and digest,
requester public key, random request ID, and a lifetime of at most five
minutes. A requester signature is required in addition to the threshold
signature; possession of a copied token alone is insufficient.

The proof binds the exact operation, not a fresh server challenge or transport
channel. Someone who obtains both the token and its valid proof can race the
same authorized operation, but cannot change it or consume it twice. Protect
proof-bearing requests as credentials; do not publish them in logs.

The verifier consumes the capability in shared durable storage before calling
the handler. Replay against another control-plane replica is rejected. A
failed operation or a crash after consumption requires a new authorization;
the client must inspect actual state before retrying. This is at-most-once
authorization, not an exactly-once distributed transaction for arbitrary work.
Audit acceptance records must not be mistaken for proof that the handler
completed successfully.

FROST round-two nonces are consumed before signing and never persisted for
reuse. Pending rounds are bounded and expire. A signer restart abandons its
pending rounds; the coordinator must start a new round with fresh nonces.
Do not clone a live signer or resume its process from a VM memory snapshot:
restoring pending nonce state can invalidate this guarantee. Cold-start the
signer after restoration, and never run the same share on concurrent clones.

## Activation Boundary

This is opt-in and must not be switched on during an unrelated live recovery.
Provision and verify the complete intended voter roster first. Do not silently
replace missing voters with additional shares on accessible VMs.

Upgrade every control-plane replica before enabling enforcement. Mixed old
and new binaries do not provide cluster-wide enforcement. The shared manifest
anchor rejects a different manifest or epoch; removing a local configuration
file is not an authorized downgrade. Operator bearer credentials must not
bypass quorum-required management mutations once enabled.

Drain all in-flight management mutations and pause new management mutations on
every replica during initial activation, including enrollment and membership
changes. The initial roster check and legacy request admission are not a
transactional membership-reconfiguration protocol. A new
binary that is already running without a verifier must reject management
mutations once the shared anchor appears, until it is restarted with the
approved manifest; reads and signed agent protocol traffic can continue.

Membership changes use a fresh DKG ceremony and an epoch transition approved by
both the old and new frozen majorities. The transition binds the complete new
manifest digest, old digest, cluster, epoch, nonce and expiry. The shared store
atomically compares the old anchor, installs the new public manifest and retains
transition history. Competing or stale transitions fail; old-epoch capabilities
cannot be consumed after the transition. This is a key-group replacement, not
in-place share refresh. Automatic roster shrinking, emergency threshold reduction
and forced manifest replacement are not supported. FROST signatures are not
themselves a Raft log or a Byzantine membership consensus protocol.

Rotation signing is explicitly enabled with `--rotation-anchor-path` (environment
`HETERONETWORK_ADMIN_QUORUM_ROTATION_ANCHOR_PATH`). This root/daemon-owned public
configuration supplies the trusted old manifest; an HTTP caller cannot nominate
its own trust anchor. New signing shares must still be generated and installed on
their intended VMs before the ceremony. Existing signer endpoints and new staging
endpoints must be distinct while both groups operate. Do not copy a live share or
replace all signers before the old group has approved the transition.

After acceptance, provision the new public manifest on each control plane before
its next restart. Startup deliberately refuses a local manifest that disagrees
with the shared anchor; it does not silently trust a changed database as a new
bootstrap authority. Archive public transition evidence and stop the old signing
processes using the reviewed rollout procedure.

Existing protocol traffic such as signed agent heartbeats is separate from
human management authorization. Read-only console access retains its existing
authentication. Tenant Flash workloads are not restarted by provisioning this
feature.

## Runtime Configuration

The standalone signer is `iparsd quorum-signer`. It runs once on each voting
VM, including VMs that do not host a control plane. It refuses wildcard and
cleartext public listeners; use a specific overlay address and an unprivileged
port (the example uses `19790/TCP`, reachable only through the VPN).

Tracked deployment files:

- `deploy/systemd/heteronetwork-quorum-signer.service`
- `deploy/systemd/quorum-signer.env.example`

Install the approved public manifest as
`/etc/heteronetwork/admin-quorum/manifest.json` and the VM-specific environment
as `/etc/heteronetwork/admin-quorum/signer.env`. Keep the local share at
`/etc/credstore/heteronetwork-quorum-share.json`, root-owned and mode `0600`.
The unit passes the share through systemd credentials and runs unprivileged.
No private share or OIDC token belongs in Git, command-line arguments, or logs.

`iparsd quorum-signer --check-config` accepts the same configuration arguments
as normal startup and verifies inputs without opening a listener. This does
not prove that the IdP or the other voters are reachable.

Every upgraded control-plane service receives
`HETERONETWORK_ADMIN_QUORUM_MANIFEST_PATH` pointing to the identical manifest.
On initial activation its voters must exactly match the registered non-client
nodes. Subsequent restarts retain that frozen roster even if a voter is offline
or a network node has been removed. New enrollment does not automatically
grant a signing share; a membership transition remains a separate ceremony.

The new binary refuses startup without a manifest when a shared anchor already
exists, or with a conflicting manifest. Do not activate until all replicas are
upgraded, all voters have checked their own shares, and quorum issuance and
execution have been verified in an isolated environment.

Console reads continue to work with existing authentication. Existing console
mutation buttons do not yet collect threshold signatures: use the quorum CLI
for protected actions. The Unix CLI enforces private-file permissions; native
Windows secret-file support is not enabled by this implementation.

## CLI Workflow

Run the initial `ipars quorum dkg part1`, `part2`, and `part3` ceremony on each
voter, using the same reviewed roster. Part one produces a public packet for
all participants. Part two produces a separate confidential packet for each
recipient; never broadcast those packets. Part three verifies the transcript
and produces that VM's private key share and the public manifest. Every
participant must compare the final manifest digest through an authenticated
channel before deployment. Retire intermediate secret files after all
participants have verified completion; file removal is not a guarantee of
physical erasure on snapshots or SSDs.

After provisioning, ordinary administration runs from one Unix CLI client:

```sh
ipars quorum requester-keygen --out requester.key --public-out requester.pub
ipars quorum request --manifest manifest.json --requester-key requester.key \
  --method PUT --path /v1/admin/nodes/node-TARGET/display-name \
  --body rename.json --out request.json
ipars quorum issue --manifest manifest.json --request request.json \
  --requester-key requester.key --oidc-token owner-access-token \
  --body rename.json --token-out approval.json --vpn-cidr 10.250.0.0/16
ipars quorum execute --manifest manifest.json --token approval.json \
  --requester-key requester.key --body rename.json \
  --control-plane-url http://10.250.0.10:19088 --vpn-cidr 10.250.0.0/16
```

`owner-access-token` is a private file containing an access token from the
configured owner login, not a VM password or an operator bearer credential.
Outputs must be new paths and secrets must have mode `0600`. Replace example
node IDs and addresses with the approved deployment configuration. `rename.json`
contains the normal display-name API body, for example
`{"display_name":"new-name"}`. The exact bytes used for request, issuance and
execution must match. Do not normalize JSON or add a newline between steps.

The client contacts the manifest's signers itself; per-operation SSH is not
required. No redirect following, disabled certificate verification, or plaintext
public transport is needed. An HTTP VPN endpoint requires an explicit allowed
VPN CIDR. TLS endpoints use normal certificate validation.

To revoke an outstanding capability, approve and execute a new `POST` to
`/v1/admin/quorum/revocations` with the body
`{"request_id":"<64-character hex request ID>"}`. The revocation is subject
to the same majority requirement. It cannot undo an operation already accepted;
when a majority is unavailable, the short token lifetime is the fallback.
Use `--response-out` on execution to retain an API response in a new private
file. Response bodies are not printed because enrollment responses can contain
credentials.

## Verification And Deployment Status

The initial September 10 implementation passed 50 focused tests: eight crypto tests,
four SQLite ledger tests, one disposable PostgreSQL HA ledger test, thirteen
quorum HTTP tests, thirteen existing OIDC regressions, four daemon configuration
tests, and seven CLI tests. The CLI coverage includes the three-part file DKG
ceremony and actual loopback HTTP issuance with two of three signers available,
followed by guarded execution (200) and replay rejection (401). Loopback is a
test-only transport exception, not a production CLI option.

The PostgreSQL test used independent pools and sixteen concurrent submissions;
exactly one was accepted. It also checked pre-use revocation, a consume/revoke
race, reconnect durability and manifest mismatch. Its disposable database,
container and credential files were removed; no production database was used.

The subsequent rotation core/storage change passed ten core tests, nine local
storage checks, three control-plane regressions and two disposable PostgreSQL
checks. These cover joint signatures, epoch and key replacement, competing
transitions, active public manifests and serialization with old-token consumption.
An operation admitted before rotation can still finish afterward; rotation is
not cancellation of an already-dispatched operation.

This implementation has not been activated on the live six-node cluster. No
production key-generation ceremony, share deployment or end-to-end test across
those six VMs has been performed. Complete their management access and original
storage recovery before provisioning shares. In particular, never manufacture
the missing voters' shares on one accessible VM merely to enable the feature.
OS sudo and direct database administration remain outside this authorization
boundary. The separate [sudo design and verifier prototype](SUDO_QUORUM.md) is
not an installed privilege-enforcement plugin. Membership rotation has not been
exercised on the production VMs.

## References

- [FROST protocol, RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- [ZF FROST library](https://frost.zfnd.org/)
- [Distributed key generation tutorial](https://frost.zfnd.org/tutorial/dkg.html)
