# Frozen-majority admin capabilities

This crate authorizes exact HeteroNetwork admin HTTP mutations, not shell commands,
sudo, or arbitrary endpoints. `frost-ed25519` is pinned to `=3.0.0` and re-exported
as `ipars_quorum::frost`; `ipars_quorum::dkg` exposes the production DKG protocol.
Dealer provisioning is used only in unit tests.

## Integration contract

- `Manifest` implements Serde and contains `schema_version: u32`,
  `cluster_id: String`, `epoch: u64`, `members: Vec<Member>`, and
  `public_key_package: Vec<u8>` (FROST serialized public package).
- `Member` contains `node_id: String`, `identifier: u16` (nonzero), and
  `endpoint: String`. Node IDs and identifiers are unique.
- `Manifest::validate() -> Result<()>`, `digest() -> Result<String>` (lowercase
  SHA-256 hex), and `public_keys() -> Result<frost::keys::PublicKeyPackage>`.
- `CapabilityClaims` contains `schema_version: u32`, `cluster_id: String`,
  `epoch: u64`, `manifest_digest: String`, `method: String`, `path: String`,
  `body_sha256: [u8; 32]`, `requester_public_key: [u8; 32]`,
  `request_id: [u8; 32]`, `issued_at: u64`, and `expires_at: u64`.
- Times are Unix seconds; expiry is exclusive, issuance cannot be in the future,
  and lifetime is at most 300 seconds. Generate request IDs with an OS CSPRNG.
- Sign `claims.proof_bytes()` with the requester's Ed25519 private key to create
  `RequestProof { signature: Vec<u8> }`. FROST signs `claims.signing_bytes()`.
  These are distinct, domain-separated, length-prefixed canonical encodings.
- `SignerEngine::new(manifest, node_id: &str, key_package, max_pending: usize,
  pending_ttl_secs: u64) -> Result<Self>` takes a FROST `keys::KeyPackage`
  directly. Key packages support upstream Serde; never log their Debug output.
- `round1(&mut self, &claims, &proof, now) -> Result<Round1Response>` returns
  `{session_id: [u8; 32], identifier: u16, commitments: SigningCommitments}`.
- Build `frost::SigningPackage::new(commitments_by_identifier,
  &claims.signing_bytes())` from at least a frozen majority of responses.
- `round2(&mut self, session_id, &claims, &signing_package, now)` returns
  `Result<frost::round2::SignatureShare>`. Every attempted use of a known session
  consumes it, including invalid packages. Retry requires a fresh round one.
- Aggregate with upstream `frost::aggregate`; serialize the result into
  `CapabilityToken { claims, signature: Vec<u8> }`.
- `verify_capability(&manifest, &token, &proof, method: &str, path: &str,
  raw_body: &[u8], now: u64) -> Result<()>` validates the complete binding.

## Trust and lifecycle requirements

The embedding application installs the trusted manifest independently of token
input. Validation does not establish who registered the VMs: provisioning must
ensure that the frozen manifest contains every registered VM. Membership or key
changes require a new trusted epoch and DKG, never a reduced online denominator.
The public key package must embed exactly `floor(N/2)+1`; legacy packages missing
the threshold are rejected. FROST requires at least two members; the upper limit
here is 1024. Manifest digest is independent of member ordering.

Endpoints are pinned by the trusted manifest, must be unique HTTP(S) origins
with root path `/`, and may not contain credentials, queries, or fragments. Transport must enforce
its TLS or authenticated VPN trust policy and must not follow arbitrary redirects.
This crate makes no network requests.

Before round one, the HTTP layer must authenticate and authorize the configured
owner. PoP alone is not owner authorization. Apply bounded request sizes and
rate limits before decoding. Keep the engine behind exclusive synchronization;
it never serializes pending nonces. FROST zeroizes nonces and private key packages
on drop. Pending sessions are bounded (1..1024) and expire after 1..300 seconds;
restart loses all sessions. The caller supplies a trustworthy clock.

The execution layer must atomically claim `(manifest_digest, request_id)` in a
durable replay ledger before mutation. Stateless signature verification alone
does not provide one-time execution. Retain replay entries through expiry and
coordinate across control-plane replicas. Hash exact received body bytes and
compare raw method/path without query stripping or URL normalization.

The allowlist contains seven admin mutations: POST enrollment and
client-enrollment, PUT policy, DELETE nodes/{id}, PUT nodes/{id}/display-name,
POST paths/{local}/{remote}/pin, and POST quorum/revocations, all under `/v1/admin`.
The HTTP revocation handler must validate its typed request-ID body; the core
binds its exact bytes without interpreting mutation bodies. Manifest epochs must
be positive. Additional routes
must be explicitly reviewed before extending `allowed_mutation`.

Run only this crate's focused tests with `cargo test -p ipars-quorum --lib`.

## Membership and key rotation

`ManifestTransition` contains `old_manifest_digest: String`,
`new_manifest: Manifest`, `request_id: [u8; 32]`, `issued_at: u64`, and
`expires_at: u64`. Its `signing_bytes() -> Result<Vec<u8>>` is distinct from
ordinary capabilities and binds the old digest, computed new manifest digest,
cluster, next epoch, request ID, and validity window. The new digest commits to
the full roster, endpoints, and public key package. Member ordering is canonical.

`ManifestRotation { transition, old_signature: Vec<u8>, new_signature: Vec<u8> }`
requires both groups' FROST signatures over exactly the same transition bytes.
`verify_rotation(&old_manifest, &rotation, now) -> Result<VerifiedRotation>` checks
both signatures, cluster equality, strict epoch increment without overflow,
distinct new group key, frozen majorities, and a lifetime of at most 300 seconds.
The new group's signature proves that its signing threshold possesses the new
shares. Production provisioning still uses authenticated DKG, never a dealer.

`SignerEngine::round1_rotation(&old, &transition, now)` and
`round2_rotation(session_id, &old, &transition, &package, now)` work for either
group, sharing the ordinary session capacity and nonce lifecycle. The transport
must authenticate the configured owner and install the trusted old anchor before
calling these methods, including on a proposed new signer. These methods do not
accept an arbitrary raw-message signing request. Each signer must match either
the exact old or exact new manifest digest.

`VerifiedRotation` has private fields and no Deserialize implementation. Storage
accepts this verified value, rechecks expiry after acquiring its transaction
lock, then CASes the exact old anchor to the new one. It cannot force-overwrite a
newer epoch. The same lock protects capability consumption and revocation.

The control-plane/store API provides:

- `initialize_admin_quorum_manifest(cluster, manifest)`: atomic first anchor and
  public-config installation, or idempotent installation matching an existing
  anchor. Existing incompatible anchors and unanchored retained history deny.
  Initial all-registered-node roster validation remains the caller's obligation.
- `publish_admin_quorum_manifest(cluster, manifest)`: attaches public config to
  an already matching anchor, including migration from a digest-only anchor.
- `get_active_admin_quorum_manifest(cluster)`: coherent active anchor/config
  snapshot. Missing config behind an existing anchor is an error, not permission
  to bootstrap another manifest.
- `rotate_admin_quorum_manifest(verified) -> Result<bool>`: joint authorization,
  atomic anchor CAS, both public manifests persisted, signed transition history.
- `list_admin_quorum_rotation_history(cluster, limit)`: newest first, capped at
  100 entries. `ControlPlane` wrappers supply its configured cluster automatically.

After rotation, verifiers must read the active public manifest rather than retain
the startup manifest. Old-token consume transactions ordered after CAS fail even
if a verifier cached the old manifest before the transition. A mutation whose
consume transaction completed before CAS was already admitted and may finish
afterward; this API does not cancel already authorized work. Runtime startup must
prefer stored active config, not try to rebind a stale bootstrap file. New signer
private key installation and authenticated roster lifecycle are external to this
public-config store. No online-node count changes a threshold.
