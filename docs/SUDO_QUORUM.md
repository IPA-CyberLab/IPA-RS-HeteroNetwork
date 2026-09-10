# Local Sudo Quorum Approval

Status: isolated single-use sudo privilege grant, local Unix service and standard
approval-plugin prototype; separate exact-context research remains blocked on
final-environment binding. None is deployed. No live host sudoers, sudo.conf, PAM,
SSH or authentication changes. Disposable-container configuration is test-only.

## Explicit Privilege Grant Profile

This profile authorizes **sudo-level root privilege for one invocation**, not an
exact argv/cwd/environment or a reusable login session. It is separate from both
the exact-command research below and existing exact HTTP administration tokens.
Unchanged sudoers authorization and its existing authentication policy must ALSO
succeed. That policy may accept a cached timestamp or an existing NOPASSWD rule;
the plugin does not guarantee fresh password entry. A fresh-password deployment
profile would need separately reviewed sudoers settings, not an implicit plugin
claim. The grant
does not enlarge the commands permitted by sudoers. A permitted root shell can
outlive grant expiry and delegate further authority; expiry limits new admissions,
not the lifetime or effects of an admitted process. This is not a root sandbox.

`src/privilege.rs` signs the distinct domain
`heteronetwork-sudo-privilege-grant-v1`, with scope `sudo`, host node ID, caller UID,
pinned owner subject, run-as UID zero, immutable manifest epoch/digest, frozen
policy digest, 256-bit host nonce, issuance time and 60-second expiry. The policy
digest includes the complete root-provisioned manifest and UID-to-owner mapping.
The configured host node ID must occur in that manifest's frozen member roster;
a foreign host is rejected before ledger creation. This profile does not support
non-voter target hosts without a separately reviewed target-host policy.
Root callers, unmapped UIDs, non-root run-as and sudoedit are unsupported and denied.
Ordinary commands and shells permitted by sudoers are within the root-privilege
scope; no attempt is made to describe their environment as immutable.

`lifecycle/privilege_gate.c` uses the official approval ABI, validates bounded and
duplicate-free metadata, and checks sudo's caller UID against the kernel real UID
while effective UID is root. It checks root run-as metadata, authenticates the
Unix service with `SO_PEERCRED`, and never executes or substitutes a command.
Unknown ABI or initialization failure returns minus one, never the disabling
`open()==0` result. There is no password-only fallback on IPC or quorum failure.

`local-sudo-grants` has no signing keys, HTTP listener or root command executor:

1. Root provisions `/etc/ipars-sudo-prototype.json` (regular, single-link, 0600),
   `/run/ipars-sudo-prototype` (0755) and `/var/lib/ipars-sudo-prototype` (0700).
   Startup rejects symlinks, non-root ownership and writable ancestors; the
   database and existing sidecars must be root-owned private regular files.
2. Only root can connect to `adapter.sock` (0600). A root-authenticated adapter
   sends `SQP1` plus the original caller UID as four big-endian bytes. The daemon
   checks the frozen mapping, persists a fresh challenge, and returns its 32-byte
   nonce. The plugin prints a public handle and holds that same connection open.
3. `submit.sock` (0666 in the protected directory) accepts length-prefixed JSON
   `Submission {nonce:[32 bytes], signed:null|{grant,signature}}`. Null fetches a
   challenge. Kernel peer UID must match the active invocation for both fetch and
   submission. No supplied UID overrides this check. A grant must exactly match
   the live host-generated challenge. A submission acknowledgement means queued
   for verification, not approved or executed.
4. The adapter task verifies the majority signature, then atomically consumes the
   nonce in a WAL/FULL-synchronous SQLite ledger with the immutable anchor check
   in the same statement. It takes a fresh system-clock reading after acquiring
   the pooled connection and SQLite writer lock, and rechecks expiry before and
   after durable commit and immediately before a nonblocking success write.
   Waiting for contention cannot retain an earlier authorization time. A commit
   that finishes after expiry burns the grant without admitting the command.
   Only then does it send byte `1` to the plugin. The
   plugin's successful check permits sudo to continue its normal execution flow.

Any lost acknowledgement burns the grant. Disconnect, extra adapter input,
expiry or daemon restart invalidates the live invocation; there is no reconnect
or nonce reuse. Consumed records survive restart. A new invocation always needs
a new host nonce and majority signature. The service never replaces existing
socket paths, deletes ledger evidence, or hot-reloads membership/mappings.
After a crash or ordinary termination, stale sockets can therefore prevent restart.
There is no automatic cleanup or production restart unit. An authorized local
administrator must first verify the previous service has stopped and identify its
owned sockets before removing only those socket entries. Never remove or recreate
the database/anchor to make restart succeed. Container tests perform this cleanup
only after waiting for their own child service to exit.

Limits: 8 active adapters, 16 submission handlers, socket listen backlog 16,
16 KiB JSON frames, 3-second adapter header deadline, 5-second submission deadline,
60-second approval wait, 65-second plugin total deadline, four SQLite connections,
and 1,024 durable records. Exhaustion denies; safe record GC is not implemented.
This is a lifetime record limit, not merely a concurrent-pending limit: consumed
and abandoned records count too. Restart does not reset capacity. No production
rollout is supported until retention/GC and recovery are reviewed.
Root-controlled storage, current kernel credentials and the trusted sudo binary
are part of the boundary. Already-root processes can impersonate an adapter and
are explicitly outside it; a root peer alone is NOT evidence of an original user
without the trusted plugin's metadata checks. UID recycling requires reviewed
reprovisioning, not automatic mapping reuse.

### Signing Boundary

The version 1 local prototype has **no production sudo signer integration**. Its container uses
`examples/disposable-fixture.rs`, an offline 2-of-3 dealer-key test fixture that
refuses to run outside a root container. Never install the example or its keys.
It signs only the typed sudo privilege domain, not arbitrary messages.

A production signer needs a dedicated protocol validating an authenticated host
challenge, frozen host/UID/subject mapping, pinned owner OIDC subject/email and
client proof of possession in both FROST rounds, with fresh single-use nonces and
bounded requests. Local root IPC is not remote host attestation. Existing HTTP
admin signing endpoints must not be repurposed as a generic signing oracle.
Until that contract, independent review and access-recovery testing are complete,
the working container path is a prototype, not installable production enforcement.

Required production issuance invariants (not implemented by this v1 prototype):

- Pin the host-attestation public key to `(cluster, host_node_id, key_epoch)` in
  trusted signer configuration. Its signature covers the complete typed challenge;
  a request-supplied key must never establish its own authority.
- Map each local UID to an issuer-scoped `(issuer, subject)` identity. Matching a
  subject alone is insufficient across identity providers. Each signer independently
  verifies the authenticated identity against this trusted mapping.
- Include the requester public key in both the host-authenticated challenge and
  the threshold-signed grant. Both signing rounds require proof of possession over
  that exact challenge. Redemption proof still needs an explicit reviewed contract:
  issuance-only proof does not make a captured grant non-transferable.
- Provision the policy represented by `policy_digest` to each signer through a
  trusted configuration path. An opaque caller-supplied digest is not evidence
  that the UID mapping or privilege scope is authorized.
- Keep redemption subordinate to the host's live pending invocation. Closing that
  invocation invalidates redemption even if remote signing rounds later finish.

These are a versioned sudo-specific protocol, not extensions permitting arbitrary
message signing through the HTTP administration signer. No production CLI token
issuance is implied by the offline fixture or these requirements.

### Version 2 Integration

The shared typed protocol in `crates/ipars-quorum/src/sudo.rs` is version 2 and
must not be mixed with the version 1 local prototype. A dedicated signer mode is
selected with `iparsd quorum-signer --sudo-policy-path POLICY.json`; it rejects
simultaneous rotation configuration and a policy whose manifest differs from the
explicit signer manifest. It exposes only the sudo signing routes, not an executor.
The existing `--check-config` mode validates inputs without opening a listener.

Tracked, opt-in deployment templates are
`deploy/systemd/heteronetwork-sudo-quorum-signer.service` and
`deploy/systemd/sudo-quorum-signer.env.example`. They use a separate configuration
directory and systemd credential path. Provision the intended per-VM shares through
the reviewed DKG ceremony, never through the container's dealer-key fixture. The
version 2 policy pins an exact HTTPS issuer; an existing HTTP-only issuer must be
addressed explicitly before deployment, not silently rewritten or accepted.

These templates are not installed or enabled automatically. Version 2's local
adapter exists as a separate isolated prototype described below. Recovery, release
packaging, real-voter provisioning and rollout verification remain incomplete.
Starting a signing service alone does not enforce sudo on a VM.

The coordinator accepts a version 2 challenge already signed by the trusted local
host mechanism. It does not manufacture that attestation or execute sudo:

```sh
ipars quorum sudo-issue --policy sudo-policy.json --challenge host-challenge.json \
  --requester-key requester.key --oidc-token owner-access-token \
  --token-out sudo-token.json
```

The challenge must bind the requester's public key before issuance. The CLI checks
every frozen signer endpoint before sending credentials, gathers a fixed majority,
verifies the aggregate signature, and publishes a private token without replacing
an existing file. Output requires a trusted Unix directory. This command alone
does not redeem the token: the local adapter must request and verify a fresh
redemption proof and durably consume the live invocation.

### Root-Local Version 2

`local-sudo-v2` and `lifecycle/privilege_v2_gate.c` use separate sockets under
`/run/ipars-sudo-v2`, config `/etc/ipars-sudo-v2/config.json`, a private raw 32-byte
attestation seed at `/etc/ipars-sudo-v2/host.key`, and durable state under
`/var/lib/ipars-sudo-v2`. These paths are not production installation instructions;
no host sudo configuration is modified by building them. The configured host key
must match the host's public key in the full trusted version 2 policy.

The root adapter supplies the kernel-checked original UID and a fresh nonce. Only
that UID can bind its requester public key over the submission socket. The service
then signs the complete host challenge; it never accepts a supplied UID, host,
owner mapping or policy. After a matching majority token is submitted, it creates
a distinct fresh redemption nonce. Requester proof, live-session binding, immutable
ledger anchor and atomic single-use consumption must all succeed before approval.

For an already configured isolated version 2 test environment, leave the original
sudo invocation waiting in its first terminal. The trusted root plugin prints its
64-hex-character invocation handle. In a second terminal on the same host, as the
same original non-root user, set `HANDLE` to that printed value and run:

```sh
ipars quorum sudo-approve --handle "$HANDLE" --policy sudo-policy.json \
  --requester-key requester.key --oidc-token owner-access-token
```

Do not run this approval client through sudo or switch users: its kernel real UID
must be nonzero and equal its effective UID. The requester key and owner access
token must be private files owned by that user with mode 0600. The locally trusted
policy pins the host attestation keys, UID-to-owner mapping and complete frozen
signer manifest. HTTPS signer endpoints are accepted; literal-IP HTTP endpoints
require the existing explicit `--vpn-cidr CIDR` transport option.

The CLI connects only to `/run/ipars-sudo-v2/submit.sock`, rejecting symlinks and
non-root-owned or group/other-writable directory ancestry. It authenticates kernel
peer UID zero before sending any data. Each local exchange has a three-second
timeout and version-checked, bounded 16 KiB frames; there is no socket override.
`BindRequester` returns a host-signed challenge that must match the handle, the
client's kernel UID, the requester key and the trusted policy before any signer
request. The CLI gathers and independently verifies a frozen majority, then sends
`SubmitToken` without writing a token file. It checks the returned fresh redemption
nonce, UID, scope and expiry, signs the requester proof, and independently verifies
the core redemption contract before sending `Redeem`.

The handle names one live invocation, not a reusable session. The challenge's
at-most-60-second lifetime starts at host issuance and is not extended by running
the client or waiting for signers. Fresh expiry checks apply during signing and
before submission and redemption. Closing the original invocation, expiry or
service restart invalidates its pending approval. Timeouts and lost replies are
not retried automatically; a lost reply does not undo durable consumption.

Only a version 2 `Submitted` reply produces `{"status":"approval_submitted"}`.
This means approval was submitted, **not that the root command executed or
succeeded**. The CLI spawns neither sudo nor SSH, provides no SSH fanout or command
executor, and leaves execution to the original sudo process. Expiry limits new
admissions, not the lifetime of an already admitted process. This workflow does
not install the local service or enable production enforcement.

The version 2 adapter acknowledgement includes the trusted expiry. The C plugin
checks realtime expiry and its monotonic deadline after receiving the complete
acknowledgement, preventing buffered approvals from being accepted after expiry.
Lost acknowledgements do not undo consumption. Ordinary sudoers authentication
still applies; this remains a privilege admission gate, not a root sandbox.

Wire data lives in `ipars_quorum::sudo::local`; the prototype reexports those types.
The version 1 protocol is not accepted on version 2 sockets. Version 2 admission
collects at most 1,024 expired records transactionally, retaining all unexpired
records and the immutable anchor. A persisted wall-clock floor rejects rollback
before collection or consumption. Capacity remains 1,024 retained records; it is
not reset on restart. Legacy ledger migration quarantines admission through the
latest recorded expiry; unknown or incomplete schemas fail closed.

A root-private lifetime process lock serializes cooperating version 2 servers.
Restart removes only trusted, unchanged socket entries whose connection is refused;
live listeners and unsafe paths are rejected. The initial upgrade MUST first stop
nonlocking legacy servers and their automatic restarts: connection refusal cannot
exclude a legacy process between bind and listen. Never delete the database or
anchor to recover service. Approved local policy rotation, production packaging
and recovery rollout remain incomplete; do not deploy unattended enforcement yet.

Kernel/physical/root/DB-owner control and a compromised signing majority remain
outside the threat model. UID lifecycle management, key provisioning and operational
recovery require further production review. The clock floor cannot protect against
an administrator restoring or replacing the trusted database itself.

## Security Contract

Ordinary local sudo execution must satisfy BOTH existing sudoers/authentication
policy and a fresh majority-issued capability. Quorum failure never turns into
authentication-only fallback, an operator-token exception, or automatic root
access; it never enables NOPASSWD or changes existing authentication settings.
An already configured NOPASSWD rule still requires the majority grant.
Sudo remains the only component that executes the approved local command.
There is no HTTP route that executes a command and no helper that runs a shell.

The capability covers one invocation, not a login session. Sudo's credential
timestamp does not substitute for per-invocation quorum authorization.
Success means authorization was durably consumed, not that the command ran or
succeeded. A crash after consumption requires a new challenge and approval.

This is application-level enforcement against ordinary local users, stolen
passwords, token replay, request substitution, and fewer than a majority of
compromised signers. Existing root, physical/boot administrators, kernel control,
the signing majority, and owners able to rewrite the verifier's database or
trusted configuration are outside the cryptographic boundary. Old/unmodified
sudo binaries and alternate privilege paths must be inventoried separately.
An approved root shell would delegate arbitrary subsequent actions; this design
is not a sandbox and does not cryptographically constrain an already-root process.

## Interface Choice And Sources

Use sudo's approval-plugin interface as an additional policy gate. It runs after
policy acceptance and exposes command metadata, execution argv, and environment.
The policy interface also describes numeric identities, cwd, execfd, and session
setup. Crucially, session setup can modify the environment: an approval snapshot
must not be described as guaranteed final execution state without lifecycle tests.
[Official sudo plugin API](https://www.sudo.ws/docs/man/sudo_plugin.man/).

Compile a small C adapter against the installed, supported sudo header; verify
the runtime ABI version and bounded input arrays. Keep FROST and storage outside
the adapter. Its interface is approval/denial only, never an execution service.
[Upstream sudo_plugin.h](https://github.com/sudo-project/sudo/blob/main/include/sudo_plugin.h).

PAM remains useful for authentication/account policy, but its standard item
interface does not supply the complete sudo execution tuple. PAM alone is not
the proposed exact-command authorization boundary.
[Linux-PAM item API](https://github.com/linux-pam/linux-pam/blob/master/doc/man/pam_get_item.3.xml).

## Exact-Command Research

The remainder of the exact-context contract describes the original optional
stronger profile, NOT requirements silently imposed on the privilege grant above.

Host identity comes from root-controlled node configuration, not gethostname,
an environment variable, a token field alone, or a caller-supplied HTTP header.
The bridge measures and binds:

- Real caller UID/GID and supplementary groups from trusted sudo user metadata.
- Effective and real run-as UID/GID and actual supplementary group vector.
- Absolute resolved executable, measured SHA-256, device and inode.
- Exact argv vector, including argv[0], argument boundaries, empty arguments,
  and non-UTF-8 bytes. Never shell-join, interpolate, or normalize arguments.
- Absolute effective cwd, device and inode; no optional-cwd fallback.
- Exact sanitized environment vector and trusted environment-policy revision.
- Umask and an explicitly supported execution-mode profile.
- Frozen manifest/epoch, local host policy digest, random 256-bit host nonce,
  issuance time, and an expiry no later than 60 seconds after issuance.

The prototype length-prefixes variable-length fields and vectors, uses fixed-width
big-endian numeric values, and signs the domain
`heteronetwork-sudo-approval-v1`. HTTP admin tokens cannot authorize sudo.
The policy digest commits to the validated manifest, host, revision, exact
environment template, and executable allowlist. A separate sudo signing key group
is recommended; do not turn the existing admin signer into a generic signing oracle.

The initial policy is deliberately explicit: selected root-owned ELF commands,
trusted cwd paths, exact environment templates. Unsupported sudoedit, chroot,
preserved arbitrary FDs/groups, namespace transitions, scripts, shell/interpreter
delegation, and mutable execution contexts are denied until modeled and reviewed.
This is a staged supported-command policy, not a proposal to deny all sudo forever.

## Local Flow And Public Contracts

1. Sudoers authorizes/authenticates the request normally.
2. Approval adapter captures the supported execution context. It connects only
   to a root-controlled Unix socket and requests a challenge. The local service
   checks peer credentials; only the trusted adapter may create execution requests.
3. The service persists the random nonce, signed-context digest, expiry, and pending
   status before exposing a request handle. It records no raw argv/env in the ledger.
4. A companion unprivileged client retrieves only its own challenge and obtains
   majority signatures through a distinct host-approval issuance protocol. Signers
   pin owner subject/email and bind the host's permitted caller UID mapping.
   Host attestation and client PoP must be reviewed before this protocol is exposed.
5. The local service compares the signed context to the still-bound invocation,
   verifies the majority signature, then atomically changes pending to consumed.
6. Only committed consumption permits the adapter to return approval to sudo.
   Errors, unknown requests, revocation, expiry, or uncertain commits deny execution.

Proposed bridge messages are typed `BeginInvocation` and `SubmitApproval`, never
`Execute`, and never a shell command string. A separate caller-accessible submission
socket, if introduced, needs kernel-authenticated UID ownership and strict request
correlation. A root peer alone is not proof of a particular sudo caller; preserve
and validate the trusted sudo metadata and request lifecycle.

Keep this separate from membership rotation work. No hot manifest replacement
or local deletion/recreation of anchors. Rotation must specify pending-request
invalidation, durable epoch transitions, and recovery before becoming available.

## Persistence And Bounds

Prototype API: `HostVerifier::open`, `challenge`, `approve`, `revoke`, `close`.
It reuses `ipars-quorum` manifest/FROST verification and SQLx SQLite, not custom
threshold cryptography. A single local ledger is appropriate because capabilities
are bound to one host. All verifier processes on that host must use that same
protected database, including after reboot; copies are not independent authorities.

Consumption is a conditional UPDATE on nonce, signed-context digest, pending state,
expiry, and immutable policy anchor. SQLite serializes writers; this avoids a
separate check-then-consume race. Revocation and consumption compete for the same
pending row. [SQLite transactions](https://www.sqlite.org/lang_transaction.html).

Use WAL and FULL synchronous durability. Hardware/filesystem durability assumptions
still apply. [SQLite synchronous policy](https://www.sqlite.org/pragma.html#pragma_synchronous).

Prototype limits: 60-second challenges; 256 arguments; 128 environment entries;
64 KiB combined argv/environment bytes; 256 caller/run-as groups; four DB connections;
two-second SQLite busy timeout; three-second pool acquisition timeout; 1,024 ledger
records. No prototype GC: exhaustion denies rather than deletes replay evidence.
Production also needs bounded IPC frames, admission concurrency, total deadlines,
disk limits, safe expired-record GC, monotonic-clock/boot binding, and rollback tests.

## Execution Races And Release Gates

The library accepts caller-provided metadata and time for testing. It does NOT
prove those values describe a real OS process. A usable plugin must close that gap.

### Tested Approval Lifecycle Boundary

`prototypes/sudo-quorum/lifecycle` builds against the official v1.9.17p2
`sudo_plugin.h`, pinned by upstream commit and SHA-256 in its Dockerfile.
It does not reproduce the ABI with a hand-written struct or Rust FFI layout.
The gate requires the exact compiled API version (1.22); unknown versions fail
initialization. In particular, approval `open()` returning zero **disables** the
plugin, whereas `check()` returning zero denies. Initialization errors must return
minus one. The gate has no successful `check()` path.
[Pinned upstream header](https://github.com/sudo-project/sudo/blob/d1b48c651cec19fe37d1f0d3299d2283fb0f88e4/include/sudo_plugin.h),
[upstream approval dispatch](https://github.com/sudo-project/sudo/blob/d1b48c651cec19fe37d1f0d3299d2283fb0f88e4/src/sudo.c).

The separate `witness.so` is measurement-only, not quorum enforcement. It returns
success solely to observe the lifecycle in a disposable container, after normal
sudoers/password acceptance. It is never linked into the deny gate or Rust verifier.
Its build requires `DISPOSABLE_LIFECYCLE_TEST`; there is no host install target.
Do not load either artifact on production or treat the witness as authorization.

The integration fixture keeps the distribution's sudoers, audit/I/O plugins and
PAM authentication/account checks. Its only allowed command is a root-owned ELF
fixture that prints booleans and executes nothing else. A session-only `pam_env`
entry in the disposable image introduces a harmless fixed marker. The observed
approval environment lacks that marker; the executed command receives it.
This is an ordinary supported session transformation, not an attack or a test
that replaces sudoers with a permissive policy. Output order can be buffered;
the assertion compares the two labeled snapshots, not line order.
[Upstream PAM session handling](https://github.com/sudo-project/sudo/blob/d1b48c651cec19fe37d1f0d3299d2283fb0f88e4/plugins/sudoers/auth/pam.c).

Context availability and remaining proof obligations:

| Field | Available at approval | Missing final guarantee |
| --- | --- | --- |
| Caller | sudo `user_info` UID/GID/groups; fixture UID matches kernel real UID | Preserve this in the trusted sudo process; a root socket peer alone cannot prove original caller UID |
| argv | execution vector, including empty, spaced and non-UTF-8 arguments (tested) | Reject later substitution and unmodeled execution modes |
| Run-as | numeric real/effective UID/GID and group metadata | Test actual group vector, defaults and credential changes; names alone are insufficient |
| cwd | policy cwd; fixed trusted fixture cwd matches execution | Bind directory identity and ancestry; deny optional cwd/chroot and races |
| Executable | `execfd` available with fixture `fdexec=always` | Measure the held FD and prove it remains the executed object; presence alone is insufficient |
| Environment | policy-filtered vector | **Fails exact final binding: PAM session changes it after approval** |

Consequently no `BeginInvocation` IPC or majority approval consumption is connected
to the exact-context deny gate. The verifier's host nonce and immutable majority anchor remain
unchanged, but they cannot authenticate an unproven OS snapshot. No caller-supplied
`Invocation`, config path, time or peer claim is promoted to trusted metadata.
Root-controlled configuration/storage validation and caller-UID attestation remain
prerequisites, not implemented properties of the C artifacts.

A concrete next integration boundary requires a reviewed sudo front-end hook after
session setup and final environment transformations, immediately before execution,
with a held executable FD, stable cwd and preserved original caller credentials.
Alternatively a specific immutable session/plugin profile must prove there are no
post-approval changes across every execution path. Merely disabling PAM sessions,
guessing final environment values, using an I/O-open hook (also too early), or
authorizing a wrapper to execute commands is not an accepted substitute. No such
front-end patch or production configuration change is included here.

- Verify executable identity against sudo's actual execfd where supported. Inspect
  that same held FD; a pathname hash alone is not protection against replacement.
- Restrict cwd and executable ancestry to trusted non-writable directories until
  FD-based execution/cwd guarantees are demonstrated for the selected sudo build.
- Reject execution flags not covered by the profile. Include security labels,
  namespaces, inherited FDs, and resource/environment transformations when supported.
- Verify session/PAM hooks cannot change the bound environment after approval.
  If they can, change the reviewed integration boundary or deny that configuration;
  do not silently weaken exact-environment binding.
- Initial executable identity does not bind dynamic libraries, config files,
  stdin, network input, subprocesses, or every effect of the approved program.
- Provide private service-owned storage and root-owned configuration with secure
  no-follow/ownership/ancestor checks. Prototype `open` does not implement these
  privileged filesystem checks and must not be installed as a security boundary.
- For the exact-command profile, the bridge, IPC, host-specific signer rounds, owner/UID mapping, attestation,
  client PoP, clock rollback handling, and production revocation authorization are
  not implemented. The prototype's revoke method is a trusted local API only.

## Recovery And Rollout

Keep existing production sudo/PAM unchanged until all nodes' access and out-of-band
recovery are verified. First use a disposable VM and a separately packaged test sudo
build; then reviewed shadow observation that cannot alter authorization. Tests must
cover supported ABI versions, password/timestamp behavior, denied policy, concurrency,
reboots, nonce reuse, DB outage/full disk, malformed IPC, clocks, and post-check context.

Before enforcement, agree a documented, named break-glass procedure using an already
authorized physical/console recovery channel, explicit operator approval, audit trail,
and post-recovery review. It is an acknowledged trust exception, not a hidden plugin
fallback. Do not automatically disable approval when the VPN, IdP, or quorum is down.
Do not deploy simultaneously to every recovery node or remove the last verified path.

## Prototype Verification

The Rust crate is outside the main workspace/release graph and has its own lockfile.
The privilege service has Unix listeners but no execution or credential switching.
Rust tests create temporary local databases and signing keys. C artifacts are
built and loaded only inside disposable test images.

```sh
cargo test --locked --manifest-path prototypes/sudo-quorum/Cargo.toml
cargo clippy --locked --manifest-path prototypes/sudo-quorum/Cargo.toml --all-targets -- -D warnings
```

Tests cover exact-context tampering, expiry/bad signatures/unknown nonces, persistent
replay rejection after reopen, concurrent consumption, revocation, immutable anchors,
and bounded/NUL-rejecting inputs. Passing them is not authorization for production
sudo configuration changes.

Run the lifecycle harness from the repository root, never run its Python entrypoint
directly on a host. Do not add host mounts, host networking, a Docker socket,
`--privileged`, or production configuration/credentials to this container:

```sh
docker build -t ipars-sudo-quorum-lifecycle:test prototypes/sudo-quorum/lifecycle
timeout 60s docker run --rm --network none ipars-sudo-quorum-lifecycle:test
```

The build uses `-Wall -Wextra -Werror` and checks current/unknown ABI handling and
unconditional denial. Runtime assertions cover wrong password, denied sudoers
command, exact fixture argv/cwd/run-as, post-approval environment mutation, and
gate rejection of ordinary and unsupported-mode requests. This is evidence of an
integration blocker, not an end-to-end majority-authorized sudo success test.

The separate privilege integration DOES exercise successful majority-authorized
sudo, with a test-specific PASSWD rule and disabled timestamp reuse. This fixture
does not establish that the plugin itself enforces fresh passwords. Build native Linux binaries
compatible with the disposable Debian image (tested with the local Rust toolchain):

```sh
cargo build --locked --manifest-path prototypes/sudo-quorum/Cargo.toml --bin local-sudo-grants --example disposable-fixture
docker build -f prototypes/sudo-quorum/lifecycle/Dockerfile.privilege -t ipars-sudo-privilege:test prototypes/sudo-quorum
timeout 180s docker run --rm --network none ipars-sudo-privilege:test
```

The privilege container tests real sudo success, password/sudoers rejection,
wrong host/UID/epoch/expiry, cross-UID IPC rejection, concurrent single consumption,
bad signature, replay, service disconnect/restart, immutable UID mapping,
root-only configuration, bounded admission and actual 60-second expiry. They never
mount host configuration or keys. The final expiry check intentionally waits.
