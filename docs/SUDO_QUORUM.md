# Local Sudo Quorum Approval

Status: implementable design and isolated, non-executing verifier prototype.
Not a deployed sudo plugin. No sudoers, sudo.conf, PAM, SSH, or live host changes.

## Security Contract

Ordinary local sudo execution must satisfy BOTH existing sudoers/authentication
policy and a fresh majority-issued capability. Quorum failure never turns into
password-only fallback, NOPASSWD, an operator-token exception, or automatic root
access. Sudo remains the only component that executes the approved local command.
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

## Canonical Request

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
- The bridge, IPC, host-specific signer rounds, owner/UID mapping, attestation,
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

The crate is outside the main workspace/release graph and has its own lockfile.
It has no binary, plugin shared object, listener, process execution, or credential
switching. Its tests create only temporary local databases and test signing keys.

```sh
cargo test --locked --manifest-path prototypes/sudo-quorum/Cargo.toml
cargo clippy --locked --manifest-path prototypes/sudo-quorum/Cargo.toml --all-targets -- -D warnings
```

Tests cover exact-context tampering, expiry/bad signatures/unknown nonces, persistent
replay rejection after reopen, concurrent consumption, revocation, immutable anchors,
and bounded/NUL-rejecting inputs. Passing them is not authorization for production
sudo configuration changes.
