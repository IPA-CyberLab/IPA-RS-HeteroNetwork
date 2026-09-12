# Inactive DEV Sudo Companion

`scripts/install-dev-sudo-companion.py` places only the verified dev6 companion
on one of the three identity-pinned DEV guests. It reuses the installed DKG
helper's hostname, machine ID, DMI, cluster, live agent and public roster checks;
it does not run any DKG phase or change a key share.

The root-only input bundle is `/opt/heteronetwork-dev-sudo-companion`, containing
the wrapper, reviewed `sudo-quorum-v2-artifact.py` and `sudo-dev6.tar.gz`.
The wrapper pins both helper sources and the release archive. The existing
artifact decoder checks architecture, paths, payload hashes, modes, disabled
notice, source commit, clean release profile and release metadata before copying.

The destination is the separate inactive directory
`/opt/heteronetwork/sudo-v2/artifacts/0.1.15-dev.6`.
No active pointer, unit, sudo.conf, sudoers, PAM, policy, host key or ledger is
created or modified. No packaged binary or plugin is executed. The wrapper
requires absent sudo-v2 configuration/runtime/state paths and no sudo-v2 plugin
reference in sudo.conf. It snapshots sudo.conf, sudoers and sudoers.d entries
before/after and requires unchanged contents and file metadata.

An existing destination is verified, never replaced; partial or different bytes
cause refusal. The shared installer writes the manifest last and retains partial
state for inspection. This is not an atomic transaction or automatic rollback.
Re-execution verifies existing bytes but does not turn them into a running service.

## Observed Installation: 2026-09-10

All three guests completed the actual install and readback with exit status 0:

| Guest | Version | Byte Verification | Activation |
| --- | --- | --- | --- |
| hetero-dev-1 | 0.1.15-dev.6 | Passed | Not performed |
| hetero-dev-2 | 0.1.15-dev.6 | Passed | Not performed |
| hetero-dev-3 | 0.1.15-dev.6 | Passed | Not performed |

Release source commit:
`22c4e3baf5de53f70bbac08f5fe62a0590e24526`.
Archive SHA256:
`0a1d2c9c0d39435e53777557a859a734ef0d1af7d5cc07e0de27d673a8cba569`.
Wrapper SHA256:
`62587ac0c9a33e396c42ee4fb65d71a180bfca3a824a7d8a638689ad004d53c2`.
Shared installer SHA256:
`f5bcd1bbe4a985b4a62d6f228c4a8d5ffcb0ec949de7384436d18c0c7620b322`.

Each result reported `sudo_configuration_unchanged: true`,
`payload_executed: false`, `service_installed: false`, and
`activation_performed: false`. Native running agents were not upgraded by this
copy. No production host was targeted.

The real owner identity, host attestation keys, trusted policy, signer services,
effective sudo plugin integration, authenticated majority issuance and privileged
end-to-end validation remain required. Installed bytes and a disabled notice are
not proof that majority approval is enforced. Do not enable the plugin until the
complete local and remote approval path is provisioned and verified.

The public preflight supports an explicit `--native-check` after installation of
the real owner policy and host key. After archive, installed-byte, policy and unit
hash checks pass, it runs only `bin/local-sudo-v2 --check-config`, with a clean
environment, suppressed output and a 15-second timeout. The config argument must
be `/etc/ipars-sudo-v2/config.json`, matching the native checker's fixed path.
The native process reads the host key to validate its public pin, but does not
start a service or open runtime state. Without the flag, no binary is executed.
Success still returns exit 2 and `ready_to_enable: false`: service configuration,
authenticated quorum issuance and effective enforcement remain separate checks.
This option has not been run on the DEV guests with a provisioned owner policy.

The optional `--inactive-runtime-check` inspects systemd's loaded fragment path,
drop-ins, daemon reload requirement and disabled/inactive/dead state. It rejects
unit overrides and any explicit `Plugin` directive in `/etc/sudo.conf`, including
legitimate explicit stock plugins, which require separate review. Continuations
are rejected rather than interpreted. This is an inactive-state preflight, not
an active plugin audit; it issues only `systemctl show` and reads configuration.
It does not audit sudoers, PAM, direct root access or other privilege bypasses.
Those remain explicit blockers even when both optional checks pass. This runtime
inspection has not yet been executed against provisioned DEV owner policy/units.

## Admission Boundary

The public preflight also rejects duplicate host attestation keys, root or
noncanonical caller UIDs, out-of-range key epochs and malformed owner identity
strings. These structural checks do not replace native cryptographic validation
of the public keys, FROST package or policy. Passing them still reports
`ready_to_enable: false`.

Owner authorization uses the exact verified OIDC issuer and subject, not an email
address or display name. A real owner must be enrolled and those public identity
pins confirmed before activation; the temporary DEV bootstrap administrator must
not be silently substituted. Quorum participation is machine policy approval,
not evidence that a separate human approved on each VM. Existing root access or
unrestricted sudo can bypass an inactive plugin, so installed signing artifacts
alone do not enforce the requested administrative boundary.

## Observed Host Attestation Provisioning: 2026-09-11

The pinned provisioner generated one Ed25519 host-attestation key independently
inside each DEV guest. Private 32-byte seeds remain root-only at
`/etc/ipars-sudo-v2/host.key`; neither the physical host coordinator nor this
repository received them. The three public records are committed in
`sudo-hosts.json` and bind guest name, machine ID, cluster ID, node ID, DKG
manifest hash and key epoch. Their public keys are distinct.

The first coordinator run reported `key_created: true` on all three guests. A
second run reported `key_created: false` and derived the same three public keys
from the stored private seeds. Both runs reported no sudo configuration change,
no activation and no private-key export. The guest provisioner SHA256 is
`f0e8c9437d3a9e108de253bf3aff1cd66c30078e52b363168bc32cf6254f2fff`;
the physical-host coordinator SHA256 is
`e35d9ad2192c451d0411f4dfcfe474d19fabe92c3b9bcd855be57aa9ab9bd9c3`.
Twelve focused offline tests passed before deployment.

At that checkpoint only the host-attestation prerequisite had advanced. No
`config.json`, signer process or sudo plugin was active. The real owner's exact
DEV OIDC subject remains absent, so constructing an active policy or enabling
enforcement would currently substitute an unverified identity and is
intentionally refused.

## Observed Inactive Runtime Provisioning: 2026-09-11

The dev6 signer binary and local sudo companion were subsequently provisioned
to all three DEV guests through the pinned physical-host coordinator. The
signer uses its own immutable binary under
`/opt/heteronetwork/sudo-v2/runtime/0.1.15-dev.6`; it does not replace or restart
the running HeteroNetwork agent. The local companion remains under the verified
artifact tree. Versioned `current` symlinks and the two hardened systemd unit
files were installed on each guest.

The guest runtime provisioner SHA256 is
`1baf64fd95a9a44f5e86f0bb8eb365ac60649ddb06e08355a975a4ba29eac821`;
the physical-host coordinator SHA256 is
`0327f25c58cbf4bdd72b6376cd76b06d06aa5d6a08c43cf8e3abc9e8c447795d`.
The installed signer binary SHA256 is
`dd26e9907c426fe1f2b628a5010441a4127ef26ab763195c353a8c7e09cf05bb`.

Both `heteronetwork-sudo-local.service` and
`heteronetwork-sudo-quorum-signer.service` reported `inactive`, `dead` and
`disabled` on every guest after deployment. No policy, daemon configuration,
runtime socket, ledger, sudo plugin setting, service start or service enable was
created. An immediate second coordinator run installed no files and changed no
symlink or unit, while returning the same inactive state on all three guests.
The active sudo path is therefore unchanged; this is staged runtime material,
not majority-sudo enforcement.

## Active DEV Rollout Contract

The active rollout is split into explicit `prepare`, `check`, `start` and
`activate` phases. `scripts/build-dev-sudo-active-bundle.py` accepts only the
immutable dev7 release metadata and its two hash-bound archives. The resulting
root-only bundle contains the exact public DEV policy, service definitions,
native CLI, signer, local verifier and approval plugin. The bundle builder does
not install or start anything.

On `ichikawap1`, `scripts/deploy-dev-sudo-active.py` uses only the fixed
root-owned DEV SSH key, strict known-host pins and the three fixed guest machine
identities. It can distribute the bundle and invoke `prepare`, `check`, `start`
or `status`; it deliberately has no `activate` phase. Preparation copies each
guest's existing local DKG share into a systemd credential source without
exporting it, installs the exact owner policy, runs both native configuration
checkers and creates a requester key owned by UID 1000. Start enables the local
verifier and signer for boot only after those checks pass.

Activation appends the one reviewed approval-plugin directive to
`/etc/sudo.conf`. It must be invoked separately inside an already-open root
session on each guest, after all three signer health endpoints are reachable.
Keep those three sessions open until an actual non-root `sudo` command has
completed through the 2-of-3 path. The `rollback` phase removes only that exact
directive and refuses unknown plugin configuration.

The operator workflow uses two terminals on the target host. In the first,
`sudo` prints a 64-hex invocation handle and waits. In the second:

```text
heteronetwork-sudo-login
heteronetwork-sudo-approve <64-hex-handle>
```

Login uses the pinned HeteroCloud Keycloak issuer, public `ipars-web` device
client and exact owner subject. It verifies the returned identity through
userinfo and writes only the access token to the caller's private config
directory. Approval obtains a FROST majority over the HeteroNetwork overlay and
submits the result directly to the root-owned local verifier. The resulting
grant is bound to the host, caller UID, run-as UID and pending invocation; it
expires within 60 seconds and is durably single-use. It is intentionally not a
reusable root bearer credential.

The approval helper reads a public-only policy copy from
`/etc/heteronetwork-sudo-quorum/policy.json`. Signer shares and service inputs
remain below root-only directories; the public copy contains only the voter
roster, public keys, command constraints and owner identity pins.

All three DEV voters currently share one physical host. This validates protocol,
service and sudo integration behavior but does not prove physical fault-domain
availability. Production enrollment requires a separate DKG and independently
pinned host key for every production machine; DEV shares and policies must never
be copied into production.
