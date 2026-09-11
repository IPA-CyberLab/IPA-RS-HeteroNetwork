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
