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
