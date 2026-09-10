# Disabled Sudo V2 Artifact

This package is **not enabled** by publication or staging. The release workflow
publishes it as a digest-bound native companion; activation remains separate.
It supplies only `local-sudo-v2`, the
`quorum_v2_gate` approval plugin, a disabled-state notice, and integrity metadata.
It contains no issuer shares, requester keys, host keys, policy, credentials,
fixture binaries, service units, sudoers/PAM configuration, or live ledger.

The package is not a generic root executor. The existing implementation remains
an additional approval gate for an invocation already authorized by sudoers and
the normal password/authentication policy. It is not an exact-command sandbox
and does not protect against an already privileged OS administrator.

## Build

Use a trusted Linux source tree and native Rust/C toolchain. Required tools are
Python 3, Cargo with the repository toolchain, a C compiler, `nm`, and Git. The
prototype has its own Cargo workspace/lockfile. Linux amd64 and arm64 are
recognized; cross compilation is not silently inferred.

Supply the public `sudo_plugin.h` from sudo v1.9.17p2 at immutable upstream
revision `d1b48c651cec19fe37d1f0d3299d2283fb0f88e4`. Its required SHA256 is
`11234d6e47e6da95adcb3ace71dc93f1d94b759aeca4cd938d829c076adfb35f`.
The helper does not download headers or inspect production sudo configuration.

```bash
bash scripts/package-sudo-quorum-v2.sh \
  --sudo-header /trusted/inputs/sudo_plugin.h \
  --out-dir /trusted/output/new-sudo-v2-artifact
```

The output parent must exist, belong to the caller, and not be writable by other
users. The output directory must not exist. Release builds are the default;
`--profile dev` is available for disposable verification and recorded as such.
The build compiles/runs the focused buffered-expiry ACK regression, not a sudo
invocation. It checks the plugin export and ELF architecture and records source
hashes before/after building. Uncommitted source is explicitly marked dirty;
`source_commit` is repository context, not a claim that dirty bytes equal that
commit. No release/source versions are rewritten and no publish action runs.

Output files are the archive, its SHA256 sidecar, and `manifest.json`. Archive
metadata is deterministic for identical payload/provenance; independent compiler
builds are not claimed reproducible. Digests establish integrity, not publisher
identity: obtain the expected archive digest through a trusted independent path.

## Non-Activating Install

```bash
bash scripts/install-sudo-quorum-v2-artifact.sh \
  --archive /trusted/input/sudo-quorum-v2-linux-amd64.tar.gz \
  --sha256 TRUSTED_64_CHARACTER_SHA256 \
  --destination /opt/heteronetwork/sudo-v2/artifacts/NEW_DIRECTORY
```

Provision the destination parent separately. Root installation requires
root-owned ancestry without group/world write permissions; unprivileged staging
is also supported. The installer rejects symlink ancestors, existing destinations,
extra archive paths, links, wrong architecture, altered notices, mismatched
hashes, and setuid/setgid modes. It never runs an artifact. It writes the manifest
last and leaves an incomplete newly created directory for operator inspection
if a write fails; it never deletes or replaces an existing installation.

No unit is installed, started, or enabled; no `sudo.conf`, sudoers, PAM, host
authentication, routing, or active-version pointer is touched. The binary is
0755 and the plugin is 0644, never setuid/setgid. No daemon starts at boot.

## Release Contract (Not Publication)

From a clean checkout of the exact intended release commit:

```bash
bash scripts/package-sudo-quorum-v2.sh --sudo-header /trusted/sudo_plugin.h \
  --out-dir /trusted/new-output --profile release \
  --source-commit FULL_LOWERCASE_40_HEX_SHA --version v1.2.3-dev.1
```

Both identity flags are required together. Version must be SemVer without build
metadata (`+...` is rejected to match the catalog), optionally
prefixed with `v`; source commit must equal HEAD. Release mode checks the entire
worktree, including untracked files, before and after building, requires the
release profile, and validates the completed archive and matching clean-source
provenance before emission. Keep build outputs outside the checkout (or in its
existing ignored build directory). Only linux-amd64 is release-supported.

The new output directory includes `release-contract.json`: the inner platform
record to bind at HeteroNetwork catalog `.sudo_native["linux-amd64"]`, not a full
catalog and not a channel update. Its exact fields are:

```json
{
  "asset": "heteronetwork-1.2.3-dev.1-sudo-v2-linux-amd64.tar.gz",
  "sha256": "ARCHIVE_SHA256",
  "source_commit": "FULL_COMMIT_SHA",
  "profile": "release",
  "plugin_header_sha256": "PINNED_HEADER_SHA256",
  "files": {
    "bin/local-sudo-v2": {"sha256": "SHA256", "size": 1, "mode": 493},
    "lib/quorum_v2_gate.so": {"sha256": "SHA256", "size": 1, "mode": 420},
    "NOT_ENABLED.txt": {"sha256": "SHA256", "size": 1, "mode": 420}
  }
}
```

The example sizes/hashes are placeholders; emitted sizes are actual positive
bounded byte counts. `manifest.json` is archive-digest-covered but excluded from
the file list to avoid self-hashing. The parent release publisher must enforce
`source_commit == catalog.commit == exact release event SHA`, matching asset
version, release-only publication and no overwrite. No other component may use
this binding. Emission is not a publisher signature or permission to activate.

Without both identity flags this remains standalone, reports
`release_contract: false`, and emits no release contract, even with the release
build profile. The dev path remains available but is not a release artifact.

## Release Workflow Binding

`.github/workflows/ci.yml` runs on published releases only. Its publication job
retains the real sudo E2E dependency and builds the inactive payload before
publishing the image. It fetches the public header from the immutable official
sudo revision above; the packager verifies the pinned SHA256 before compilation.
Header, Cargo target, package and catalog outputs live under `RUNNER_TEMP`, not
in the clean source checkout. Exact event SHA, checked-out HEAD and tag must agree.

`scripts/bind-sudo-release-artifact.mjs bind BASE.json CONTRACT.json SUDO_ARCHIVE
OUTPUT.json` validates the parent catalog schema, independently decodes the actual
sudo archive with the packaging validator, compares all contract metadata and
digests, and exclusively creates the combined artifact. Native packaging consumes
this combined artifact so the final catalog contains both `native` and
`sudo_native`. It never updates deployment channels.

Before upload, `verify CATALOG.json SUDO_ARCHIVE NATIVE_ARCHIVE` requires both
validated bindings, verifies sudo archive contents/provenance and the actual
native archive digest. Native payload metadata is generated by the existing
native packager; this verifier does not re-extract the native archive. All digest
values come from actual build bytes, not release tag assumptions.

The existing-assets guard includes the sudo archive as well as the native archive
and catalog. Upload has no `--clobber`; partial publication requires investigation,
not replacement. Focused emitter/binder/schema tests run in release verification.
This workflow binding still does not install or activate sudo on any host.

## Read-Only Configuration Check: New Builds Only

**Do not invoke `local-sudo-v2 --check-config` on the existing dev5 artifact or
any older/unverified binary. Older binaries ignore arguments and start the
server instead, potentially opening or creating the ledger, process lock and
IPC sockets. The flag is not a safe feature-detection probe.**

The new source implementation accepts exactly `--check-config` and uses the
same policy and host-attestation-key validation as runtime startup. It requires
root and the existing fixed, strictly checked `/etc/ipars-sudo-v2/config.json`
and `/etc/ipars-sudo-v2/host.key` paths; there are no path overrides. Success or
failure emits no key material. This branch returns before accessing runtime
directories, opening the ledger, acquiring the process lock or touching sockets.

Use this feature only after a newly built, independently verified future release
is confirmed by its exact source commit and companion digest to include this
implementation. No already released artifact gains the feature from a source
change. Do not execute an old binary with this flag, `--help`, or another guessed
argument to discover support. This documentation does not authorize an upgrade,
release, service start or plugin activation.

The separate `scripts/dev-sudo-readiness.py` checker remains static: it never
executes the installed companion, including dev5. Its artifact, public-policy
pin and service-file checks are prerequisites, not activation clearance. A
successful native configuration check also does not validate an existing ledger,
effective service overrides, sudo plugin loading, or the full privileged E2E path.

## Separate Activation Review

Before any later activation, independently review the installed sudo approval
plugin ABI, root-owned plugin/daemon ancestry, service identity and limits,
trusted SudoPolicy/manifest and owner identities, host attestation key and its
epoch, persistent ledger/clock/locking behavior, and the real CLI signer path.
Provision only new deployment-specific secrets through the legitimate ceremony.
Never install a disposable fixture or reuse its dealer keys. Preserve existing
sudoers authorization and password authentication; missing or invalid approval
must deny rather than fall back to an unguarded execution path. Loading the plugin
without a healthy provisioned local service can deny otherwise valid sudo calls,
so this packaging helper intentionally provides no automatic activation command.

This package does not remove the independent full E2E requirement, including
`sudo-issue`, `sudo-approve`, expiry, restart, replay, identity denial, and the
real sudo password/sudoers gates. See `docs/SUDO_QUORUM.md` and
`scripts/test-sudo-quorum-v2.sh` for that separate evidence.

Offline packaging tests (no artifact execution or host configuration changes):

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts \
  -p test_sudo_quorum_v2_artifact.py -v
```
