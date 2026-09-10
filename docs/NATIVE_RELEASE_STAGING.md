# Native Release Staging

Native preparation verifies and stores immutable release bytes. It does not
install a release, change a live binary or symlink, invoke a packaged program,
run helper scripts, restart a service, or modify VM/tenant configuration. A
prepared slot or selected channel is **not a completed VM rollout**.

## Shared Release Contract

The tool consumes the existing release artifact and `CHANNELS.json` from
[RELEASE_CHANNELS.md](RELEASE_CHANNELS.md). There is no separate native catalog,
version counter, or dev/prod promotion mechanism. The shared artifact contains:

```json
{
  "schema_version": 1,
  "component": "heteronetwork",
  "version": "1.2.3",
  "commit": "FULL_LOWERCASE_40_CHARACTER_COMMIT",
  "image": "ghcr.io/ipa-cyberlab/heteronetwork@sha256:LOWERCASE_IMAGE_SHA256",
  "native": {
    "linux-amd64": {
      "asset": "heteronetwork-1.2.3-linux-amd64.tar.gz",
      "sha256": "LOWERCASE_ARCHIVE_SHA256",
      "files": {
        "bin/ipars": "LOWERCASE_FILE_SHA256",
        "bin/iparsd": "LOWERCASE_FILE_SHA256",
        "bin/ipars-k8s-controller": "LOWERCASE_FILE_SHA256",
        "libexec/public-services-autopilot.sh": "LOWERCASE_FILE_SHA256"
      }
    }
  }
}
```

Placeholders intentionally fail validation. All hashes must be genuine lowercase
64-character SHA-256 values. The asset name uses the release version without a
leading `v`. Required payloads are all three listed binaries. Optional helpers
have flat paths matching `libexec/[a-z][a-z0-9-]*.sh`, with at most 64 total files.
The committed builder currently includes nine reviewed helpers. The stager
requires every catalogued file and rejects every unlisted file.

The package builder copies native binaries from the stopped, just-built release
image and binds the archive hash and file hashes into the same artifact as the
image digest and commit. Preparation uses the shared Node `validateArtifact`
and `transition` functions through a fixed local bridge; it never imports code
from the archive. The transition call validates the complete channel history
without writing it. Native staging additionally bounds metadata and rejects
control characters and an unexpected native source-image repository.

SHA-256 proves byte integrity, not publisher identity or rollout authorization.
Obtain both the catalog and archive through the approved release process, review
the release provenance, and protect the channel file against unauthorized writes.
The tool does not download URLs or independently attest that an ELF binary was
built from its claimed commit. ELF header checks do not prove ABI compatibility,
dynamic-library availability, successful execution, or runtime health.

## Prepare and Inspect

Requirements: Linux, Python 3.11 or newer, Node 18 or newer available under the
system `/bin:/usr/bin` search path, and a trusted checkout containing the staging
script, bridge, and shared release validator. Staging needs no root privilege.
Use an existing private directory owned by the invoking user; under root it must
be root-owned. The tool refuses symlinked directory components, untrusted writable
ancestors, and group/world-accessible staging directories. A root-owned sticky
temporary ancestor is allowed for isolated tests.

```sh
mkdir -m 0700 /absolute/private/native-stage
python3 scripts/native-release-stage.py prepare \
  --channels /absolute/reviewed/channels.json --environment dev \
  --archive /absolute/downloads/heteronetwork-1.2.3-linux-amd64.tar.gz \
  --root /absolute/private/native-stage
```

The JSON response includes `selected_revision`, `environment`, `artifact_id`,
`archive_sha256`, the complete canonical `manifest`, `slot`, and
`activation_performed: false`. The artifact ID is SHA-256 of the shared
validator's canonical `JSON.stringify(artifact)` bytes, without a newline. This
binds the full primary artifact and native map, not only the daemon or archive.

The slot is `ROOT/slots/ARTIFACT_ID`, containing canonical `manifest.json`,
`archive.tar.gz`, and the exact `bin/` and `libexec/` payloads. Payloads and metadata
are staged read-only with no executable permission; final slot directories are
read-only. A complete temporary slot is fsynced and atomically renamed into place.
An existing slot is reverified rather than overwritten.

```sh
python3 scripts/native-release-stage.py inspect \
  --root /absolute/private/native-stage --artifact ACTUAL_ARTIFACT_ID
```

Inspection revalidates the catalog and rehashes the archive and every payload.
It rejects extra contents, hard-linked files, changed sizes, writable payloads,
symlinks, and nonregular files. Read-only modes prevent accidental changes; they
do not prevent the directory owner or root from changing permissions or bytes.

## Selection and Promotion

Promote with the existing `release-channels.mjs` workflow after reviewing dev
test evidence. Its prod selection retains the exact primary artifact and native
map; no rebuild is involved. Resolve the prepared slot against that shared state:

```sh
python3 scripts/native-release-stage.py select \
  --channels /absolute/reviewed/channels.json --environment prod \
  --expected-revision 2 --root /absolute/private/native-stage
```

`select` is a read/verification operation. It does not update `CHANNELS.json`,
maintain another state file, copy a second payload, or write a live `current`
symlink. It fails if the selected artifact has not been prepared or has changed.
The optional expected revision detects a stale caller's channel snapshot.
`prepare --environment prod` can prepare the approved prod artifact directly on a
different VM without requiring the dev slot to exist on that machine.

The shared channel file can advance after it is read. Reported revision and
digests describe that snapshot, not a lease on deployment state. The separately
approved activation procedure must recheck current desired state, the intended
environment and host, the complete artifact identity, and on-disk hashes before
changing any live path. Copying channel files between machines is not a distributed
CAS or an authorization mechanism.

## Archive and Filesystem Boundaries

Only literal catalog paths in a gzip-compressed USTAR archive are accepted.
Directory entries, `./` prefixes, traversal, absolute paths, duplicates, links,
devices, FIFOs, sparse files, and PAX/GNU extension records are rejected. Parsing
uses Python's tar-header API without `extract` or `extractall`; archive paths are
never used to select arbitrary filesystem destinations.

The compressed archive is limited to 512 MiB; each binary to 256 MiB; each helper
to 2 MiB; and total extracted payload to 1 GiB. All three binaries must be ELF64,
little-endian, x86-64 executables with a valid basic ELF header. The reader checks
the archive SHA before parsing on the same descriptor used for decompression,
then hashes the exact payload bytes it writes. Sizes are bounded from actual
input, not trusted declarations in the manifest.

All staging operations use an exclusive local `.lock` and descriptor-relative
filesystem access. No shell, archived helper, or archived binary is executed.
The fixed Node validation subprocess has a sanitized environment, excluding
`NODE_OPTIONS`, `NODE_PATH`, and other inherited execution settings. Failures do
not echo untrusted metadata or archive paths into terminal output.

A caught preparation failure removes its own temporary slot. A process crash
may leave a stale lock or an unselected temporary/complete slot. Inspect the
process and filesystem before removing those remnants; do not automatically
break locks based only on a reused PID. Fsync/atomic rename require a local
filesystem with normal Linux semantics, not independent networked copies.

## Activation Limitations

### Read-Only Host Inventory

Before implementing or authorizing native activation, collect the installed host
facts with the fixed-scope local inventory tool:

```sh
python3 -B scripts/native-release-inventory.py
```

Run it locally through an already authorized administration channel. It has no
remote host, command, unit, filesystem-root or output-file option. It does not
connect to production from another machine, invoke archived/installed payloads,
restart services, change channel state, or write an activation selector. It emits
JSON to stdout; collecting evidence is **not activation or a completed rollout**.
Actual live switching, dependent-service restart, health verification and rollback
remain the next implementation task.

The collector uses fixed `/usr/bin/systemctl show` calls with allowlisted
key/value properties. It discovers the full `heteronetwork-*` unit namespace,
including DB, Keycloak, PostgreSQL/bootstrap/public-services/Relay-autopilot
services and timers. Fixed unit-directory discovery supplements loaded systemd
units so inactive/unloaded installed units are not silently omitted. It records
load/active/sub/enabled states, dependency edges, the transitive
Requires/BindsTo/PartOf dependent closure, and unit-fragment/drop-in hashes and
ownership/modes. Dependencies outside that namespace are identified as an
uninspected boundary; external stop dependents make the evidence incomplete.
The closure is restart-planning evidence, not an executed systemd job plan.
Dependency lists parse systemctl's whole-word double quoting and doubled
backslashes with a bounded, validated quoted-word parser. Dependency names may
contain complete `\x` escapes followed by two lowercase hex digits (for example
`\x2d` in a systemd credential mount). They remain literal
metadata, bounded to 255 characters; malformed escapes, encoded controls and
encoded slashes are rejected. Unterminated/concatenated quotes and bare backslashes
in the serialized property are rejected rather than silently stripped. This does
not expand queried unit names or allowed filesystem paths.

The fixed payload inventory hashes all three binaries and nine packaged helpers
at `/opt/heteronetwork/bin` and `/opt/heteronetwork/libexec`. The independently
installed `/opt/heteronetwork/bin/caddy` is reported separately under `preserve`;
it is not part of the native release or permission to replace the whole `bin`
directory. File reads use pinned no-follow directory descriptors and report
untrusted ownership/modes, links, missing/inaccessible files and observed races
as incomplete evidence. Only the conventional `/lib` to `/usr/lib` vendor-unit
alias is normalized; arbitrary file/directory symlinks are not followed.

Main/control process executable hashes are collected through the kernel's
`/proc/PID/exe` link when permitted, without reading command lines or environments.
A bounded visible-process scan reports unclassified consumers of fixed native
paths or matching installed executable inodes. Unit-file literal artifact
references are reported, but are not proof of effective command execution.
An interpreter hash cannot identify its running helper script; those bindings
remain unverified. Other PID namespaces, copied executables at unrelated paths,
future invocations and arbitrary external-unit consumers are outside this scan.
No configuration/environment values, ExecStart arguments, key contents, unit
contents or subprocess error text are emitted.

Bounds: 256 units, 64 drop-ins per unit, 8,192 entries per unit directory, 4,096
visible processes, 1 MiB per unit/drop-in, 2 MiB per helper, 256 MiB per executable,
and 2 GiB total hashed bytes. Each systemctl call has a five-second timeout and
2 MiB output limit, with up to one additional second for killed-child cleanup;
collection checks a 120-second overall budget between reads.
The final report is capped at 8 MiB. These are not hard deadlines for a stalled
kernel filesystem read. Reads may update filesystem access times; the tool
performs no explicit filesystem writes.

`evidence_complete` describes only successful collection within that scope.
Unknown roles/consumers, unobservable processes, unavailable properties, missing
artifacts, unsafe metadata or exceeded bounds produce issues and exit status 2.
Exit status 0 is scoped evidence collection, **not deployment readiness**:
`deployment_ready` and `activation_performed` are always false, and
`snapshot_atomic` is false. The report does not establish release provenance,
rollout authorization, current HA health, state/schema compatibility or rollback
safety. Recheck host facts immediately before any separately approved activation.

`dependencies.uninspected_stop_dependents_by_origin` attributes external stop
boundaries to each inspected unit, including transitive paths through inspected
units. For example, a gateway may affect kubelet through its dependent agent.
This is only a known boundary, not a complete external dependency graph; the
collector neither inspects those external units nor clears the incomplete-evidence
gate. Never treat an empty per-origin boundary as proof that restarting is safe.

On the supplied `.10` observation, Agent requires Gateway, while Control Plane,
Signal and STUN each require and bind to Agent. An Agent stop therefore requires
explicit dependent-service restart and recovered HA readiness before progressing
to another host; a successful inventory does not satisfy either gate.
Supplied read-only `.10` observations identify Web UI port `19088` and Control
Plane port `19443`, with successful `/healthz` responses; port `18088` is not
listening. These are supplied host facts, not probes performed by this inventory
tool. Revalidate actual listeners rather than assuming deployment-template ports.

The supplied read-only non-root `.10` v3 inventory on 2026-09-10 parsed 32 units
with no `invalid_systemctl_dependencies` errors. Exit status remained 2: process
permissions, unreviewed roles/dependents, unverified helper bindings and the
missing host `ipars-k8s-controller` still leave evidence incomplete. The report
sets `evidence_complete`, `deployment_ready` and `activation_performed` to false.
This verifies collection/parsing, not root-level completeness or a deployment;
no activation was performed.

The existing `rollout-console-owner-update.sh` is a specialized, executing rollout
helper. It expects a different archive layout, installs configuration, reconciles
authentication, and restarts services. **Do not pass this native archive to it.**
This staging tool does not adapt, invoke, or certify that helper.

Actual activation remains a separate approved rollout task. It must review
coupling between all three binaries, the nine helpers, service units, proxy and
bootstrap configuration, persisted state formats, database migrations, quorum
manifests, and node roles. This archive is not a complete replacement for those
configuration assets. Updating only `iparsd` does not establish operational
compatibility or a complete upgrade. No arbitrary root HTTP executor is added.

Dev testing needs separate VMs/state, databases, secrets, DNS, and IdP clients.
A directory named dev is not infrastructure isolation. Rolling back selected
bytes does not roll back database migrations or restore compatible live state.
Preparation and these tests do not modify production, restart agents, alter
sudo/PAM, or operate tenant containers.

## Focused Verification

```sh
python3 scripts/native-release-stage.test.py
python3 -B scripts/native-release-inventory.test.py
node --check scripts/native-release-stage.catalog.mjs
```

Tests use private temporary directories and deliberately non-runnable synthetic
ELF fixtures. Integration runs the committed package builder with those fixtures
and the nine real helper files, stages/promotes through the shared channel tool,
and verifies preparation/selection preserves every byte. It does not execute any
packaged program and is not a VM rollout or runtime-health test.

Inventory tests mock systemd/process discovery and use inert temporary files.
They cover fixed read-only commands, bounded output/timeouts, credential-output
suppression, inactive-unit discovery, dependency closure, executable evidence,
unknown consumers, symlink/race rejection and incomplete reporting. They do not
collect live production inventory or execute any artifact.

## Sudo Companion Identity

The shared HeteroNetwork catalog also accepts an optional `sudo_native` binding
for a separate Linux amd64 sudo-v2 archive. It binds the version-derived asset
name, archive SHA256, matching source commit, release build profile, pinned sudo
plugin header, and the exact hashes, sizes and modes of the daemon, plugin and
disabled-state notice. These fields participate in stage/promote/rollback equality
and history replay; omitting or changing them cannot match a selected release.

This validation checks metadata, not build provenance or deployed policy. The
native preparation tool requires `--sudo-archive` whenever the selected catalog
contains `sudo_native` (and rejects that argument without a binding). For example:

```sh
python3 scripts/native-release-stage.py prepare --root /trusted/private-staging \
  --channels /trusted/channels.json --environment dev \
  --archive /trusted/heteronetwork-1.2.3-linux-amd64.tar.gz \
  --sudo-archive /trusted/heteronetwork-1.2.3-sudo-v2-linux-amd64.tar.gz
```

The fixed sibling packager validator checks the companion archive digest,
manifest and payload hashes/sizes/modes, ELF architecture, disabled notice,
source commit, clean release profile, ACK regression and pinned plugin header.
The catalog binding must match the verified metadata. Companion bytes are stored
under `slots/<artifact-id>/sudo/`, with private directories and non-executable
`0400` files; archive installation modes are verified but not applied. Inspection
and selection revalidate the companion archive and every staged payload before
returning `prepared: true` and `sudo_prepared: true`. A missing or altered
companion prevents preparation/selection, including reuse of an existing slot.
Catalogs without a binding retain base-only verification and report
`sudo_prepared: false`. No payload is executed, installed or activated; this does
not establish runtime readiness or provision policy, keys or services. Publication
must establish the companion's clean source and actual payload identity, and
the companion installer must verify its bytes independently. No currently
selected release is retroactively assigned a synthetic sudo archive binding.

## Observed DEV Selection: dev.6

On 2026-09-10, release run `34538542968` completed successfully for commit
`22c4e3baf5de53f70bbac08f5fe62a0590e24526`. The published catalog and both
archives were downloaded from release `v0.1.15-dev.6`. The preparation and
selection commands independently validated all payloads against that catalog.
The resulting artifact ID is
`57cfd22395cfaa85557f94fb039f79acc6f15a8f5b0b4b2155f3ba88fa23a228`.

`deploy/releases/channels.json` revision 9 selects this release for DEV only.
The native archive SHA256 is
`ddd1cf26a1b6957ef64cf6506f744188f415ac92dafee1db2b7b82fc361c45ca`;
the sudo companion archive SHA256 is
`0a1d2c9c0d39435e53777557a859a734ef0d1af7d5cc07e0de27d673a8cba569`.
Both `prepared` and `sudo_prepared` were true; `activation_performed` was false.

This release contains the native `local-sudo-v2 --check-config` implementation.
Do not invoke that argument on older binaries: those binaries may ignore it and
start the service. No DEV or production agent was replaced by this selection,
and no production channel, sudo configuration or running service was changed.
