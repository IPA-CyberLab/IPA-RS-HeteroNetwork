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
node --check scripts/native-release-stage.catalog.mjs
```

Tests use private temporary directories and deliberately non-runnable synthetic
ELF fixtures. Integration runs the committed package builder with those fixtures
and the nine real helper files, stages/promotes through the shared channel tool,
and verifies preparation/selection preserves every byte. It does not execute any
packaged program and is not a VM rollout or runtime-health test.
