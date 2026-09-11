# Reviewed Release Selections

## Flow DEV Selection: Authenticated Redis

On 2026-09-11, revision 11 selects Flow `0.1.21-dev.5`, source
`411361c1551118d37ae70bee3306865093434000`. Workflow `34547624248` completed
successfully, including Redis authentication template checks and both image
publications. The release artifact binds:

- Flow: `sha256:5043adf20f75bf9a013b8c2a73cf611ac8145b6ee6f73c31c1320680f8b1ff08`
- LiveKit: `sha256:614c169bce49531838c0177f3698b280fbdafe66306db59c0e1721e6b17936f2`

DEV enables the bundled three-pod authenticated Redis/Sentinel configuration
and removes the separate single-instance Redis generator. The four-chart
offline check passed: Flash 12 resources, Flow 31, HCloud 12, Syouyu 21.
Site and auxiliary image fixtures are not operational provisioning evidence.
No application deployment or production promotion was performed.

## Flow DEV Selection: 2026-09-11

Revision 10 selects Flow `0.1.21-dev.4`, source
`b618852726ff5ffff1ed0386bad86b437ebface5`. Release workflow run `34546024819`
completed successfully, including verification and both image publications.
The uploaded `flow-release-artifact.json` binds:

- Flow: `sha256:02b3216210130fe51dce6331c88285c91e573d670811badcf0ae99fe1400a45e`
- LiveKit: `sha256:ce0f07783028d390752961a0247480adc840f6918fb870752d48b902dcb5694c`

The source commit includes checksum-verified Redis/PostgreSQL Helm dependency
archives, resolving the ignored-dependency checkout failure without bypassing
the immutable-source guard. The four-chart offline render and focused TURN
port/URL and redundant-placement regressions passed against selected checkouts.
Site and auxiliary-image inputs in those tests remain fixtures, not operational
deployment data. No cloud workload was deployed or promoted to production.

## Catalog Contract

`channels.json` is desired release state, not deployment evidence. It is updated
through `scripts/release-channels.mjs` with an expected revision. Do not reset its
history or edit digests manually. No existing production Application consumes
this file automatically.

## Initial Dev Selection

HeteroNetwork `0.1.15-dev.3` was selected from the successful
[release run 34514319296](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/34514319296)
and its [published assets](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/releases/tag/v0.1.15-dev.3).
The tag resolves to `eb3c9e145bf9e298aafba9bd0d1afad361d4192a`.

The downloaded archive and every catalogued binary/helper passed native
preparation and selection verification. The resulting artifact ID is
`80d9db6800418eb3ea232bf03dff9a805814445a37cbc30c4f0ecb8b96e22795`.
The release CI also passed the default cgroup-bounded majority-sudo E2E; this is
isolated test evidence, not production Keycloak or key-provisioning evidence.

The local prepared cache is disposable and is not committed. Recreate it from
the exact published archive using [native staging](../../docs/NATIVE_RELEASE_STAGING.md).
The selected version has not been activated on a VM. The initially empty `prod`
selection does not describe, remove or replace the currently running production
versions. Never promote solely because preparation or CI succeeded: verify the
isolated dev deployment and application workflows first.

## Flash Dev Selection

Flash `0.1.30-dev.1` was selected at revision 2 from the successful
[release run 34516628863](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/actions/runs/34516628863)
and its published `flash-release-artifact.json`. The source commit is
`e0cd20382c344b4e349f2f3327f0006b186fe913`; the final multi-architecture image
digest is `sha256:cd4150194ff1133ec6faf04567110dab14e905cd436744b02a4892ee1809357b`.
Verification and both architecture builds passed before the final image was
published. This records a dev selection, not a deployed workload or production
promotion.

## HeteroCloud And Syouyu Dev Selections

Revisions 3 and 4 select the published artifacts from successful release runs:

| Component | Version | Source commit | Release run |
| --- | --- | --- | --- |
| HeteroCloud | `0.1.71-dev.1` | `361b62213246b41f1765c381438c33af96f59dc9` | [34516902105](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/actions/runs/34516902105) |
| Syouyu | `0.1.7-dev.1` | `a15d8ab0f60685b932ca8f6d2a9ed88e4f96d3a9` | [34516904320](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Syouyu/actions/runs/34516904320) |

The downloaded release JSON supplied the image digests recorded in
`channels.json`. Neither selection activates a service. Production remains
unchanged; fresh dev deployment and end-to-end validation are still required.

## Flow Dev Selection

Revision 5 selects Flow `0.1.21-dev.3` from successful
[release run 34519325435](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flow/actions/runs/34519325435),
source commit `d275340d5f07b6dd409fafd5b7ce825a84a613cf`.
The published `flow-release-artifact.json` binds both Flow and LiveKit image
digests. Both image builds and the Rust, scheduling, monitoring and chart checks
completed successfully. Earlier failed candidates were not selected or retagged.
All five components now have dev selections; no production promotion or runtime
deployment follows automatically from this catalog change.

## HeteroNetwork Dev.4 Selection

Revision 6 selects `0.1.15-dev.4`, source
`c5f8502ae9f57f35726345f4c361651152deff1e`, from successful
[release run 34521073321](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/34521073321).
Both published native archives were downloaded and verified with
`native-release-stage.py prepare`, followed by `select` at revision 6.
The prepared artifact ID is
`f5fbb42753ac0378763f1228d149b504b0bddddc04cd905fafbf3f7ed8c6969a`.

This selection binds the release-profile sudo companion, including its source
commit, plugin header and file hashes. Preparation reported `sudo_prepared: true`
and `activation_performed: false`. No production sudo policy or service was
changed. Guest bootstrap, dev application validation and production activation
remain separate required steps.

## HeteroCloud Dev.2 Selection

Revision 7 selects `0.1.71-dev.2`, source
`197a8184cadbcd32d7a2fac7f9ecf92cb8a8b6d2`, after successful
[release run 34533354126](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/actions/runs/34533354126).
The downloaded artifact binds image digest
`sha256:c3f189bbca05830da15d7a8a4c102246c7137fc3a5ab30d70c3cc329689db3f9`.
This chart enforces HTTPS owner-console secure cookies; the dev overlay enables
them and Helm verification checks the rendered arguments. This is a verified
release selection, not a deployed HeteroCloud service or production promotion.

## HeteroNetwork Dev.5 Selection

Revision 8 selects `0.1.15-dev.5`, source
`99ea82684a9c58c353f767db276b26f79c890f76`, after successful
[release run 34534355196](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/34534355196).
All ten verification jobs and the publisher completed successfully. Both native
archives were downloaded from the prerelease; `prepare` verified the base files
and sudo companion, then `select` verified the committed channel at revision 8.
The artifact ID is
`086f3bf5280ac44b59750e7ed82cde301311e5d2e76bb01c8c8fff0cd28ef00e`.
The base archive SHA-256 is
`3bccfbd20b8fac68e8ae93de22ee5967e12b964e038e604535e063b9184c4cf9`;
the sudo archive SHA-256 is
`c65766da4aba5a587fbb4230dfde85f0aa71388f72071eb2632f39d5cd842d8f`.

This release includes the public STUN fallback and fresh-dev kubeadm fixes.
Preparation reported `sudo_prepared: true`, `activation_performed: false`.
The running dev agents have not been upgraded from dev.4 by this selection.
Production shares, sudo enforcement and application rollout remain incomplete.

A read-only inventory of ichikawap1 during this selection found the agent active
and the local control plane inactive. Agent stop dependencies include control
plane, overlay DNS, PostgreSQL bundle, signal and STUN, with kubelet outside the
inspected unit scope. Collection exited 2 due to incomplete evidence, including
unreviewed unit roles and an absent native Kubernetes controller binary. This is
not authorization for an unattended agent restart. No live service or sudo
configuration was changed by the inventory.
