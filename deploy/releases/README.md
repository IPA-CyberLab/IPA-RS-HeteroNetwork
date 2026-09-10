# Reviewed Release Selections

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
