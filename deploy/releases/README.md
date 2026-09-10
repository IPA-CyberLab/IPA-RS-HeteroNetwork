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
