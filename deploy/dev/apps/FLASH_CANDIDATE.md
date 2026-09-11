# Flash DEV Candidate

On 2026-09-11, published prerelease
[v0.1.30-dev.2](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/releases/tag/v0.1.30-dev.2)
at exact source commit `1bd42505cf61a0cb7c2cb9df36b15d3d5f21ddf7`.
The candidate includes the diagnostic-generation operation-in-progress fix and
the preceding pinned-gVisor installer support. It does not imply PROD promotion.

Release workflow run:
[34593292094](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/actions/runs/34593292094).
At the last inspection, release identity/artifact verification succeeded and
both architecture jobs were in progress. No release artifact or final image
digest has been accepted yet. Do not restart this run based on an observation
timeout; inspect its authoritative state first.

The next steps are to verify successful completion of both image jobs and the
manifest job, download `flash-release-artifact.json`, verify its component,
version, commit and registry digest, and stage that exact artifact with the
release-channel tool. Current channel revision is16 and selected Flash remains
0.1.30-dev.1. Re-read the revision before staging; never overwrite another update.
The current runtime still uses its shared-storage migration on revision16.

After staging, prepare the selected-source manifests with `prepare-runtime.py`,
review the exact Flash-only delta and dependency/capacity admission, deploy into
the identified DEV cluster, then verify diagnostic pending generations, real
provider operations and preserved unrelated workloads. Do not substitute an
unverified architecture tag or source-commit tag for the published digest.

No DEV runtime image or PROD channel was changed by publishing this candidate.
