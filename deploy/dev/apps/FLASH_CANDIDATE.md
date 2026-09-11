# Flash DEV Candidate

On 2026-09-11, published prerelease
[v0.1.30-dev.2](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/releases/tag/v0.1.30-dev.2)
at exact source commit `1bd42505cf61a0cb7c2cb9df36b15d3d5f21ddf7`.
The candidate includes the diagnostic-generation operation-in-progress fix and
the preceding pinned-gVisor installer support. It does not imply PROD promotion.

Release workflow run:
[34593292094](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud-Flash/actions/runs/34593292094).
The run completed successfully: release verification, amd64/arm64 image builds
and the manifest job all succeeded. The published tag resolves to the exact
source commit above. Registry inspection of the artifact's immutable index
confirmed both linux/amd64 and linux/arm64 images.

Accepted index: `sha256:191c9c68251f7b578490b12fb18797f5f364b1124ae80fd14f457c42eb252cb2`.
amd64 manifest: `sha256:6015a4f4e9566682d0f3b096c41b7dd01a70f0ad11180e75e40c6e54ef005ed5`.
arm64 manifest: `sha256:ffc551db8af40bca63b8f4cf82e2efebd509e72f19056c482573a6590674b555`.
Artifact file SHA256: `e637d4fc3fddc2bb33fab73e8fbf917ea472e4b704d9a8092cc8a4daffe09d9b`.
The release-channel tool staged this artifact at revision17, changing only DEV
Flash. All nine channel tests passed. PROD remains unchanged.

Selected-source preparation passed with clean checkouts at each selected commit.
Bundle: `/tmp/hetero-dev-runtime-revision17-prepared`.
Manifest SHA256: `146d12418c17a225e84168e779db7bf830b0771b86eca9a8762cae7bc64ce5d1`.
Flash resources SHA256: `99388dcf194b5a53b09b8d1e4976f2757a83c436da0773e2eee6a3aa6d922e40`.
The Flash-only render diff changes the two Deployment images and the controller
storage class (already migrated live to dev-flash-rwx). Chart sources are unchanged.

Guarded DEV rollout and provider lifecycle verification completed on2026-09-11.
`upgrade-flash-dev2.py` validates both immutable bundles and permits only the
reviewed image/storage delta. It requires the shared-storage migration already
present live, patches only the two Deployment images and provenance annotations,
and waits for each rollout. Repeated apply made no image changes.

Actual helper bundle: `/opt/heteronetwork-dev-flash-upgrade-bbb4faac` on DEV1.
API ReplicaSet `568cbd6585` has three Ready Pods, one per DEV node; controller
ReplicaSet `76db9f7d96` has two Ready Pods on DEV1/DEV2. Image verification,
six health checks, three unauthenticated 401 checks and six RBAC checks passed.
There were zero DEV tenant Pods at upgrade time. No PROD resources were mutated.

The complete signed lifecycle also passed on dev.2: service creation, three
WebSocket shell checks, generation1-to2 update, replacement-Pod data recovery,
service/Pod/PVC deletion, repeated deletion acceptance and CSI volume reclamation.
No fixture PV remained. Browser OIDC/UI checks and node-failure HA remain
unfinished. The lagging-generation HTTP response itself was covered by source
unit tests, not deterministically forced/observed by this live lifecycle test.
