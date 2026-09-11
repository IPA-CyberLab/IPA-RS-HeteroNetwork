# OIDC CA Candidate Selection

On 2026-09-11 the DEV channel was advanced by the CAS/replay-checked channel CLI
from revision14 to15, selecting Cloud `0.1.71-dev.5` at commit
`c81681b89b2151a9ae3214d045c938d38b8f74df`.

The published release artifact selects
`ghcr.io/ipa-cyberlab/ipa-rs-heterocloud@sha256:70a41870b9e5c986512f2665bceb5a4d079dd7e1e0958ac36751b95e7928b9b3`.
Registry inspection independently returned that index digest and a linux/amd64
manifest. The [release job](https://github.com/IPA-CyberLab/IPA-RS-HeteroCloud/actions/runs/34557835605)
completed successfully, including validation, image publishing and Linux/macOS/
Windows CLI builds. The earlier dev.4 candidate failed test-only Clippy validation;
its tag was not rewritten and it was never selected.

The clean selected-commit local Helm check passed for all four DEV charts:
Cloud12, Flow31, Flash12 and Syouyu21 rendered resources. It also checked the
Cloud API and owner CA argument/read-only Secret mount and immutable image pins.
The initial local check refused a generated Python bytecode file from our chart
test; that file was removed and the check passed with bytecode generation off.

This is selection and render evidence, not runtime deployment. The production
channel remains empty. Existing DEV DBs, app Secrets, identity DNS and scoped
Keycloak ingress are provisioned, but Cloud/Flow/Flash/Syouyu workloads are not.
Capacity expansion, real owner enrollment, authenticated login, data-path E2E,
failover and sudo enforcement remain separate unfinished requirements.
