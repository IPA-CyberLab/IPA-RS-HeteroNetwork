# HeteroNetwork host infrastructure

This module manages the existing `uc-k8sp1`, `uc-k8sp2`, and `uc-k8s3p` hosts.
The [deployment and verification record](../../../docs/master-only-iac-2026-09-15.md)
also documents the current workspace's operator connection.
Terraform runs the versioned Ansible configuration, publishes a read-only
internal Git source on `uc-k8sp5`, imports the five existing
HeteroNetwork GitOps Application sources, and creates the `control-plane-only`
Argo CD Application. The physical machines and their operating systems already
exist; this module manages their HeteroNetwork and Kubernetes configuration.

`standard-nodes.json` additionally registers `uc-k8sp4` (`100.111.33.52`,
SSH endpoint `163.220.236.54`) as a full-service node. Its separate Ansible
resource installs the pinned Agent, enrolls through the existing issuer with
a short-lived single-use token, joins the existing Kubernetes control plane,
and enables the signed native public-service installation. An inactive old
cluster configuration is backed up and reset only after verifying that it has
no running containers. The enrolled identity is saved in the same protected
recovery vault. Standard hosts use an Ansible temporary directory under `/tmp`
because this host's home directory belongs to root.

The `standard-nodes` Argo CD Application maintains schedulable Node settings,
public ingress, and enabled Longhorn scheduling. Its admission policy removes
the control-plane `NoSchedule` taint and dedicated-master taints on this host
while preserving other controller taints. Standard-node configuration has a
separate Terraform trigger from the three dedicated masters. The dedicated
master isolation policies continue to apply only to the original three hosts.
`terraform_data.console_configuration` explicitly maintains the Agent's overlay
listener on 9781 and a VPN-only compatibility proxy on 80 on all six gateways.
It also distributes and verifies the checksum-pinned native binaries on all six
gateways, including the bootstrap and enrollment issuer hosts that are not
created by the master or standard host resources.
The Agent wants this proxy so it returns after Agent restarts. The dedicated
master playbook preserves this Agent companion while disabling native
application services. No application Pod is added to the dedicated masters.
The [standard-node deployment record](../../../docs/standard-node-setup-2026-09-15.md)
describes its client DB/Keycloak proxies, declared six-endpoint Kubernetes pool,
and Longhorn filesystem disk with 64 GiB reserved for the host OS.

`terraform_data.onboarding_acceptance` runs live E2E after host configuration,
console configuration and Argo synchronization. First registration of a
standard host starts with `heteronetwork.io/onboarding=pending:NoSchedule`.
Acceptance probe Pods explicitly tolerate this taint. The gate verifies both
console URLs through every real gateway in Chromium, including the public
Keycloak credential form on 9781, dedicated-master placement rejection, and
normal scheduling, DNS, cross-node traffic and PVC persistence on standard
hosts. After every check passes at the candidate Git revision, the gate writes
`heteronetwork.io/onboarding-status=accepted` and removes its standard-host
quarantine taint. Failure returns a failed Terraform apply, records `failed`,
and retains the quarantine. An old passing report or replaced Node UID cannot
satisfy the gate. Host recreation, console changes and a new infrastructure
revision retrigger E2E. The wrapper checks this acceptance proof for drift.
The [acceptance and console recovery record](../../../docs/onboarding-e2e-gate-2026-09-15.md)
documents the checks and their scope.

Argo CD reconciles the dedicated Node labels, cordon, Longhorn scheduling
opt-out and admission policies from `deploy/gitops/control-plane-only`.
The Node mutation policy maintains the three required isolation taints while
preserving taints owned by Kubernetes controllers. Argo ignores the complete
taint array to avoid fighting automatic `unschedulable` / health taints.
The DaemonSet mutation policies preserve existing affinity OR terms, exclude
dedicated masters from nonessential DaemonSets, and keep the essential Flannel
and kube-proxy tolerations after Helm or GitOps reapplies their templates.
The Pod and binding validation policies deny normal application placement even
when a Pod tolerates every taint or directly specifies a target node.

The host playbook installs the repository's `control-plane-only` kubeadm helper,
the pinned native networking binaries, the minimal Agent service and persistent
kubelet settings. It disables native services outside the master role. It
retains mutable API-backend discovery fields while enforcing profile, host IP,
host name and maximum Pod count. Kubernetes initialization is skipped on
already joined hosts. Cleaned hosts restore their existing HeteroNetwork
identity and join the existing Kubernetes cluster with short-lived credentials
issued on `uc-k8sp5`; no new cluster is initialized.

## Apply

Install Terraform >=1.10, ansible-core 2.19.5, Python with PyYAML and kubectl.
The lockfile pins the Terraform providers. Use an operator kubeconfig that can
reach the existing cluster, the authorized SSH key, and a private work directory:

```bash
export TF_VAR_kubeconfig_path=/secure/operator-kubeconfig
export TF_VAR_ssh_private_key_path=/secure/operator.key
export TF_VAR_work_dir=/secure/heteronetwork-master-only
python3 scripts/publish-master-only.py --work-dir "$TF_VAR_work_dir"
python3 scripts/master-only-iac.py plan
python3 scripts/master-only-iac.py apply
```

The entry point prompts for sudo credentials, checks both host profiles and the
internal Git source with Ansible, and marks only resources with observed drift
for Terraform reconciliation. Secret credentials
are passed in the process environment rather than Terraform variables or state.
The canonical host entry point is this wrapper: plain `terraform plan` checks
the Terraform resources and source hashes, and does not inspect remote host
configuration managed by provisioners. `check` returns 0 for convergence, 2 for
drift, and 1 for errors. `plan` uses Terraform's corresponding detailed exit codes.

For cleaned hosts:

```bash
python3 scripts/master-only-iac.py apply --reconcile-all
```

The private work directory must contain `native-bin.tar.gz`, built from the
verified `ipars` / `iparsd` pair on `uc-k8sp5`. Both extracted checksums are
verified against `native_binary_sha256` before the Agent starts. The playbook
saves existing node identities as root-owned 0600 files in the bootstrap host's
0700 `/var/lib/heteronetwork-iac/identities/` vault and each master's root backup
directory. Restoring those identities preserves the registered 10.250.0.4–6
addresses. Protect this vault separately from the host OS being cleaned.

Terraform state uses the existing Kubernetes Secret backend in `argocd`, with
Lease locking. State, kubeconfig, SSH private keys, binary archives and identity
contents are excluded from Git. The public host inventory pins SSH host keys.
Update `nodes.json` or `standard-nodes.json` for an authorized host-key rotation and rerender GitOps nodes
with `python3 deploy/terraform/master-only/render.py`.

The production Git source is
`git://10.250.0.2:19419/heteronetwork-infrastructure.git`, branch
`codex/master-only-iac-20260915`. It contains the public upstream history plus
the infrastructure files. The publication script uses a temporary Git index
and includes only this change's explicit file list. Git is served only over
the existing encrypted HeteroNetwork, with remote pushes disabled. Rebuild
`infrastructure.bundle` with the publication script and reapply Terraform to
publish changes. Back up the Git directory on `uc-k8sp5` with its infrastructure
state. Moving to another branch requires setting `git_revision`, building its
bundle with `publish-master-only.py --branch BRANCH --work-dir DIRECTORY`, and
reapplying Terraform. Moving to GitHub after write authentication is restored
requires publishing the commit and setting `git_repository_url`; the AppProject
allowlist must include the selected source. Existing nonessential GitOps
DaemonSet sources also declare the dedicated-master exclusion directly.

## Verify

```bash
KUBECONFIG="$TF_VAR_kubeconfig_path" python3 scripts/verify-master-only.py --exercise-admission
KUBECONFIG="$TF_VAR_kubeconfig_path" python3 scripts/verify-standard-node.py --exercise-storage
KUBECONFIG="$TF_VAR_kubeconfig_path" python3 scripts/accept-registered-nodes.py --work-dir "$TF_VAR_work_dir" --check
python3 scripts/master-only-iac.py check
python3 scripts/master-only-iac.py plan
```

The verifier checks Node Ready and isolation, exactly six essential Ready Pods
per master, disabled Longhorn scheduling, Argo synchronization, actual Pod and
binding rejection, DaemonSet mutation with existing OR affinity, essential
network toleration restoration, and Node mutation preserving controller taints.
It creates a temporary test namespace and removes it afterward. Browser owner
login E2E and unrelated platform workload readiness are separate checks.
The automatic acceptance gate requires Node.js, Playwright and an installed
Chromium browser on the operator. It creates and closes its own pinned SSH
SOCKS connection to `uc-k8sp5` for overlay browser traffic; the operator
kubeconfig must already reach Kubernetes. Browser gateway selection changes
the request destination while retaining the canonical Host and Origin. Every
response is fetched from the actual gateway, without fixture responses.
The standard-node verifier also checks normal scheduler placement, DNS and
Service traffic, cross-node Pod traffic, and Kubernetes Service TLS. With
`--exercise-storage`, it provisions a 1 GiB Longhorn PVC on the standard node,
writes and syncs data, recreates the consumer Pod, and verifies the persisted
contents before deleting the temporary namespace and test volume.

References: [Terraform provisioners](https://developer.hashicorp.com/terraform/language/provisioners),
[Kubernetes state backend](https://developer.hashicorp.com/terraform/language/backend/kubernetes),
[Argo CD server-side apply](https://argo-cd.readthedocs.io/en/stable/user-guide/sync-options/),
[Kubernetes admission mutation](https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/).
