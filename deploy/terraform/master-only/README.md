# Dedicated master infrastructure

This module manages the existing `uc-k8sp1`, `uc-k8sp2`, and `uc-k8s3p` hosts.
Terraform runs the versioned Ansible configuration, publishes a read-only
internal Git source on `uc-k8sp5`, imports the five existing
HeteroNetwork GitOps Application sources, and creates the `control-plane-only`
Argo CD Application. The physical machines and their operating systems already
exist; this module manages their HeteroNetwork and Kubernetes configuration.

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

The entry point prompts for sudo credentials, checks the master hosts and the
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
Update `nodes.json` for an authorized host-key rotation and rerender GitOps nodes
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
python3 scripts/master-only-iac.py check
python3 scripts/master-only-iac.py plan
```

The verifier checks Node Ready and isolation, exactly six essential Ready Pods
per master, disabled Longhorn scheduling, Argo synchronization, actual Pod and
binding rejection, DaemonSet mutation with existing OR affinity, essential
network toleration restoration, and Node mutation preserving controller taints.
It creates a temporary test namespace and removes it afterward. Browser owner
login E2E and unrelated platform workload readiness are separate checks.

References: [Terraform provisioners](https://developer.hashicorp.com/terraform/language/provisioners),
[Kubernetes state backend](https://developer.hashicorp.com/terraform/language/backend/kubernetes),
[Argo CD server-side apply](https://argo-cd.readthedocs.io/en/stable/user-guide/sync-options/),
[Kubernetes admission mutation](https://kubernetes.io/docs/reference/access-authn-authz/mutating-admission-policy/).
