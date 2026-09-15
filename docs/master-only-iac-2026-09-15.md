# master専用3台のIaC化・実適用記録

2026-09-15 UTC。既存の物理ホスト `uc-k8sp1`（10.250.0.4）、`uc-k8sp2`（10.250.0.5）、
`uc-k8s3p`（10.250.0.6）のHeteroNetwork・Kubernetes設定と配置制限をコード管理へ移行した。
3号機の実機名は `uc-k8s3p`。

## 管理構成

- [Terraformモジュール](../deploy/terraform/master-only/README.md) が3台のAnsible構成、内部Git配信、
  Argo CDの `control-plane-only` Application、既存5 Applicationの同期元とAppProjectを管理する。
- [ホスト構成](../deploy/terraform/master-only/ansible/masters.yaml) がホスト鍵を固定した接続先へSSHし、
  固定チェックサムのAgentバイナリ、専用kubeadm profile、最小サービス、kubeletの隔離・容量設定を適用する。
  参加済みホストのKubernetes初期化・再参加はスキップする。
- [GitOps構成](../deploy/gitops/control-plane-only/kustomization.yaml) がNodeラベル、cordon、
  Longhornの配置禁止、Pod・Bindingの拒否、DaemonSetとNodeの変異ポリシーを管理する。
  Argo CDの自動同期・自己修復を有効にした。
- Kubernetes管理対象を削除しないよう、Terraformには `prevent_destroy`、
  GitOpsのNodeには `Prune=false,Delete=false` を設定した。
- Terraform stateは既存クラスタの `argocd` namespace内のSecret backendを利用し、Leaseでロックする。
  SSH秘密鍵、sudoパスワード、ノードidentityの内容をstateやGitへ保存しない。

内部Gitの同期元は `git://10.250.0.2:19419/heteronetwork-infrastructure.git`、
branchは `codex/master-only-iac-20260915`。
GitHubへの書き込みが403で拒否されたため、Terraformで既存の `uc-k8sp5` に配信を用意した。
HeteroNetworkのアドレスだけで待ち受け、専用アカウントと読み取り専用systemd環境を使い、
リモートpushを提供しない。master専用3台にはGitサービスを配置していない。

既存DaemonSetを含む5つのGitOps Applicationも、このbranchへ同期元を切り替えた。
Longhorn等のHelm・operator管理DaemonSetにはAdmissionで同じ除外条件を維持する。
Kubernetes controllerが付けるtaintを保持しながら必要な3 taintを強制し、
Argo CDとcontrollerがtaint配列の所有権を奪い合うことを避けた。
Kubernetesが補うMutatingAdmissionPolicyの既定値もマニフェストに明示して同期差分を解消した。

## 実機で確認した結果

- Terraformから3台の設定を適用し、Ansibleの失敗・接続失敗は0件。
- ホストと内部GitのAnsible checkは変更0件。
- `control-plane-only` は `Synced / Healthy`、管理対象16リソースすべて `Synced`。
- 3台とも `Ready / SchedulingDisabled / control-plane`。各台のPodはetcd、API server、
  controller manager、scheduler、Flannel、kube-proxyの6個だけで、すべてReady。
  アプリケーション・ストレージ用Podは0個。Longhornの `allowScheduling=false` を確認。
- 既存の非必須DaemonSet 13個が3台を除外する条件を保持している。
- 3台それぞれへの通常Podの直接 `nodeName` 指定とBindingを実際にAPIへ送信し、6件すべて拒否。
  全taintを許容するPodでも配置できない。検証用namespaceは削除済み。
- DaemonSetの新規作成時の除外条件付与、既存のOR条件・matchFieldsの保持をserver dry-runで検証。
- Nodeのcordon・専用taintを外す更新はAdmissionが復元し、controllerの他のtaintを保持することを検証。
- Flannelとkube-proxyの専用tolerationを外す更新でも、必要な2つの許容設定が復元されることを検証。
- uc-k8sp1の `/etc/default/kubelet` だけを最大Pod数16から17へ書き換え、
  [IaCの実行スクリプト](../scripts/master-only-iac.py) がuc-k8sp1だけを変更対象として検出。
  Terraform経由で元のファイル内容へ復元し、kubeletの稼働を確認した。
  テスト変更時にはサービスを再起動せず、稼働中の容量を変えていない。
- Admissionの拒否メッセージだけを変更したところ、Argo CDの自動操作が1.9秒で元に戻した。
  配置拒否の式は変更していない。
- ホスト設定の復元後も、Kubernetes用etcdの全5 endpointでproposalの正常コミットを確認した。
- 変更復元後のIaC実行スクリプトによる最終planは終了コード0、ホスト・Git配信の差分0、
  Terraformの `No changes` を確認。stateにsudoパスワード・SSH秘密鍵が含まれないことも確認した。
- `terraform fmt -check`、`terraform validate`、Ansible syntax check、Python構文確認、
  GitOpsのAPI server dry-run、`git diff --check` が成功。

クラスタ・配置の確認時revisionは `0f8587fff2c83869d633ea939767370caa8b7bbe`。
その後の検証記録の公開でも、同じbranchを使う。
詳細なJSON結果・操作ログ・stateバックアップはこの作業環境の
root専用 `/root/.local/state/heteronetwork-master-only/` に保持した。
ホストidentityは `uc-k8sp5` のroot専用 `/var/lib/heteronetwork-iac/identities/` に保存し、
OSクリーンアップ後も同じ登録・IPを復元するための材料とした。
既存の実機への適用と変更復元を検証しており、OS全消去からの復旧を今回再試行してはいない。

## この作業環境からの再実行

公開されていない秘密材料は既存のSSH鍵とroot専用work directoryを使う。
この作業環境のkubeconfigはSSH経由でAPIへ接続するため、別のターミナルで次を起動する。

```bash
ssh -N -i /workspace/IPA-RS-HeteroNetwork/.key \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/root/.local/state/heteronetwork-master-only/known_hosts \
  -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:26443:10.250.0.2:6443 mizuame@163.220.236.45
```

```bash
cd /workspace/IPA-RS-HeteroNetwork
export TF_VAR_kubeconfig_path=/root/.local/state/heteronetwork-master-only/kubeconfig
export TF_VAR_ssh_private_key_path=/workspace/IPA-RS-HeteroNetwork/.key
export TF_VAR_work_dir=/root/.local/state/heteronetwork-master-only
python3 scripts/master-only-iac.py plan
python3 scripts/master-only-iac.py apply
```

コードを変更した際は、先に `python3 scripts/publish-master-only.py --work-dir "$TF_VAR_work_dir"`
でbundleを作り、Terraformから公開してArgo CDに同期させる。
実行スクリプトはSSHでホスト・Git配信の差分を検出して、対象リソースだけを再構成する。
ホスト構成の変更復元はこのスクリプトの実行時に行い、Argo CDが管理するクラスタ設定は継続的に自己修復する。
別の実行環境では到達可能なoperator kubeconfigを指定する。

この記録は3台のmaster専用IaC構成の検証結果。
他のApplicationには既存の `Progressing` があり、管理コンソールの所有者ログインや
ブラウザE2E一式の成功を示すものではない。
