# uc-k8sp4 の標準ノード登録

2026-09-15 UTC。`100.111.33.52` の `uc-k8sp4` を、通常Pod・ストレージ・公開サービスを
利用できるノードとして既存HeteroNetworkとKubernetesへ登録した。

| 項目 | 登録値 |
| --- | --- |
| ホスト | uc-k8sp4 / mizuame |
| Tailscale | 100.111.33.52 |
| SSH・公開アドレス | 163.220.236.54 |
| HeteroNetwork | 10.250.0.11 |
| Node ID | node-30c455638eba4281a25bb8ec2c8b742b |
| Kubernetes | v1.36.4 / control-plane / 通常Pod配置可 |
| OS・メモリ | Ubuntu 24.04 / 約32GiB |
| kubelet上限 | 110 Pods |

## IaC

[Terraformモジュール](../deploy/terraform/master-only/README.md) の
`terraform_data.standard_host_configuration["uc-k8sp4"]` が
[標準ホスト構成](../deploy/terraform/master-only/ansible/standard.yaml) を適用する。
公開インベントリは [standard-nodes.json](../deploy/terraform/master-only/standard-nodes.json)。
SSH接続先のホスト鍵は、認証済みTailscale側ホストから確認して固定した。
ホームディレクトリがroot所有だったため、Ansibleの作業先は `/tmp` の専用ディレクトリを使う。

既存issuerから有効期間30分・1回限りの署名付き登録トークンを発行し、固定チェックサムの
Native 0.1.14（392145e）で登録した。issuer秘密鍵は既存issuer内だけで使用する。
登録identityは `uc-k8sp5` のroot専用復旧vaultへ保存する。
SSH秘密鍵、sudoパスワード、identity、DB接続情報はGitとTerraform stateへ保存しない。

旧Kubernetes設定は異なるCAを使用し、稼働コンテナは0個だった。
`/var/backups/heteronetwork/iac-standard/previous-kubernetes.tar.gz` へ保存してからresetし、
短命のcontrol-plane参加資格情報で既存クラスタへjoinした。
標準profileのbootstrap実行元を `/opt/heteronetwork/iac/scripts/` に分け、
実行時ヘルパーのインストール先と同一になる問題を避けた。
Kubernetes API接続には、IaCが指定する既存5台とこのノードの6 endpointを使う。
3台限定cohortを推定する旧backend autopilotはこのノードでは無効にする。

Terraformが作成する `standard-nodes` Argo CD Application は
[標準GitOps構成](../deploy/gitops/standard-nodes/kustomization.yaml) を自動同期・自己修復する。
Nodeのcordon解除、通常Podを許可するラベル、公開ingress、Longhornの配置許可を管理する。
Admissionがcontrol-planeの `NoSchedule` と専用master taintを取り除き、その他のcontroller taintを保持する。
元の3台は別の `control-plane-only` Application が管理する。
Git同期元は内部の `git://10.250.0.2:19419/heteronetwork-infrastructure.git`、
branchは `codex/master-only-iac-20260915`。

## Nativeサービスとストレージ

署名を検証した公開サービスbootstrapを実行し、Agent、Control Plane、Signal、STUN、Relay、
公開Gateway、PostgreSQLクライアント用プロキシ、Keycloak edge proxyを稼働させた。
公開IPのHTTPS証明書はGatewayが取得する。

既存DB bundleの配布プロセスがTailscale側で待ち受けていたため、SSHで保護された
クライアント用bundleをIaCから取得し、既存DBノードのVPN endpointへ接続するプロキシを構成した。
配布するbundleはCA証明書とアプリケーション用資格情報を含み、DB CA秘密鍵を含まない。
プロキシ設定の差分は専用ヘルパーの読み取り専用検査で検出し、Terraform経由で復元する。
Keycloakのローカルhealth pathは、既存ノードと同じ `/realms/heterocloud/.well-known/openid-configuration` を使う。

Longhornは `/var/lib/longhorn` の `iac-default-disk` をGitOpsで登録し、OS用に64GiBを予約する。
このホストはNVMeとLVMのみで、`multipath -ll` は空だった。
[Longhorn公式のmultipath対処](https://longhorn.io/kb/troubleshooting-volume-with-multipath/)に従い、
未使用のmultipath service/socketを無効にした。`dm_crypt` をロードし、再起動後にもロードする設定を保存する。

## 検証

[標準ノード検証](../scripts/verify-standard-node.py) は実際に通常スケジューラーからPodを配置する。
uc-k8sp4とuc-k8sp5の両方から、DNS、Service経由HTTP、uc-k8sp4のPod IPへのHTTP、
クラスタCAで検証したKubernetes ServiceのTLS接続が成功した。テストnamespaceは削除した。
標準NodeのAdmissionは専用taintを除き、他のtaintを保持することをserver dry-runで検証した。

`--exercise-storage` 付きの実行では、`longhorn-syouyu-local` の1GiB PVCを作成し、
uc-k8sp4上の単一replicaへ書き込み・sync後、Podを再作成して同じ内容を読み出せた。
テストPod、PVC、namespaceは検証終了後に削除した。
最初のattach検証で、既存Longhorn管理Podの削除処理が残り、そのboundトークンが
401になってengine-imageの新ノード認識が更新されない問題を検出した。
該当する管理Podを作り直し、正常な管理ノードによる所有権引き継ぎと
uc-k8sp4のengine-image認識を確認してから、通信・ボリューム検証を再実行して成功した。
既存ボリュームやreplicaデータは削除していない。

元の3台は引き続きReady・SchedulingDisabledで、各台は6個の必須Ready Podだけだった。
アプリケーション・ストレージ用Podは0個。Kubernetes用etcdの全6 endpointで正常コミットを確認した。
このノードの公開HTTPS `/healthz` への証明書検証付き接続も成功した。
両ホストprofileと内部Git配布のAnsible差分検査はすべて0で、Terraformの
`plan -detailed-exitcode` は `No changes` / exit 0だった。

検証結果と操作ログはroot専用 `/root/.local/state/heteronetwork-master-only/` に保存する。
再実行方法は [既存IaC記録](master-only-iac-2026-09-15.md) とモジュールREADMEを参照する。
他のApplicationには既存の `Progressing` があり、この記録は全アプリケーションや所有者ログインの
ブラウザE2E一式の成功を示すものではない。
