# uc-k8sp1〜3 の master 専用再セットアップ（2026-09-15）

ユーザーによるクリーンアップ後、次の3台をHeteroNetworkへ再登録し、既存Kubernetesクラスタへcontrol-planeとして再参加させた。3号機の実機名は `uc-k8s3p`。

| 実機名 | HeteroNetwork IP | Kubernetes | 通常Podの配置 | 必須Pod | 使用メモリの目安 |
| --- | --- | --- | --- | --- | --- |
| uc-k8sp1 | 10.250.0.4 | Ready / control-plane | 禁止 | 6個、すべてReady | 1,413 MiB |
| uc-k8sp2 | 10.250.0.5 | Ready / control-plane | 禁止 | 6個、すべてReady | 1,325 MiB |
| uc-k8s3p | 10.250.0.6 | Ready / control-plane | 禁止 | 6個、すべてReady | 1,340 MiB |

メモリは2026-09-15 10:06 UTC時点の `MemTotal - MemAvailable`。各ホストは約3.7 GiBで、約2.3〜2.4 GiBが利用可能。kubelet / kubeadmはv1.36.4、control-planeのコンテナは既存クラスタに合わせたv1.36.3、containerdは2.2.1。

## 配置禁止の設定

3台はcordon済み（`SchedulingDisabled`）で、次のtaintを維持する。

```text
node-role.kubernetes.io/control-plane:NoSchedule
heteronetwork.io/control-plane-only=true:NoSchedule
heteronetwork.io/control-plane-only=true:NoExecute
```

`heteronetwork.io/control-plane-only=true` ラベル、公開Ingressを無効にするラベル・annotation、外部ロードバランサーから除外する標準ラベルも設定した。標準のロードバランサー除外ラベルはkubeadmが空文字の値で設定しており、キーの存在を検証している。

既存の13個の非必須DaemonSetには、対象3台のhostnameを除外する必須nodeAffinityを追加した。Longhornの対象Nodeは `spec.allowScheduling=false`。アプリケーション、Longhorn、CSI、Ingress、HeteroNetworkサービス用Podは対象3台に存在しない。

[control-plane-only-policy.yaml](../deploy/kubernetes/control-plane-only-policy.yaml) の2つのValidatingAdmissionPolicyとbindingを適用した。通常Podの `spec.nodeName` による直接配置と `pods/binding` による配置の両方を拒否する。例外は、kubeletが作成するcontrol-planeのmirror Podと、必要なFlannel / kube-proxyのみ。mirror Podはノード自身の認証も要求する。

各ホストで動く6個のPod / コンテナは次のとおり。

- etcd
- kube-apiserver
- kube-controller-manager
- kube-scheduler
- kube-flannel
- kube-proxy

masterとして必要な上記コンポーネントは稼働する。アプリケーションとストレージ用Podは0個。

## 永続設定とHeteroNetwork

[kubeadm-ha-node.sh](../scripts/kubeadm-ha-node.sh) に `control-plane-only` profileを追加し、対象3台へ配置した。`/etc/heteronetwork/kubernetes/node.env` にprofileと最大Pod数16を保存し、`/etc/default/kubelet` に専用ラベルと登録taintを保存した。`finalize` のtaint解除対象から専用ノードを除外する変更も含む。既存クラスタへの参加では `finalize` による全ノード設定変更を実行していない。

HeteroNetworkは既存と同じ0.1.14（392145e）のバイナリを使用し、ネットワーク用Agent、プライベートDNS、Kubernetes APIのローカルプロキシと経路設定だけを配置した。公開サービスの自動昇格は無効。PostgreSQL / DCS、Keycloak、Relay、Signal、STUNサーバー、公開Ingress、HeteroNetwork control-planeは対象3台にインストールしていない。

HeteroNetworkプロトコルの登録roleは `worker` で、Kubernetesの役割は `control-plane`。登録には `kubernetes-control-plane`、既存のHA cohort `kubernetes-ha-545a7a1911f9580a`、`kubernetes-control-plane-only` のタグを使用した。

新しいidentity / WireGuard鍵を各ホストで生成した。通常のIP割当では既存Kubernetesノードの10.250.0.3と重複するため、新しい公開鍵とホスト名を確認して、既存登録のバックアップを取得した上で管理側DBのトランザクションにより元の10.250.0.4〜6を予約した。その後、管理側で発行した署名付き・1回限りのトークンとホストの鍵による認証済み再参加を完了した。既存の他ノードの登録と所有者認証設定は変更していない。

## 実機での検証

- 3台ともkubeadm join成功、Node Ready、control-plane role、cordon、必要なtaintを確認。
- 各3台のPodが必須6個だけで、すべてRunning / Ready。CRIの稼働コンテナも同じ6個のみ。
- 各3台のKubernetes API `/readyz` は `ok`。
- Kubernetes用etcdは既存2台と追加3台の計5 voting members。全5 endpointでproposalの正常なコミットを確認。
- 各3台で通常Podの直接指定と明示的bindingを実際にAPIへ送信し、6件すべて拒否されることを確認。検証用namespaceは削除済み。
- Admission policyのCEL型警告は0件。DaemonSetの除外設定、Longhornの配置禁止、専用profileと自動昇格無効の永続設定を検証。
- `bash -n`、既存のhelper self-test、`git diff --check` が成功。

クラスタ側の検証結果は `uc-k8sp5` のroot専用 `/var/backups/heteronetwork/20260915T0942Z-master-only/master-only-verification.json`、各ホストの構成・コンテナ確認は同じディレクトリの `native-master-only-verification.json` に保存した。参加ログと変更前DaemonSet設定も同ディレクトリに保持している。認証情報は共有リポジトリへ保存していない。

これは今回のmaster専用設定の実機検証記録。管理コンソールの所有者ログインやブラウザE2E一式の成功を示すものではない。既存の `mizuame-nucboxg5` のNotReady、PostgreSQL用DCSの構成は今回の対象外。

その後、ホスト設定をTerraform＋Ansible、配置制限をArgo CD管理へ移行した。
現在の構成・実適用・変更復元の結果は [master-only-iac-2026-09-15.md](master-only-iac-2026-09-15.md) を参照。
