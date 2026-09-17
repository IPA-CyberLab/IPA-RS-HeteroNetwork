# uc-k8sp1〜3 の削除（2026-09-15）

ユーザーの指示で次の3台を削除した。3号機の実機名は `uc-k8s3p`。

| 実機名 | HeteroNetwork IP | 削除後の使用メモリ |
| --- | --- | --- |
| uc-k8sp1 | 10.250.0.4 | 581 MiB |
| uc-k8sp2 | 10.250.0.5 | 504 MiB |
| uc-k8s3p | 10.250.0.6 | 508 MiB |

- 認証済みの管理APIで3台のHeteroNetwork登録を削除。関連パス、ヘルス、NAT、ハートビート情報も削除された。残存する対象サービス登録・Keycloak候補リースも削除。
- Kubernetesの3台のNodeと対応するetcdメンバーを削除。残るmasterは `ichikawap1` と `uc-k8sp5`。既存の `mizuame-nucboxg5` は対象外。
- PostgreSQL用DCSから対象2メンバーを削除。既存データを保持したまま `db-a` の1メンバー構成になった。PostgreSQLは `db-a` がLeader、`db-b` がSync Standby、同じタイムライン396でレプリケーション遅延0を確認。
- 対象3台のHeteroNetworkサービス・自動実行タイマー・kubeletを停止、無効化。標準の `kubeadm reset` で稼働用Kubernetes認証情報とstatic Pod設定を削除。containerdも停止、無効化した。
- 対象3台にはサービス再起動を防ぐ `99-retired.conf` を配置。再参加にはこれらの条件を解除して改めて初期化する必要がある。
- 残るmasterのAPIサーバーから対象etcd接続先を削除した。両masterのAgentを再開し、Kubernetes APIの `/readyz` を確認。

対象ホストのPodやクラスタサービスは稼働していない。PVの実データ、OS、SSH/Tailscale設定は消去していない。イメージキャッシュの一括消去やOS再インストールは実施していない。

DB用DCSの障害時自動切替を維持する構成変更は今回の削除には含めていない。3メンバー以上を要求するDBトポロジーautopilotは残る2台で停止、無効化した。DB用DCSは1台構成のため、従来のDCS冗長性はない。Kubernetes用etcdは2台構成。

各ホストの秘密情報を含む退避・実行記録はroot専用の `/var/backups/heteronetwork/20260915T0820Z-retire-uc-k8sp1-3/` に保存。共有リポジトリに認証情報を保存していない。

今回の検証は削除対象の不在、etcdメンバー一覧、対象サービス停止、Kubernetes設定削除、残るAPI・DBの稼働確認。ブラウザE2E一式の成功を示すものではない。
