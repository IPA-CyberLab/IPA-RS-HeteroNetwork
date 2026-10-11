# 2026-10-11 Coder / Whisper 障害

時刻はすべて UTC。状態: サービス復旧を確認、障害再現 E2E を検証中。

## 影響

- Coder と Whisper が断続的に HTTP 503 を返した。
- Coder の共有ディスク再接続中はコンテナの再作成が発生し、ワークスペースのエージェント接続も切れた。
- HyperEVM では、これとは別にメモリ上限到達による応答遅延があり、IDE が `Agent state is disconnected` を表示した。
- ホスト再起動の記録は確認していない。以下の「再作成」は Kubernetes Pod または共有ストレージのプロセスに関するもの。

## 確認できた原因と経路

1. Kubernetes API / etcd のリクエストが遅延し、kubelet のノード Lease 更新がタイムアウトした。uc-k8sp5 では 16:08:26–16:08:56 に更新失敗が連続した。API ログにも `etcdserver: request timed out` がある。
2. 全 6 台の controller-manager が `node-monitor-grace-period=20s` だった。短い更新遅延で生存しているストレージノードが `NodeStatusUnknown` になった。16:08:47 に uc-k8sp1 / p4 / p5 が NotReady となり、16:08:55–57 に Ready へ戻った。
3. Longhorn はその判定を受け、RWX の share-manager を復旧した。NFS の再接続と remount 要求が発生し、Longhorn 自身がアプリケーション Pod を削除した。Coder 親 Pod の削除は 16:09:16 の `handlePodDeletionIfVolumeRequestRemount` ログで確認した。通常の 300 秒の Pod toleration では、この別経路の削除を防げなかった。
4. Coder は共有ディスクと PostgreSQL への接続に依存する。先行する 15:21 の DB Pod 再作成後、15:26:24 に親プロセスが `pubsub Watchdog timed out` で終了している。親のこの終了理由は OOM ではない。

etcd には slow fdatasync と heartbeat 遅延の記録がある。さらに、6 台中 4 台では heartbeat / election timeout が既定の 100 / 1000 ms、2 台では 500 / 5000 ms と不統一だった。4 台の CPU / メモリ予約も 100m / 100Mi に残っていた。全メンバーのタイミングは統一が必要であり、この不整合を修正した（[etcd 公式のタイミング設定](https://etcd.io/docs/v3.6/tuning/#time-parameters)）。一方、物理ディスクだけをすべての API 遅延の原因とは断定していない。ネットワーク・I/O・負荷の切り分けは残る。20 秒の設定が短い管理通信の遅延をストレージとアプリケーションの停止へ拡大した点は、ログで確認できている。

参考: [Kubernetes controller-manager の node-monitor-grace-period](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-controller-manager/) と [Longhorn の自動 Pod 復旧](https://longhorn.io/docs/1.12.0/high-availability/recover-volume/)。ノード監視猶予は複数回の更新と接続回復を許容する必要がある。

## HyperEVM の別の障害

- 旧 8 GiB コンテナは 10:04:06 に `OOMKilled`。cgroup は `oom=6`, `oom_kill=2` を記録していた。
- 32 GiB で復旧後、16:26 頃に再度エージェントが切断した。コンテナ内の Python プロセスの RSS は約 39 GiB、cgroup の使用量は 32 GiB 上限に張り付いていた。この時点では `oom_kill=0` で、メモリ回収による応答遅延を観測した。
- Kubernetes の resize API で 48 GiB に拡張すると再接続した。Pod UID `5623f4d6-6100-48ba-802b-431975eb71a3` と再起動回数 0 を維持した。
- Flash API のサービス設定、Deployment、ReplicaSet、Coder Terraform テンプレートの workspace memory override を 48 GiB に揃えた。同期中だけ対象 Deployment のロールアウトを止め、既存 ReplicaSet に同じテンプレートを反映後、再開した。親 Coder や他のワークスペースの再起動は行っていない。
- 容量増加は任意のメモリ消費を無制限に許容するものではない。上限まで使い切る処理がさらに増えれば、再び負荷制限の対象になる。

## 対応

- ノード監視猶予を 20 秒から 60 秒へ変更。Terraform の `terraform_data.node_health_policy` から、6 台を順番に更新し、新しい引数と Ready を確認してから次へ進む。
- kubeadm のクラスタ設定と初期化スクリプトにも保存し、参加・更新時に 20 秒へ戻らないようにした。
- 設定変更では kubelet / containerd の再起動を行わない。元の controller-manager manifest は監視ディレクトリ外にバックアップする。
- Envoy controller の最低 CPU / メモリ確保と leader election の猶予を修正した。この変更だけでは再発したため、これをもって復旧とは判定しなかった。
- 管理対象 5 台の API server の etcd client 接続先を、到達性確認済みの 3 台へ揃えた。uc-k8sp4 は既存のローカル etcd 接続を維持した。etcd の 6 voter 構成は変更していない。
- `terraform_data.etcd_policy` で全 6 台の heartbeat / election timeout を 500 / 5000 ms、予約リソースを 500m / 512Mi に揃えた。各台の変更前後に全メンバーの応答とリーダー合意を確認し、変更対象がリーダーなら健全な既存メンバーへ移譲する。kubeadm-config にも保存し、manifest は監視ディレクトリ外で作成後に原子的に置換する。
- ユーザー指定の exec 専用サービスには停止・削除・リサイズ操作を行っていない。ただし 16:09 の Longhorn 自動復旧で Pod が再作成されたため、障害全体を通して UID が不変だったとは報告しない。

## 経過

| 時刻 | 事実 |
| --- | --- |
| 10:04:06 | 旧 HyperEVM がメモリ上限で OOMKilled |
| 14:18 | Coder 親などの Pod 再作成を確認 |
| 15:17:59 | HyperEVM を 32 GiB で復旧、既存の永続ホームを維持 |
| 15:21–15:26 | DB 再作成と Coder pubsub watchdog 終了 |
| 16:06–16:07 | VPN＋ブラウザ E2E がタイムアウトで失敗。成功扱いにしていない |
| 16:08:47 | 3 ノードが一時 NotReady |
| 16:09 | Longhorn RWX 復旧がアプリケーション Pod 再作成へ波及 |
| 16:15 | Coder / Whisper のコンテナが Ready に復帰 |
| 16:19 | Whisper `/healthz` が 200、`cuda:0` / `model_loaded=true` |
| 16:26 | HyperEVM の 32 GiB 上限到達でエージェントが切断 |
| 16:29 頃 | 全 6 controller-manager の 60 秒設定と Ready を確認 |
| 16:32 | HyperEVM を稼働中に 48 GiB へ拡張、再接続 |
| 16:35 | Coder / Whisper の連続 HTTP 確認 12/12 が 200 |
| 16:38–16:43 | Coder / Whisper の 5 分間監視 60/60 が 200 |
| 16:54 | etcd の既存 6 メンバーすべてで HA 設定と正常応答を確認 |
| 16:56 | 全 9 アプリ Pod の UID を維持。Chromium で HyperEVM の IDE 表示を再確認（200、4.23 秒） |
| 17:42–17:43 | 復旧後の 9 Pod は同じ UID / 再起動 0 / Ready。Coder・Whisper は 200。HyperEVM の最終切断時刻は 16:26 のまま、接続更新を継続 |

## 再発防止 E2E

`.github/workflows/storage-heartbeat-e2e.yml` が GitHub runner 内に専用の kind コントロールプレーンと 2 台の Ubuntu KVM ワーカーを作る。本番の kubeconfig、VPN、トークンは渡さない。停止対象はそのジョブが作ったノード名・kind ラベル・VM の識別値で固定する。

実際の Kubernetes 1.36.4、宣言済みバージョンの Longhorn と Envoy Gateway、RWX PVC を使う HTTP アプリケーションを起動する。各 HTTP リクエストで保存データの読み出し・書き込み・fsync を行う。

1. **修正後:** kubelet だけを 35 秒停止してハートビートを欠落させる。HTTP 200、データ一致、Pod UID、再起動回数、share-manager UID が維持されることを要求する。
2. **旧設定の再現:** 20 秒へ戻して同じ停止を行う。NotReady と Envoy の実際の 503、share-manager の再作成を要求する。障害が再現しなければテストは失敗する。
3. **継続する故障:** 修正後の猶予より長く停止する。故障検知と 503 を確認し、復帰後に手動 Pod 削除なしで同じ PVC / データへ戻ることを要求する。

初期の Docker ワーカー構成では、テスト環境の iSCSI netlink 通信が失敗し、共有ディスクの準備に失敗した。3 回の試行は合格としていない。iSCSI に独立したカーネルを与えるため、ワーカーを KVM VM に変更した。続く VM 準備では名前解決、CRI の起動待ち、Docker 専用 cgroup 設定の引き継ぎを修正した。これらの失敗・中止も合格数に含めず、各実行の結論を JSON に残す。

17:44 時点では [再実行 38160730945](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/38160730945) が環境構築中であり、障害再現テストの合格は未確認。通常の VPN＋Chromium E2E は [38157484921](https://github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/actions/runs/38157484921) で成功した。

VM 参加のタイムアウト例外に、この CI だけの一時 bootstrap token が出た試行のログは GitHub から削除した。以後はタイムアウト例外から引数を除外し、失敗ログのマスクと回帰テストを追加した。本番の認証情報を使うジョブではない。

この E2E はハートビート欠落から RWX / HTTP へ波及する障害を扱う。物理ディスクの遅延や HyperEVM の実アプリケーションの無制限メモリ消費を再現したものとは扱わない。実行結果と証跡は隣接 JSON に記録する。
