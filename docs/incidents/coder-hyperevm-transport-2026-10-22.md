# HyperEVM code-server が upstream request timeout になる障害

発生日: 2026-10-22 UTC。対象は Coder の HyperEVM ワークスペース。

## 影響と確認した原因

認証済みのアプリ URL に対して HTTP 504 / `upstream request timeout` を
15.162 秒で再現した。一方、Coder 本体の `/healthz` は 200、VM 内の
code-server `/healthz` は約 1 ms で 200 を返していた。
VM は 8 GiB のまま稼働し、コンテナ再起動回数は 0 だった。
今回確認した障害は OOM や IDE プロセス終了ではなく、Coder 本体と
ワークスペースの間のデータ経路の故障だった。

エージェントには `too many DERP packets queued; dropping` が継続していた。
中継接続は約 31 時間維持されていたが、サーバーピアへの直接経路は無効だった。
VPC の許可にはワークスペースから本体への TCP 7080 と DB 用の TCP 5432
しかなく、Coder が内部で選ぶ WireGuard の UDP ポートは許可されていなかった。
そのため中継が詰まると、正常な VM 内の IDE にアクセスできなくなった。

DERP の送信停止を最初に発生させた上流内部の条件は特定していない。
管理 API の `connected` やアプリのローカルヘルスチェックだけでは、この故障を
検知できなかった。これらの表示だけを復旧判定に使ってはならない。

## 対応

`deploy/terraform/master-only/coder-transport.tf` に本体と HyperEVM の
双方向 UDP 許可を追加し、Terraform で本番へ適用した。両端とも
組織 ID・VPC ID・サービス ID の一致を必須とし、同一 namespace 内だけを対象にした。
外部公開、TCP ポートの追加、VPC 全体への許可は行っていない。

この許可は運用管理下にある 2 サービス専用である。ユーザー向け VPC の
「Flash が公開設定したポートだけを許可する」制約は変更していない。
別のワークスペースにも必要になった場合は、対象を明示して IaC を更新する。

調査中の 13:11 UTC に実行された停止ビルドは古いテンプレートのディスク設定で
HTTP 400 になり、Coder の最終ビルドが「停止失敗」になった。Flash の停止は
実行されず、VM 内の作業は継続していた。利用者が操作を止めたことを確認後、
既存の修正版テンプレートから起動ビルドを実行した。

このビルドが新しいエージェント認証情報を生成したため、Deployment を一時停止して
VM の作り直しを防ぎ、接続エージェントだけを別プロセスとして起動した。
既存の code-server、Codex、プロジェクトのデータは維持した。
初回に既存 filebrowser の DB ロックで起動警告が残ったため、filebrowser と
新しい接続エージェントのみを再起動し、エージェント `ready`、両アプリ `healthy` を確認した。

差分がエージェントトークンと世代ラベルだけであることを検証し、既存 ReplicaSet の
将来の Pod 用テンプレートを Deployment に同期して、一時停止を解除した。
Pod UID、コンテナ ID、再起動回数は変化していない。
この操作は一般的な更新手順ではなく、稼働中の作業を守るための単発の復旧操作である。
Kubernetes の [ReplicaSet 選択処理](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/controller/deployment/util/deployment_util.go)
がテンプレート比較時にハッシュラベルだけを除外することを確認したうえで実行した。

## 検証

- 修正後のエージェントは本体の Pod IP へ UDP で直接接続し、約 2 ms の応答を確認した。
- 認証済みアプリ URL は HTTP 200、確認した GET は 0.265～0.441 秒だった。
- 実ブラウザで `/root/projects/HyperEVM` を開き、README の選択・エディター描画・
  WebSocket の双方向通信・5 秒の安定接続を確認し、同じ操作を再読み込み後にも確認した。
- `scripts/coder_transport_live_e2e.py` で、実際に適用した 2 ポリシーを独立 namespace に
  複製し、実 gVisor Pod を 2 ワーカーへ配置して 9 項目を検証した。
  既定の拒否、双方向 UDP、TCP の拒否、別組織・別 VPC・別サービスの拒否、
  許可の復元、許可削除後の新規フローの拒否がすべて成功した。
  テスト環境は削除し、namespace が消えたことまで確認した。
- Terraform の再 plan は `No changes` だった。

最初の隔離通信テストではラベルを戻した直後の許可復元が間に合わなかった。
テストをノードへのポリシー反映を待つ方式に修正し、新規フローで再検証した。
拒否の判定は連続する 2 回の新規通信で確認する。

## 残る運用上の注意

現在の VM 内では接続エージェントを追加起動している。元の PID 1 とエージェントは
作業プロセスを維持するため残している。次回の計画停止・起動では Pod 単位で
通常のテンプレートから再作成し、この単発の復旧状態を解消すること。
現 Pod の環境変数は不変なので、現 Pod 内のコンテナだけを再起動する手順では
新しいエージェント認証情報が反映されない点に注意する。

中継停止そのものへの上流修正は未実施である。今回の対策は直接経路の確保と
接続の再確立であり、中継内部の不具合を修正したという意味ではない。
復旧判定には Coder 本体のログイン画面に加えて、実ワークスペースのファイル表示と
WebSocket 通信を含める。公開可能な測定結果は同名の JSON に保存する。

隔離通信テストの再実行例:

```sh
python3 scripts/coder_transport_live_e2e.py \
  --kubectl /path/to/kubectl --kubeconfig /private/path/to/kubeconfig \
  --image ghcr.io/ipa-cyberlab/ipa-rs-heterocloud-flash@sha256:713c6ec2807f241bb06be7dfc93f0542f50f1b485238e2082e0ecaec496d2671 \
  --nodes uc-k8sp4 uc-k8sp5 --report /private/path/to/report.json
```

イメージは両ワーカーにキャッシュ済みでなければ実行を拒否する。
テストは秘密情報・永続ディスクを使用せず、Pod あたりメモリー上限は 128 MiB。
本番のユーザー Pod や通信許可を停止・変更して故障を再現するものではない。
