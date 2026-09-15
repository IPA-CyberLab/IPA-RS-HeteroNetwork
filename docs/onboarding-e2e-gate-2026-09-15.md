# コンソールのポート復旧と新規登録のE2E判定

2026-09-15 UTC。`http://console.heteronetwork.internal:9781/ui/` の再度の接続拒否を再現した。
直前のIaC再設定がAgentのoverlayコンソールのポートを指定していなかったため、
uc-k8sp1、uc-k8sp2、uc-k8s3p、uc-k8sp4は初期値80で待ち受け、9781は接続拒否だった。
DNSはクライアントが接続しているgateway自身のVPN IPを返すため、他のgatewayで
9781が開いているだけでは、この障害を検出できなかった。

## 永続設定

[Terraformモジュール](../deploy/terraform/master-only/README.md) の
`terraform_data.console_configuration` が
[専用Ansible構成](../deploy/terraform/master-only/ansible/console/configure.yaml) を全6台へ適用する。
既存のポート設定を明示したsystemd drop-inでAgentの待ち受けを9781に固定し、
VPNアドレスの80はループバックAgentの9780へHAProxyで転送する。
Hostをcanonicalコンソール名に制限し、既存AgentのHost/Origin検査に合わせて転送する。
Agentからプロキシを `Wants` するため、Agent再起動後も80が戻る。
内部Git配布もAgentから `Wants` し、Agent再起動後に配布daemonが停止したままになることを防ぐ。
マスター専用構成は、このAgent用互換プロキシを停止対象から除外する。
元の3台への通常Pod・ストレージPodの配置は禁止したままである。

## 新規登録のaccept条件

`terraform_data.onboarding_acceptance` がホスト構成、コンソール構成、Git配布、Argo同期後に
[acceptance判定](../scripts/accept-registered-nodes.py) を必ず実行する。
ホストの作り直し、コンソール構成変更、検証コード変更、Git配布revision変更で再実行する。
検証にはNative署名登録とKubernetes参加が必要なので、それらを先に完了させる。
標準ノードは初回Kubernetes登録時から `heteronetwork.io/onboarding=pending:NoSchedule` を持ち、
検証中に通常スケジューラーからの通常Podの新規配置を止める。検証Podにはこのtaintの明示的な許容を追加する。
再検証時は既存Podを終了させない。専用マスターは既存の恒久的な隔離を保持する。

次の実検証が、配布されたcandidate Git revisionで全部通ることを要求する。

- [ブラウザ検証](../scripts/verify-console-gateways.mjs)：全gatewayの80と9781の
  正規URL、UIと設定のHTTP 200、JavaScriptエラーなし。9781から実際にDevice Loginを
  開き、公開Keycloakのユーザー名・パスワードフォームと送信先を確認する。
- [マスター検証](../scripts/verify-master-only.py)：Ready、各台6個の必須Ready Pod、
  通常Pod・bindingの拒否、DaemonSet隔離とネットワーク用tolerationの復元。
- [標準ノード検証](../scripts/verify-standard-node.py)：通常スケジューラーによる
  quarantine中の通常Pod配置拒否、検証Pod配置、DNS、Service HTTP、別ノードとのPod通信、CA検証付きKubernetes TLS、
  実Longhorn PVCへの書き込み・sync・Pod再作成後の読み出し。

成功後だけNode注釈 `heteronetwork.io/onboarding-status=accepted` と検証revision・日時を保存し、
標準ノードの専用quarantine taintを除去する。失敗時はTerraform applyが失敗し、
注釈を `failed` としてquarantineを保持する。
判定はIaC完了状態とKubernetesの配置許可を制御し、Native登録プロトコル自体を変更しない。
検証中のNode UID変更と古い成功ログによる誤acceptも拒否する。
root専用 `onboarding-acceptance.json` に実検証結果とNode UIDを保存する。
IaC wrapperの `check` / `plan` はこの証跡と実Node状態の不一致も検出する。

## 検証記録

全6台の80・9781の12 endpointは構成適用時にHTTP 200を確認した。
同じ12 endpointのChromium検証も成功し、全6台の9781から公開Keycloakの
ユーザー名・パスワードフォームを開けた。JavaScriptエラーは0件だった。
誤acceptを防ぐ失敗系テストでは、E2E失敗、検証中のNode再登録、古い成功ログ、
全検証成功後だけtaintを除去する順序を検証した。
実環境でも配置拒否の判定が失敗した際、apply失敗・`failed` 注釈・quarantine保持を確認した。
スケジューラーの集約された拒否文にはtaint名が含まれなかったため、Node上の実taint、
対象ノードを限定するselector、`Unschedulable` とtaint拒否の理由を照合する判定へ修正した。
失敗した検証のstderrと途中の証跡もroot専用ディレクトリへ残す。

ブラウザ検証は実gatewayへネットワーク要求を転送し、Host/Originと正規URLを保持する。
レスポンスのstatus・header・bodyにはfixtureや差し替えデータを使わない。
検証用namespace、PVC、一時SOCKS接続は終了時に片付ける。
保護された証跡は `/root/.local/state/heteronetwork-master-only/` に保存する。

この登録判定は管理者の資格情報を送信しない。管理者としてのログイン完了・reload・cookie復元は
既存の [authenticated console E2E](../scripts/heteronetwork-console-browser-e2e.mjs) が担当し、
登録検証のログイン開始成功をその成功として扱わない。
