# UDP / TCP / HTTPS / HTTPによる接続

登録済みのノードとWindows/macOSクライアントは、通常はUDPを使います。送信側のネットワークでUDPが遮断されていると、WireGuardの接続先を変えずにHTTPを使わないTCP、HTTPS、HTTPの順に切り替えます。素のTCPはWireGuardと同じ番号のTCPポートを標準とし、HTTPSは443、HTTPは80を使用します。TCP専用ポートが遮断されていてもHTTPS/HTTPへ進みます。HTTPSの公開ポートを登録時に変更した構成では、そのポートも広報されます。

## 通信と認証

公開ゲートウェイのCaddyと、ローカルのagent・relayを更新してください。コントロールプレーンが署名付きハートビートから公開入口を受け取り、ACLで見えるピアだけにURLを配布します。リレーの入口は選択時に署名付き照会で取得し、全ノードの全ピアマップに複製しません。

UDP応答がない最初のハンドシェイクは約3秒後、確立済み接続で応答が途絶えた場合は猶予を置いて切り替えます。素のTCPは `HNTCP1` の接続開始メッセージと長さ付きのバイナリフレームを使います。HTTPリクエスト、Upgrade、ロングポーリングは使いません。接続の認証はHTTP版と同じ登録済み鍵のMACで行い、データはWireGuardの暗号文です。

HTTPS/HTTPは通常のPOSTとGETのロングポーリングを使い、WebSocket UpgradeやHTTP/3を必要としません。明示的なHTTPプロキシも通常のHTTPクライアントの経路で使えます。リダイレクトには従いません。

HTTPでも転送するデータはWireGuardの暗号文です。公開ゲートウェイは、登録済みWireGuard鍵同士のX25519共有秘密から導出したMACで接続元を確認します。MACは接続元とゲートウェイのID・時刻・使い捨てnonce・診断値を含むリクエスト本文に結び付いています。共有の管理用／リレー登録用トークンを公開HTTPへ送りません。HTTPリレーの利用には、ACLとトークンポリシーで許可された組み合わせのセッショントークンが必要です。

キューは各方向64パケット、バッチは256 KiBまでです。セッションはアイドル60秒、最大1時間で更新し、再接続には最大30秒のバックオフがあります。TCP・HTTP中も約60秒ごとにUDPを再確認し、復旧すれば戻ります。UDP再確認では同じ暗号パケットをTCP/HTTPへ同時送信せず、WireGuardのリプレイ防御との競合を避けます。応答がなければ2秒後に利用中のTCP/HTTP経路へ送ります。

Windowsは既存VPNサービス内の付属プロセス、macOSは既存の特権ヘルパー内で転送します。鍵はWindowsの子プロセスへ標準入力の専用パイプで渡します。通信方式の変更によるVPNサービスの再インストールやUACの再要求はありません。

この機能は登録済み端末のデータ通信のフォールバックです。新規登録や管理認証のTLS要件、公開オーナーの既存のSTUNによる到達性判定は変更しません。

## TCPのポート設定

agentは標準で `--wireguard-listen-port` と同じ番号のTCPソケットを開きます。変更する場合は `--wireguard-tcp-listen 0.0.0.0:51821` を指定し、外側のポートが異なる場合は `--wireguard-tcp-public-port 51822` も指定してください。環境変数は `HETERONETWORK_AGENT_WIREGUARD_TCP_LISTEN` / `HETERONETWORK_AGENT_WIREGUARD_TCP_PUBLIC_PORT` です。リレーは `--tcp-listen` / `--tcp-public-port` を使用し、標準はUDPリレーと同じ番号です。

HTTPゲートウェイが使用する80・HTTPS待受ポートとは、別のTCPソケットにしてください。HTTPゲートウェイを無効にした専用構成なら素のTCPを80や443に設定できます。`--disable-tcp-tunnel` で素のTCPを無効化できます。待受ソケットを作成できない場合はTCPの入口を広報せず、既存のUDP・HTTP/HTTPSサービスを維持します。Docker ComposeのリレーはUDPと同じ番号のTCPポートも公開し、HelmのリレーService・コンテナポート・NetworkPolicyにもTCPを追加しています。ホストネットワークを使わないagent配置では、WireGuardの待受番号のTCPポートも外部から到達できるようにしてください。

TCPの接続先は署名付きハートビートとピアマップで自動配布されるため、利用端末へ個別のポート設定は不要です。

## URL・ホスト名とCNAME

公開入口にはIPアドレスに加え、DNS名を指定できます。たとえば `vpn.example.com` のCNAMEを `edge.provider.example` に向け、次のように登録します。CNAMEの値はホスト名だけです。方式・ポートは接続先URLで指定します。

```sh
iparsd agent \
  --public-transport-url https://vpn.example.com \
  --public-transport-url tcp://vpn.example.com:51820 \
  --public-transport-url udp://vpn.example.com:51820
```

既存の必須引数も併せて指定してください。管理画面のノード登録では「公開接続先URL（任意）」に1行1件で入力できます。APIは `public_transport_urls` 配列を受け付け、生成したインストーラーが設定を保存します。環境変数は `HETERONETWORK_AGENT_PUBLIC_TRANSPORT_URLS`、リレーは `HETERONETWORK_RELAY_PUBLIC_TRANSPORT_URLS` です。最大8件で、複数指定はカンマ区切りです。

A/AAAA・CNAMEの解決は接続する端末で行います。TCP・HTTP/HTTPSは接続時に再解決し、UDPは約30秒ごとに更新します。DNS障害時は直前のUDP接続先を保持します。複数の解決先やIPv4/IPv6がある場合、TCPは到達しないアドレスで待ち続けず別の候補を試します。公開入口の解決結果からプライベートIP・ループバック・リンクローカルなどを除外します。HTTPSは元のホスト名でHost/SNIと証明書を検証します。HTTPプロキシを明示設定した場合は、そのプロキシのDNS・接続経路も使用します。

HTTP/HTTPSは `/v1/tunnels/wireguard/open` を自動補完します。外部のリバースプロキシでは `/v1/tunnels/wireguard/*` をagentへ転送し、relayでは `/v1/tunnels/relay/*` を転送してください。relayのHTTP/HTTPS入口は `/v1/tunnels/relay/open` を使用します。公開Webゲートウェイを有効にしたagentでは、指定されたHTTPSホスト名をCaddyの公開入口・証明書設定に追加します。UDP・素のTCPも利用する場合は、そのポートを扱うL4の転送経路が必要です。

Helmは `agent.publicTransportUrls` / `agent.relayService.publicTransportUrls`、ネイティブ配置のAnsibleは各ホストの `public_transport_urls` リストで管理します。URL一覧は既存の数値IP一覧と別に配布するため、旧クライアントは従来のIP入口を使えます。URL対応を利用するにはコントロールプレーン・agent/relay・クライアントの更新が必要です。DNSレコード自体は利用するDNSサービス側で管理してください。

## 観測

管理コンソールの「通信方式」で、報告ノード・接続先・送受信方向・UDP/TCP/HTTPS/HTTP・状態・入口・通信量・切替回数・再接続回数・理由・失敗履歴・更新時刻を確認できます。報告は署名されたハートビートから共有DBへ保存されるため、別のコントロールプレーンにアクセスしても参照できます。90秒以上更新されない報告を正常・使用量0として扱いません。通信量はプロセス起動以降の累積値です。

ホスト名を使う入口では、設定したURLと実際に接続したIPを併記します。DNS取得失敗と公開IPが存在しない場合は、それぞれ `dns_unavailable` / `dns_nonpublic` として失敗履歴に記録します。

管理者APIは `GET /v1/admin/transports?limit=10&after=<node-id>` です。`node_id` でノードを指定できます。1ページ最大50ノード、各ノード最大4096件の観測です。`unreported` は報告のないノードです。監視用の `/metrics` は `ipars_transport_connections`、`ipars_transport_report_timestamp_seconds`、`ipars_transport_tx_bytes`、`ipars_transport_rx_bytes`、`ipars_transport_switches`、`ipars_transport_reconnects`、`ipars_transport_failures` を公開します。ラベルにはURLや認証情報を含めません。

## ロールアウトと検証

コントロールプレーン、公開ゲートウェイのagent/relay、参加ノード、ネイティブクライアントの順に更新します。機能照会に応じて新しい観測フィールドを送るため、旧コントロールプレーンとの混在中も従来形式のハートビートに戻れます。旧サーバーからピアマップを取得したときは、同じWireGuard鍵を持つ残存ピアの直近の入口を保持します。

`HTTP transport fallback` Actionsは、Rustのワークスペース検査・テスト、Linux/macOS/Windows共通転送処理の競合検出付きテスト、管理画面のChromiumテストを実行します。暗号化通信テストはBoringTunで実際のWireGuardハンドシェイクとデータ転送を行い、WANのUDP経路を遮断してHTTPへ切り替え、UDP経路の復旧後に同じローカル接続先のまま戻れることを検証します。リレーはHTTP対UDP、HTTP対HTTP、TCP対HTTP、TCP対TCPを検証します。素のTCPでもUDP遮断・暗号化通信・UDP復旧を同じ条件で検証します。
