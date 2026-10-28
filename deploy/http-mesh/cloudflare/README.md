# Cloudflare Containers の実配置

`wrangler.production.jsonc` は実配置の設定です。アカウント、公開Worker、検証済みamd64イメージのダイジェスト、制御プレーンの接続先を含みます。参加トークンと管理トークンはCloudflareのWorkerシークレットに保存し、Gitには含めません。

```sh
cd deploy/http-mesh/cloudflare
npm ci --ignore-scripts
npx wrangler login --device --browser=false
npm test
npm run check
npx wrangler deploy --config wrangler.production.jsonc
npx wrangler secret put HETERONETWORK_JOIN_TOKEN --config wrangler.production.jsonc
npx wrangler secret put MANAGEMENT_TOKEN --config wrangler.production.jsonc
```

管理トークンは32文字以上の乱数を使います。参加トークンは既存のノード登録ルールに従い、Workerロール・有限の利用回数・有効期限・HAブートストラップを設定します。現在の発行者は最大7日、最大1000回です。期限を迎える前に参加トークンを更新してください。登録後の既存ノードの通信は参加トークンの期限とは別に維持されますが、期限後に新しいインスタンスを起動するには更新が必要です。

別アカウントで使う場合は`wrangler.jsonc`の接続先とWorkerルートを設定します。この設定はDockerでソースからイメージを作成します。ビルドコンテキストは`clients/headless`だけで、リポジトリのSSH鍵は送りません。ビルド済みイメージを使う場合はCloudflareの管理レジストリへ転送し、`containers[].images.base.image`へダイジェスト付き参照を指定します。外部GHCR参照をそのまま指定する方式には対応していません。

## 起動・確認・停止

リポジトリのルートで実行します。`--token-file`は権限0600の管理トークンファイル、または`MANAGEMENT_TOKEN`を含むシークレットJSONを受け取ります。値をコマンドライン引数やURLには渡しません。

```sh
python3 scripts/cloudflare_http_members.py start cloudflare-1 \
  --origin https://heteronet-http-members.fasutotesuto.workers.dev \
  --token-file /run/secrets/cloudflare-members-management
python3 scripts/cloudflare_http_members.py ready cloudflare-1 \
  --origin https://heteronet-http-members.fasutotesuto.workers.dev \
  --token-file /run/secrets/cloudflare-members-management
python3 scripts/cloudflare_http_members.py stop cloudflare-1 \
  --origin https://heteronet-http-members.fasutotesuto.workers.dev \
  --token-file /run/secrets/cloudflare-members-management
```

名前ごとに別のDurable ObjectとVPN IPを使います。`ready`も停止中の名前を起動します。停止確認のために`ready`を呼ばないでください。公開Workerは管理APIであり、ブラウザで認証なしに開くと401を返します。認証前にはコンテナへアクセスしません。

新規アカウントで必要な`durable_object`スケジューリングを使用しています。実行サイズは`HETERONETWORK_INSTANCE`（既定`lite`）で指定し、実行イメージは`ctx.container.images.base`から渡します。この方式にはアプリ単位の`max_instances`設定がなく、アカウントの上限と管理APIの認証で制御します。

VPNの継続受信に必要な稼働時間を、5分のinactivity timeoutと1分ごとの永続アラームで更新します。稼働指定をDurable Objectへ保存し、Workerの再配置やVM停止後もアラームで復旧します。明示停止では先に稼働指定とアラームを解除し、SIGTERMでVPN登録を終了します。

`HETERONETWORK_ARGS`にはCLI引数を配列で設定できます。実配置の`18081=127.0.0.1:8080`はVPN内からコンテナのreadinessを確認するための転送で、公開Worker経由ではアプリを公開しません。

公式仕様: [Durable Objectのスケジューリング](https://developers.cloudflare.com/containers/configuration/scheduling-policy/)、[Container API](https://developers.cloudflare.com/containers/api/durable-object-container/)。実機検証の記録は[Cloudflare配置検証](../../../docs/verification/cloudflare-http-mesh-2026-10-28.json)にあります。
