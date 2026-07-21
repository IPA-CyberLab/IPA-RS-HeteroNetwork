(function () {
  "use strict";

  var ICONS = {
    "layout-dashboard": '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
    server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>',
    network: '<rect width="6" height="6" x="3" y="3" rx="1"/><rect width="6" height="6" x="15" y="15" rx="1"/><path d="M9 6h3a3 3 0 0 1 3 3v6"/><path d="M15 18h-3a3 3 0 0 1-3-3V9"/>',
    route: '<circle cx="6" cy="19" r="3"/><path d="M9 19h2a4 4 0 0 0 4-4V9a4 4 0 0 1 4-4h0"/><path d="m17 2 3 3-3 3"/>',
    "shield-check": '<path d="M20 13c0 5-3.5 7.5-8 9-4.5-1.5-8-4-8-9V5l8-3 8 3z"/><path d="m9 12 2 2 4-4"/>',
    "chevron-right": '<path d="m9 18 6-6-6-6"/>',
    menu: '<line x1="4" x2="20" y1="6" y2="6"/><line x1="4" x2="20" y1="12" y2="12"/><line x1="4" x2="20" y1="18" y2="18"/>',
    "panel-left": '<rect width="18" height="18" x="3" y="3" rx="2"/><path d="M9 3v18"/>',
    "log-in": '<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" x2="3" y1="12" y2="12"/>',
    "log-out": '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>',
    "refresh-cw": '<path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/>',
    search: '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    filter: '<polygon points="22 3 2 3 10 12.5 10 19 14 21 14 12.5 22 3"/>',
    "arrow-up-right": '<path d="M7 7h10v10"/><path d="M7 17 17 7"/>',
    "arrow-down-right": '<path d="M7 7h10v10"/><path d="m7 7 10 10"/>',
    "circle-check": '<circle cx="12" cy="12" r="10"/><path d="m8 12 2.5 2.5L16 9"/>',
    "circle-alert": '<circle cx="12" cy="12" r="10"/><line x1="12" x2="12" y1="8" y2="12"/><line x1="12" x2="12.01" y1="16" y2="16"/>',
    "alert-triangle": '<path d="m21.7 18-8.4-14a1.5 1.5 0 0 0-2.6 0L2.3 18A1.5 1.5 0 0 0 3.6 20h16.8a1.5 1.5 0 0 0 1.3-2Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>',
    x: '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    pin: '<path d="M12 17v5"/><path d="M9 3h6l1 7 3 3H5l3-3z"/>',
    "pin-off": '<path d="m2 2 20 20"/><path d="M9 3h6l1 7 2.4 2.4"/><path d="M5 13h14"/><path d="M12 17v5"/>',
    "trash-2": '<path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v5"/><path d="M14 11v5"/>',
    plus: '<path d="M5 12h14"/><path d="M12 5v14"/>',
    save: '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2Z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
    copy: '<rect width="13" height="13" x="9" y="9" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    clock: '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15 14"/>',
    activity: '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    sliders: '<line x1="4" x2="4" y1="21" y2="14"/><line x1="4" x2="4" y1="10" y2="3"/><line x1="12" x2="12" y1="21" y2="12"/><line x1="12" x2="12" y1="8" y2="3"/><line x1="20" x2="20" y1="21" y2="16"/><line x1="20" x2="20" y1="12" y2="3"/><line x1="2" x2="6" y1="14" y2="14"/><line x1="10" x2="14" y1="8" y2="8"/><line x1="18" x2="22" y1="16" y2="16"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    "more-horizontal": '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    wifi: '<path d="M5 13a10 10 0 0 1 14 0"/><path d="M8.5 16.5a5 5 0 0 1 7 0"/><path d="M12 20h.01"/>',
    "route-off": '<path d="m2 2 20 20"/><path d="M9 3h4a3 3 0 0 1 3 3v1"/><path d="M15 15v1a3 3 0 0 1-3 3H9"/><path d="M5 13h6"/><path d="M19 13h3"/>',
    "check-check": '<path d="m1 12 4 4L15 6"/><path d="m9 12 4 4L23 6"/>',
    "external-link": '<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
    moon: '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.42 1.42"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" x2="12" y1="15" y2="3"/>',
    key: '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
    terminal: '<polyline points="4 17 10 11 4 5"/><line x1="12" x2="20" y1="19" y2="19"/>'
  };

  var JAPANESE = {
    "Network control": "ネットワーク管理",
    "Cluster": "クラスター",
    "Not connected": "未接続",
    "Offline": "オフライン",
    "Connected": "接続済み",
    "Language": "言語",
    "Switch to dark mode": "ダークモードに切り替え",
    "Switch to light mode": "ライトモードに切り替え",
    "Open navigation": "ナビゲーションを開く",
    "Collapse navigation": "ナビゲーションを折りたたむ",
    "Expand navigation": "ナビゲーションを展開",
    "Refresh data": "データを更新",
    "Network": "ネットワーク",
    "Overview": "概要",
    "Devices": "デバイス",
    "Add device": "デバイスを追加",
    "Public nodes": "公開ノード",
    "Connections": "接続",
    "Network routes": "ネットワークルート",
    "Security": "セキュリティ",
    "Access control": "アクセス制御",
    "API online": "API 稼働中",
    "Control plane": "コントロールプレーン",
    "Control Plane": "コントロールプレーン",
    "Stun": "STUN",
    "Sign in": "ログイン",
    "Sign out": "ログアウト",
    "Sign in to your network": "ネットワークにログイン",
    "Use the configured identity provider to continue.": "設定済みの ID プロバイダーで続行してください。",
    "Sign in with SSO": "SSO でログイン",
    "Operator token": "オペレータートークン",
    "Paste a bearer token": "Bearer トークンを貼り付け",
    "Connect": "接続",
    "Session protected by the control plane": "セッションはコントロールプレーンで保護されています",
    "Live": "ライブ",
    "Refresh": "更新",
    "Network health at a glance.": "ネットワーク全体の状態を確認します。",
    "Registered nodes and their current health.": "登録済みノードと現在の状態を確認します。",
    "Lease-backed control and traversal services.": "リースで冗長化された制御・トラバーサルサービスです。",
    "Selected paths and operator controls.": "選択中の経路とオペレーター制御です。",
    "Advertised networks and their owners.": "広報されたネットワークと所有ノードです。",
    "Runtime connectivity policy and rules.": "実行時の接続ポリシーとルールです。",
    "Issue a short-lived token and install a node with one command.": "短期トークンを発行し、1 コマンドでノードを追加します。",
    "Public": "公開",
    "Private": "プライベート",
    "NAT": "NAT",
    "Double NAT": "二重 NAT",
    "Relay only": "リレーのみ",
    "Not detected": "未検出",
    "Direct public endpoint": "直接到達可能な公開エンドポイント",
    "Private or shared address": "プライベートまたは共有アドレス",
    "Direct Public": "公開直接接続",
    "Direct Ipv6": "IPv6 直接接続",
    "Direct Nat Traversal": "NAT トラバーサル直接接続",
    "NAT traversal available": "NAT トラバーサル利用可能",
    "NAT, relay preferred": "NAT、リレー優先",
    "Multiple NAT layers detected": "複数の NAT レイヤーを検出",
    "Direct traversal unavailable": "直接トラバーサル不可",
    "Waiting for STUN report": "STUN レポート待ち",
    "Connectivity map": "接続マップ",
    "Detected NAT posture and selected peer paths": "検出した NAT 状態と選択中のピア経路",
    "No devices registered": "登録済みデバイスはありません",
    "Connect a device to map network reachability.": "デバイスを接続すると到達性が表示されます。",
    "Connect a device to see it here.": "デバイスを接続するとここに表示されます。",
    "No path reports yet.": "経路レポートはまだありません。",
    "None": "なし",
    "Available": "利用可能",
    "No": "いいえ",
    "Unknown": "不明",
    "Endpoint Independent": "エンドポイント非依存",
    "Address Dependent": "アドレス依存",
    "Address And Port Dependent": "アドレス・ポート依存",
    "No Nat": "NAT なし",
    "Relay Preferred": "リレー優先",
    "No devices found": "デバイスが見つかりません",
    "Try changing the search or status filter.": "検索条件または状態フィルターを変更してください。",
    "Device": "デバイス",
    "VPN address": "VPN アドレス",
    "Status": "状態",
    "Role": "ロール",
    "Connectivity": "接続性",
    "Tags": "タグ",
    "Relay": "リレー",
    "Last seen": "最終確認",
    "Open device details": "デバイス詳細を開く",
    "All devices classified": "全デバイス分類済み",
    "Awaiting STUN reports": "STUN レポート待ち",
    "Advertised routes": "広報ルート",
    "Across registered devices": "登録済みデバイス全体",
    "NAT profiles": "NAT プロファイル",
    "Access rules": "アクセスルール",
    "Relay fallback enabled": "リレーフォールバック有効",
    "Relay fallback disabled": "リレーフォールバック無効",
    "High availability": "高可用性",
    "Ready": "準備完了",
    "Degraded": "縮退",
    "Connection health": "接続状態",
    "Selected path distribution": "選択中経路の分布",
    "Policy posture": "ポリシー状態",
    "Runtime settings": "実行時設定",
    "Edit policy": "ポリシーを編集",
    "IPv6 direct": "IPv6 直接接続",
    "NAT traversal": "NAT トラバーサル",
    "Relay fallback": "リレーフォールバック",
    "Enabled": "有効",
    "Disabled": "無効",
    "Path state TTL": "経路状態 TTL",
    "Public service availability": "公開サービスの可用性",
    "Lease-backed failover members": "リース管理されたフェイルオーバーメンバー",
    "HA ready": "HA 準備完了",
    "HA degraded": "HA 縮退",
    "Recently seen devices": "最近確認したデバイス",
    "Latest control-plane observations": "最新のコントロールプレーン観測",
    "View all": "すべて表示",
    "Signal": "シグナル",
    "STUN": "STUN",
    "Active": "稼働中",
    "Public instance": "公開インスタンス",
    "Services": "サービス",
    "Lease expires": "リース期限",
    "No public services": "公開サービスはありません",
    "No active service lease is registered.": "有効なサービスリースは登録されていません。",
    "HA status": "HA 状態",
    "Redundant": "冗長",
    "Single endpoint": "単一エンドポイント",
    "Unavailable": "利用不可",
    "Missing": "未設定",
    "Leased": "リース中",
    "Public node": "公開ノード",
    "Lease": "リース",
    "No public nodes": "公開ノードはありません",
    "No active public service lease is registered.": "有効な公開サービスリースは登録されていません。",
    "Service matrix": "サービスマトリクス",
    "Active lease directory": "有効なリースディレクトリ",
    "All statuses": "すべての状態",
    "Healthy": "正常",
    "Unreachable": "到達不可",
    "Search devices": "デバイスを検索",
    "All states": "すべての状態",
    "Direct": "直接",
    "Local device": "ローカルデバイス",
    "Remote device": "リモートデバイス",
    "State": "状態",
    "Endpoint": "エンドポイント",
    "Score": "スコア",
    "Updated": "更新日時",
    "Control": "操作",
    "Pin": "固定",
    "Unpin": "固定解除",
    "No connections found": "接続が見つかりません",
    "Try changing the search or state filter.": "検索条件または状態フィルターを変更してください。",
    "Selected endpoint, relay, score, and operator pin state": "選択中エンドポイント、リレー、スコア、固定状態",
    "Search by node or endpoint": "ノードまたはエンドポイントを検索",
    "Route ID": "ルート ID",
    "Advertised by": "広報元",
    "Advertised": "広報中",
    "No routes found": "ルートが見つかりません",
    "Registered devices have not advertised a matching route.": "一致するルートは登録済みデバイスから広報されていません。",
    "Networks advertised by registered devices": "登録済みデバイスが広報するネットワーク",
    "Search routes or owners": "ルートまたは所有ノードを検索",
    "Comma separated": "カンマ区切り",
    "Unnamed rule": "名称未設定ルール",
    "Delete": "削除",
    "Rule ID": "ルール ID",
    "Action": "アクション",
    "Protocol": "プロトコル",
    "Allow": "許可",
    "Deny": "拒否",
    "From roles": "送信元ロール",
    "From tags": "送信元タグ",
    "To roles": "宛先ロール",
    "To tags": "宛先タグ",
    "Routes (CIDR)": "ルート (CIDR)",
    "No matching access rules": "一致するアクセスルールはありません",
    "Use Add rule to define a new policy entry.": "「ルールを追加」で新しいポリシーを定義します。",
    "Policy settings": "ポリシー設定",
    "Runtime connectivity posture": "実行時の接続方針",
    "Permit direct IPv6 candidates": "IPv6 直接接続候補を許可",
    "Use endpoint discovery and traversal": "エンドポイント探索とトラバーサルを使用",
    "Use relay when direct paths fail": "直接経路が失敗した場合にリレーを使用",
    "Idle timeout (seconds)": "アイドルタイムアウト (秒)",
    "Endpoint TTL (seconds)": "エンドポイント TTL (秒)",
    "Path TTL (seconds)": "経路 TTL (秒)",
    "Save policy": "ポリシーを保存",
    "Match identities, tags, routes, and protocol": "ID、タグ、ルート、プロトコルを照合",
    "Filter rules": "ルールを絞り込み",
    "Filter access rules": "アクセスルールを絞り込み",
    "Add rule": "ルールを追加",
    "Device details": "デバイス詳細",
    "Registered node": "登録済みノード",
    "Close device details": "デバイス詳細を閉じる",
    "Close": "閉じる",
    "Registered": "登録日時",
    "Relay capability": "リレー機能",
    "Advertised routes": "広報ルート",
    "Remove device": "デバイスを削除",
    "Observed endpoint": "観測エンドポイント",
    "Mapping": "マッピング",
    "Filtering": "フィルタリング",
    "Traversal": "トラバーサル",
    "Confidence": "信頼度",
    "Not Reported": "未報告",
    "Web UI is not configured": "Web UI は設定されていません",
    "Enable the web UI and configure an operator token or OIDC provider on the daemon.": "デーモンで Web UI とオペレータートークンまたは OIDC プロバイダーを設定してください。",
    "Your session expired. Sign in again.": "セッションの有効期限が切れました。再度ログインしてください。",
    "Add a Linux server": "Linux サーバーを追加",
    "Generate a secure install command for a new HeteroNetwork node.": "新しい HeteroNetwork ノード用の安全なインストールコマンドを生成します。",
    "1. Device settings": "1. デバイス設定",
    "Choose the identity and capabilities assigned at enrollment.": "登録時に付与する ID と機能を選択します。",
    "Device role": "デバイスロール",
    "Edge": "エッジ",
    "Worker": "ワーカー",
    "Gateway": "ゲートウェイ",
    "Member": "メンバー",
    "Tags (comma separated)": "タグ (カンマ区切り)",
    "example: production, linux": "例: production, linux",
    "Allow relay service": "リレーサービスを許可",
    "Permit this node to advertise relay capability.": "このノードがリレー機能を広報することを許可します。",
    "2. Authentication key": "2. 認証キー",
    "Limit how long and how many times the enrollment token can be used.": "登録トークンの有効期間と利用回数を制限します。",
    "Reusable": "再利用可能",
    "Allow more than one device to use this token.": "複数デバイスでこのトークンを使用できるようにします。",
    "Expiration (days)": "有効期限 (日)",
    "Maximum uses": "最大利用回数",
    "3. Generate install script": "3. インストールスクリプトを生成",
    "The command installs the signed Linux amd64 agent, enrolls once, removes the token, and starts systemd.": "署名済み Linux amd64 エージェントを導入し、一度だけ登録してトークンを削除した後、systemd を起動します。",
    "Generate install script": "インストールスクリプトを生成",
    "Generating...": "生成中...",
    "Install command": "インストールコマンド",
    "Run this command as a user with sudo access on the new Linux server.": "新しい Linux サーバー上で sudo 権限を持つユーザーとして実行してください。",
    "Copy command": "コマンドをコピー",
    "Download script": "スクリプトをダウンロード",
    "Enrollment token": "登録トークン",
    "Treat this token as a secret. It is not stored by this browser.": "このトークンは秘密情報として扱ってください。ブラウザには保存されません。",
    "Copy token": "トークンをコピー",
    "Expires": "有効期限",
    "Uses": "利用回数",
    "Architecture": "アーキテクチャ",
    "Create another": "別のトークンを作成",
    "Enrollment is not enabled on this control plane.": "このコントロールプレーンではノード登録が有効ではありません。",
    "Command copied.": "コマンドをコピーしました。",
    "Token copied.": "トークンをコピーしました。",
    "Install script downloaded.": "インストールスクリプトをダウンロードしました。",
    "Enrollment token issued.": "登録トークンを発行しました。",
    "Expiration must be between 1 and 30 days.": "有効期限は 1 日から 30 日の範囲で指定してください。",
    "Maximum uses must be between 2 and 1000.": "最大利用回数は 2 回から 1000 回の範囲で指定してください。",
    "Copy failed": "コピーに失敗しました",
    "Linux node": "Linux ノード",
    "macOS client": "macOS クライアント",
    "Add a macOS client": "macOS クライアントを追加",
    "Generate a one-use enrollment link for the native HeteroNetwork app.": "HeteroNetwork ネイティブアプリ用の単回登録リンクを生成します。",
    "1. Token lifetime": "1. トークン有効期間",
    "The client token can be used once and cannot advertise routes or relay traffic.": "クライアントトークンは 1 回だけ使用でき、ルートやリレートラフィックを広報できません。",
    "2. Generate enrollment link": "2. 登録リンクを生成",
    "Generate macOS link": "macOS リンクを生成",
    "Enrollment link": "登録リンク",
    "Open this link on the Mac where HeteroNetwork is installed.": "HeteroNetwork をインストールした Mac でこのリンクを開いてください。",
    "Copy link": "リンクをコピー",
    "Open HeteroNetwork": "HeteroNetwork を開く",
    "Platform": "プラットフォーム",
    "Link copied.": "リンクをコピーしました。",
    "macOS enrollment token issued.": "macOS 登録トークンを発行しました。",
    "Device type": "デバイスタイプ",
    "Issue a one-use link for the native macOS client.": "macOS ネイティブクライアント用の単回リンクを発行します。"
  };

  var state = {
    config: null,
    overview: null,
    token: sessionStorage.getItem("heteronetwork_access_token")
      || sessionStorage.getItem("heteronetwork_operator_token")
      || "",
    activeView: "overview",
    selectedNodeId: null,
    loading: false,
    policyDirty: false,
    sidebarCollapsed: localStorage.getItem("heteronetwork_sidebar_collapsed") === "true",
    mobileNavOpen: false,
    locale: document.documentElement.lang === "ja" ? "ja" : "en",
    theme: document.documentElement.dataset.theme === "dark" ? "dark" : "light",
    enrollment: {
      mode: "linux",
      role: "edge",
      tags: "",
      allowRelay: false,
      reusable: false,
      expirationDays: 7,
      clientExpirationDays: 1,
      maxUses: 10,
      result: null,
      generating: false
    },
    filters: {
      nodes: "",
      nodeHealth: "all",
      paths: "",
      pathState: "all",
      routes: "",
      acl: ""
    }
  };

  function $(id) {
    return document.getElementById(id);
  }

  function t(source) {
    return state.locale === "ja" && JAPANESE[source] ? JAPANESE[source] : source;
  }

  function translateDynamicText(value) {
    if (state.locale !== "ja") return value;
    if (JAPANESE[value]) return JAPANESE[value];
    var patterns = [
      [/^Updated (.+)$/, "更新: $1"],
      [/^Sign in with (.+)$/, "$1 でログイン"],
      [/^(\d+)s ago$/, "$1 秒前"],
      [/^(\d+)m ago$/, "$1 分前"],
      [/^(\d+)h ago$/, "$1 時間前"],
      [/^(\d+)d ago$/, "$1 日前"],
      [/^(\d+) healthy$/, "正常 $1 台"],
      [/^(\d+) stale$/, "期限切れ $1 件"],
      [/^(\d+) public instances$/, "公開インスタンス $1 台"],
      [/^(\d+) active public nodes$/, "稼働中の公開ノード $1 台"],
      [/^(\d+) active$/, "稼働中 $1 台"],
      [/^(\d+) paths$/, "$1 経路"],
      [/^(\d+) routes$/, "$1 ルート"],
      [/^(\d+) rules$/, "$1 ルール"],
      [/^(\d+) results$/, "$1 件"],
      [/^(\d+) seconds$/, "$1 秒"],
      [/^(\d+) stale$/, "期限切れ $1 件"],
      [/^Showing (\d+) of (\d+) devices and (\d+) of (\d+) paths\.$/, "デバイス $2 台中 $1 台、経路 $4 件中 $3 件を表示しています。"]
    ];
    for (var index = 0; index < patterns.length; index += 1) {
      if (patterns[index][0].test(value)) return value.replace(patterns[index][0], patterns[index][1]);
    }
    return value;
  }

  function translateTree(root) {
    if (!root || state.locale !== "ja") return;
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    var nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(function (node) {
      if (node.parentElement && node.parentElement.closest("[data-no-i18n], code, pre, .mono")) return;
      var source = node.nodeValue;
      var trimmed = source.trim();
      if (!trimmed) return;
      var translated = translateDynamicText(trimmed);
      if (translated !== trimmed) {
        node.nodeValue = source.slice(0, source.indexOf(trimmed)) + translated + source.slice(source.indexOf(trimmed) + trimmed.length);
      }
    });
    root.querySelectorAll("[placeholder], [aria-label], [title]").forEach(function (node) {
      if (node.closest("[data-no-i18n]")) return;
      ["placeholder", "aria-label", "title"].forEach(function (attribute) {
        if (node.hasAttribute(attribute)) {
          node.setAttribute(attribute, translateDynamicText(node.getAttribute(attribute)));
        }
      });
    });
  }

  function applyStaticTranslations() {
    document.querySelectorAll("[data-i18n]").forEach(function (node) {
      node.textContent = t(node.dataset.i18n);
    });
    ["placeholder", "aria", "title"].forEach(function (kind) {
      document.querySelectorAll("[data-i18n-" + kind + "]").forEach(function (node) {
        var attribute = kind === "aria" ? "aria-label" : kind;
        node.setAttribute(attribute, t(node.dataset["i18n" + kind.charAt(0).toUpperCase() + kind.slice(1)]));
      });
    });
  }

  function icon(name, size) {
    var content = ICONS[name] || ICONS.activity;
    var dimension = size || 16;
    return '<svg aria-hidden="true" width="' + dimension + '" height="' + dimension
      + '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
      + content + "</svg>";
  }

  function decorateIcons(root) {
    (root || document).querySelectorAll("[data-icon]").forEach(function (node) {
      node.innerHTML = icon(node.dataset.icon);
    });
  }

  function applyTheme(theme, persist) {
    state.theme = theme === "dark" ? "dark" : "light";
    document.documentElement.dataset.theme = state.theme;
    if (persist) localStorage.setItem("heteronetwork_theme", state.theme);
    var themeColor = document.querySelector('meta[name="theme-color"]');
    if (themeColor) themeColor.setAttribute("content", state.theme === "dark" ? "#101214" : "#ffffff");
    var action = state.theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
    $("theme-toggle").setAttribute("aria-label", t(action));
    $("theme-toggle").setAttribute("title", t(action));
    $("theme-toggle").innerHTML = icon(state.theme === "dark" ? "sun" : "moon");
  }

  function updateAuthConfigText() {
    if (!state.config) return;
    if (state.config.provider) {
      $("oidc-login").querySelector("span:last-child").textContent = translateDynamicText("Sign in with " + pretty(state.config.provider));
    }
    if (!state.config.enabled) {
      $("auth-title").textContent = t("Web UI is not configured");
      $("auth-copy").textContent = t("Enable the web UI and configure an operator token or OIDC provider on the daemon.");
    }
  }

  function setLocale(locale) {
    state.locale = locale === "ja" ? "ja" : "en";
    document.documentElement.lang = state.locale;
    localStorage.setItem("heteronetwork_locale", state.locale);
    $("toast-root").innerHTML = "";
    $("locale-select").value = state.locale;
    applyStaticTranslations();
    applyTheme(state.theme, false);
    updateAuthConfigText();
    if (state.overview) {
      $("cluster-name").textContent = state.overview.cluster_id;
      $("sidebar-cluster").textContent = state.overview.cluster_id;
      $("refresh-time").textContent = translateDynamicText("Updated " + formatTime(state.overview.generated_at));
      showDashboard();
      setConnection(true);
      renderView();
      if (state.selectedNodeId) openNodeDrawer(state.selectedNodeId);
    } else {
      setConnection(false);
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function shortId(value) {
    var text = String(value || "");
    return text.length > 18 ? text.slice(0, 9) + "..." + text.slice(-5) : text || "-";
  }

  function initials(value) {
    var text = String(value || "HN").replace(/[^a-zA-Z0-9]/g, "");
    return (text.slice(0, 2) || "HN").toUpperCase();
  }

  function formatTime(value) {
    if (!value) return "-";
    var date = new Date(value);
    if (isNaN(date.getTime())) return "-";
    if (state.locale === "ja") return date.toLocaleString("ja-JP", {
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23"
    });
    return date.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    });
  }

  function age(value) {
    if (!value) return "-";
    var timestamp = new Date(value).getTime();
    if (isNaN(timestamp)) return "-";
    var seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
    if (seconds < 60) return seconds + "s ago";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
    if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
    return Math.floor(seconds / 86400) + "d ago";
  }

  function pretty(value) {
    return String(value || "unknown").toLowerCase()
      .replace(/_/g, " ")
      .replace(/\b\w/g, function (letter) { return letter.toUpperCase(); });
  }

  function localizedRole(value) {
    var roles = {
      edge: "Edge",
      worker: "Worker",
      gateway: "Gateway",
      member: "Member",
      "control-plane": "Control Plane"
    };
    return roles[value] ? t(roles[value]) : (value || t("Member"));
  }

  function normalizePathState(value) {
    return String(value || "unknown").toLowerCase();
  }

  function natProfile(entry) {
    return entry && entry.nat_classification || {};
  }

  function connectivityInfo(entry) {
    var node = entry && entry.node || {};
    var profile = natProfile(entry);
    var hasProfile = Object.keys(profile).length > 0;
    var explicit = String(profile.connectivity_state || "").toLowerCase();
    var mapping = String(profile.mapping_behavior || "").toLowerCase();
    var strategy = String(profile.strategy || "").toLowerCase();
    var natNode = ["endpoint_independent", "address_dependent", "address_and_port_dependent"].indexOf(mapping) !== -1;
    var candidates = Array.isArray(node.endpoint_candidates) ? node.endpoint_candidates : [];
    var hasPublicCandidate = candidates.some(function (candidate) {
      var kind = String(candidate && candidate.kind || "").toLowerCase();
      return kind === "public_udp";
    });
    var explicitStates = ["public", "private", "nat", "double_nat", "relay_only"];
    var state = explicitStates.indexOf(explicit) !== -1
      ? explicit
      : !hasProfile && hasPublicCandidate
        ? "public"
        : strategy === "relay_preferred"
          ? "relay_only"
          : natNode
            ? "nat"
            : "unknown";
    var labels = {
      public: "Public",
      private: "Private",
      nat: "NAT",
      double_nat: "Double NAT",
      relay_only: "Relay only",
      unknown: "Not detected"
    };
    var details = {
      public: "Direct public endpoint",
      private: "Private or shared address",
      nat: strategy === "relay_preferred" ? "NAT, relay preferred" : "NAT traversal available",
      double_nat: "Multiple NAT layers detected",
      relay_only: "Direct traversal unavailable",
      unknown: "Waiting for STUN report"
    };
    var observed = profile.observed_endpoint;
    var confidence = Number(profile.confidence);
    return {
      state: state,
      label: labels[state],
      detail: details[state],
      profile: profile,
      observed: observed || "",
      strategy: strategy,
      confidence: isFinite(confidence) ? Math.round(confidence * 100) : null
    };
  }

  function topologyNode(entry) {
    var node = entry.node;
    var connectivity = connectivityInfo(entry);
    return '<button class="topology-node topology-' + connectivity.state + '" data-node-id="' + escapeHtml(node.node_id) + '" type="button">'
      + '<span class="topology-node-icon">' + icon(connectivity.state === "relay_only" ? "route-off" : connectivity.state === "public" ? "wifi" : "network") + '</span>'
      + '<span class="topology-node-copy"><strong data-no-i18n>' + escapeHtml(shortId(node.node_id)) + '</strong><small>' + escapeHtml(connectivity.label) + '</small></span>'
      + '<span class="topology-node-state">' + escapeHtml(connectivity.confidence == null ? "-" : connectivity.confidence + "%") + '</span></button>';
  }

  function topologyLink(path) {
    var local = path.key && path.key.local || "-";
    var remote = path.key && path.key.remote || "-";
    var selectedState = normalizePathState(path.selected_state);
    return '<div class="topology-link"><button class="topology-peer" data-node-id="' + escapeHtml(local) + '" data-no-i18n type="button">' + escapeHtml(shortId(local)) + '</button>'
      + '<span class="topology-line"><span></span></span><button class="topology-peer" data-node-id="' + escapeHtml(remote) + '" data-no-i18n type="button">' + escapeHtml(shortId(remote)) + '</button>'
      + statusPill(selectedState) + '</div>';
  }

  function renderTopology(nodes, paths) {
    var visibleNodes = nodes.slice(0, 12);
    var visiblePaths = paths.slice(0, 16);
    var nodeMarkup = visibleNodes.length ? visibleNodes.map(topologyNode).join("") : emptyState("No devices registered", "Connect a device to map network reachability.", "network");
    var pathMarkup = visiblePaths.length ? visiblePaths.map(topologyLink).join("") : '<div class="topology-empty">No path reports yet.</div>';
    return '<section class="section-panel topology-panel"><div class="section-header"><div><h2>Connectivity map</h2><p>Detected NAT posture and selected peer paths</p></div><div class="topology-legend"><span><i class="legend-dot public"></i>Public</span><span><i class="legend-dot private"></i>Private</span><span><i class="legend-dot nat"></i>NAT</span><span><i class="legend-dot double-nat"></i>Double NAT</span><span><i class="legend-dot relay-only"></i>Relay only</span></div></div><div class="topology-body"><div class="topology-nodes">' + nodeMarkup + '</div><div class="topology-links">' + pathMarkup + '</div></div>'
      + (nodes.length > visibleNodes.length || paths.length > visiblePaths.length ? '<div class="topology-footnote">Showing ' + visibleNodes.length + ' of ' + nodes.length + ' devices and ' + visiblePaths.length + ' of ' + paths.length + ' paths.</div>' : '') + '</section>';
  }

  function statusClass(value) {
    var text = String(value || "unknown").toLowerCase();
    if (text.indexOf("unreachable") !== -1 || text.indexOf("unhealthy") !== -1 || text === "offline" || text === "denied") return "unreachable";
    if (text.indexOf("relay") !== -1) return "relay";
    if (text.indexOf("degraded") !== -1 || text.indexOf("stale") !== -1) return "degraded";
    if (text.indexOf("pinned") !== -1) return "pinned";
    if (text.indexOf("direct") !== -1 || text.indexOf("connected") !== -1) return "direct";
    if (text.indexOf("healthy") !== -1 || text === "online") return "healthy";
    if (text.indexOf("nat") !== -1 || text.indexOf("ipv6") !== -1) return "info";
    return "unknown";
  }

  function statusPill(value, label) {
    return '<span class="status-pill ' + statusClass(value) + '">' + escapeHtml(label || pretty(value)) + "</span>";
  }

  function listTags(tags) {
    var values = Array.isArray(tags) ? tags : Object.keys(tags || {});
    if (!values.length) return '<span class="faint">None</span>';
    return '<span class="tag-list" data-no-i18n>' + values.map(function (tag) {
      return '<span class="tag">' + escapeHtml(tag) + "</span>";
    }).join("") + "</span>";
  }

  function setStatus(message, error) {
    var node = $("status-message");
    node.textContent = message ? translateDynamicText(message) : "";
    node.classList.toggle("error", Boolean(error));
  }

  function toast(message, type) {
    var node = document.createElement("div");
    node.className = "toast " + (type || "success");
    node.innerHTML = icon(type === "error" ? "circle-alert" : "circle-check") + "<span>" + escapeHtml(translateDynamicText(message)) + "</span>";
    $("toast-root").appendChild(node);
    setTimeout(function () { node.remove(); }, 3600);
  }

  function setConnection(online) {
    var node = $("connection-state");
    node.className = "connection-state " + (online ? "online" : "offline");
    node.innerHTML = '<span class="status-dot"></span><span>' + t(online ? "Connected" : "Offline") + "</span>";
  }

  function api(path, options) {
    var request = options || {};
    var headers = new Headers(request.headers || {});
    headers.set("Accept", "application/json");
    if (state.token) headers.set("Authorization", "Bearer " + state.token);
    if (request.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    return fetch(path, Object.assign({}, request, { headers: headers })).then(async function (response) {
      if (response.status === 401) {
        clearSession();
        showAuth(t("Your session expired. Sign in again."));
        throw new Error("authentication required");
      }
      if (!response.ok) {
        var message = response.status + " " + response.statusText;
        try {
          var body = await response.json();
          if (body.error) message = body.error;
        } catch (_) {
          // Keep the HTTP status when the server did not return JSON.
        }
        throw new Error(message);
      }
      return response.json();
    });
  }

  function clearSession() {
    state.token = "";
    sessionStorage.removeItem("heteronetwork_access_token");
    sessionStorage.removeItem("heteronetwork_operator_token");
  }

  function showAuth(message) {
    $("auth-panel").hidden = false;
    $("dashboard").hidden = true;
    $("auth-error").textContent = message || "";
    $("auth-button").innerHTML = '<span class="account-avatar">A</span><span class="account-label">' + t("Sign in") + '</span>';
    setConnection(false);
    closeMobileNav();
  }

  function showDashboard() {
    $("auth-panel").hidden = true;
    $("dashboard").hidden = false;
    $("auth-button").innerHTML = '<span class="account-avatar">A</span><span class="account-label">' + t("Sign out") + '</span>';
  }

  function randomBytes(length) {
    var bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function base64Url(bytes) {
    var binary = "";
    bytes.forEach(function (byte) { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  function pkceChallenge(verifier) {
    return crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)).then(function (digest) {
      return base64Url(new Uint8Array(digest));
    });
  }

  function startLogin() {
    if (!state.config || !state.config.authorization_endpoint) return Promise.resolve();
    if (state.config.login_endpoint) {
      location.assign(state.config.login_endpoint);
      return Promise.resolve();
    }
    var verifier = base64Url(randomBytes(32));
    return pkceChallenge(verifier).then(function (challenge) {
      var loginState = base64Url(randomBytes(24));
      sessionStorage.setItem("heteronetwork_pkce_verifier", verifier);
      sessionStorage.setItem("heteronetwork_login_state", loginState);
      var params = new URLSearchParams({
        response_type: "code",
        client_id: state.config.client_id,
        redirect_uri: location.origin + "/ui/",
        scope: state.config.scopes || "openid profile email",
        state: loginState,
        code_challenge: challenge,
        code_challenge_method: "S256"
      });
      location.assign(state.config.authorization_endpoint + "?" + params.toString());
    });
  }

  function exchangeCode() {
    var query = new URLSearchParams(location.search);
    var code = query.get("code");
    if (!code) return Promise.resolve(false);
    if (query.get("state") !== sessionStorage.getItem("heteronetwork_login_state")) {
      return Promise.reject(new Error("OIDC state validation failed"));
    }
    var verifier = sessionStorage.getItem("heteronetwork_pkce_verifier");
    if (!verifier) return Promise.reject(new Error("OIDC verifier is missing"));
    var body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: state.config.client_id,
      code: code,
      redirect_uri: location.origin + "/ui/",
      code_verifier: verifier
    });
    return fetch(state.config.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body
    }).then(function (response) {
      if (!response.ok) throw new Error("OIDC token exchange failed (" + response.status + ")");
      return response.json();
    }).then(function (tokens) {
      if (!tokens.access_token) throw new Error("OIDC response did not include an access token");
      state.token = tokens.access_token;
      sessionStorage.setItem("heteronetwork_access_token", state.token);
      sessionStorage.removeItem("heteronetwork_pkce_verifier");
      sessionStorage.removeItem("heteronetwork_login_state");
      history.replaceState({}, document.title, location.origin + "/ui/");
      return true;
    });
  }

  function loadConfig() {
    return fetch("/ui/config", { headers: { Accept: "application/json" } }).then(function (response) {
      if (!response.ok) throw new Error("Unable to load UI configuration (" + response.status + ")");
      return response.json();
    }).then(function (config) {
      state.config = config;
      $("oidc-login").hidden = !config.auth_enabled;
      $("token-form").hidden = !config.operator_token_enabled;
      $("enrollment-nav").hidden = !config.node_enrollment_enabled && !config.client_enrollment_enabled;
      updateAuthConfigText();
    });
  }

  function updateNavigationCounts() {
    if (!state.overview) return;
    var metrics = state.overview.metrics || {};
    $("nav-node-count").textContent = metrics.node_count == null ? "-" : metrics.node_count;
    $("nav-service-count").textContent = metrics.active_service_instance_count == null ? "-" : metrics.active_service_instance_count;
    $("nav-path-count").textContent = metrics.path_count == null ? "-" : metrics.path_count;
    $("nav-rule-count").textContent = (state.overview.cluster_policy.acl_rules || []).length;
  }

  function loadOverview() {
    if (!state.token || state.loading || state.policyDirty) return Promise.resolve();
    state.loading = true;
    return api("/v1/admin/overview").then(function (overview) {
      state.overview = overview;
      showDashboard();
      setConnection(true);
      $("cluster-name").textContent = overview.cluster_id;
      $("sidebar-cluster").textContent = overview.cluster_id;
      $("refresh-time").textContent = translateDynamicText("Updated " + formatTime(overview.generated_at));
      updateNavigationCounts();
      renderView();
    }).catch(function (error) {
      if (error.message !== "authentication required") setStatus(error.message, true);
    }).finally(function () {
      state.loading = false;
    });
  }

  function metricCard(label, value, note, iconName, trend, trendClass) {
    return '<article class="metric-card"><div class="metric-heading"><span>' + escapeHtml(label)
      + '</span><span class="metric-icon">' + icon(iconName) + '</span></div><div class="metric-value">'
      + escapeHtml(value) + '</div><div class="metric-note">' + escapeHtml(note)
      + (trend ? '<span class="metric-trend ' + (trendClass || "") + '">' + trend + '</span>' : "")
      + "</div></article>";
  }

  function nodeTableRows(entries, limit) {
    var rows = (limit ? entries.slice(0, limit) : entries).map(function (entry) {
      var node = entry.node;
      var health = entry.health || {};
      var label = shortId(node.node_id);
      var connectivity = connectivityInfo(entry);
      return '<tr class="' + (state.selectedNodeId === node.node_id ? "selected" : "") + '"><td><button class="primary-link" data-node-id="'
        + escapeHtml(node.node_id) + '" type="button"><span class="table-primary"><span class="peer-avatar">'
        + escapeHtml(initials(node.node_id)) + '</span><span data-no-i18n><strong>' + escapeHtml(label)
        + '</strong><small title="' + escapeHtml(node.node_id) + '">' + escapeHtml(node.node_id) + '</small></span></span></button></td><td class="mono">'
        + escapeHtml(node.vpn_ip) + '</td><td>' + statusPill(health.state || "unknown") + '</td><td><span class="role-badge" data-no-i18n>'
        + escapeHtml(localizedRole(node.role)) + '</span></td><td>' + statusPill(connectivity.state, connectivity.label) + '</td><td>' + listTags(node.tags) + '</td><td>'
        + escapeHtml(node.relay_capability ? "Available" : "No") + '</td><td class="faint">' + escapeHtml(age(health.last_seen_at || node.registered_at)) + '</td><td><button class="detail-link" data-node-id="'
        + escapeHtml(node.node_id) + '" type="button" aria-label="Open device details" title="Open device details">'
        + icon("arrow-up-right") + "</button></td></tr>";
    }).join("");
    return rows || '<tr><td colspan="9"><div class="filter-empty"><strong>No devices found</strong><span>Try changing the search or status filter.</span></div></td></tr>';
  }

  function emptyState(title, message, iconName) {
    return '<div class="empty-state-card">' + icon(iconName || "server") + '<strong>' + escapeHtml(title) + '</strong><p>' + escapeHtml(message) + "</p></div>";
  }

  function renderOverview() {
    var overview = state.overview;
    var metrics = overview.metrics || {};
    var directory = overview.service_directory || { instances: [], bootstrap_endpoints: [] };
    var policy = overview.cluster_policy || {};
    var paths = overview.paths || [];
    var nodes = overview.nodes || [];
    var routeCount = nodes.reduce(function (total, entry) { return total + (entry.node.routes || []).length; }, 0);
    var natDiscovery = overview.nat_discovery || {};
    var natProfiles = Number.isFinite(natDiscovery.nat_classification_count)
      ? natDiscovery.nat_classification_count
      : nodes.filter(function (entry) { return connectivityInfo(entry).state !== "unknown"; }).length;
    var staleNatProfiles = natDiscovery.stale_nat_classification_count || 0;
    var natNote = staleNatProfiles ? staleNatProfiles + " stale" : natProfiles === nodes.length ? "All devices classified" : "Awaiting STUN reports";
    var counts = {};
    paths.forEach(function (path) {
      var pathState = normalizePathState(path.selected_state);
      counts[pathState] = (counts[pathState] || 0) + 1;
    });
    var totalStates = paths.length || 1;
    var stateRows = ["direct_public", "direct_ipv6", "direct_nat_traversal", "relay", "unreachable"].map(function (name) {
      var count = counts[name] || 0;
      var rowClass = name === "unreachable" ? "bad" : name === "relay" ? "warn" : "";
      return '<div class="state-row ' + rowClass + '"><span class="state-name">' + escapeHtml(pretty(name))
        + '</span><span class="state-bar"><span style="width:' + Math.max(count ? 3 : 0, Math.round((count / totalStates) * 100))
        + '%"></span></span><span class="state-count">' + count + '</span></div>';
    }).join("");
    var recent = nodes.slice().sort(function (a, b) {
      return new Date(b.health && b.health.last_seen_at || 0) - new Date(a.health && a.health.last_seen_at || 0);
    });
    var staleClass = metrics.stale_path_count ? "warn" : "";
    var recentContent = recent.length
      ? '<div class="table-wrap"><table><thead><tr><th>Device</th><th>VPN address</th><th>Status</th><th>Role</th><th>Connectivity</th><th>Tags</th><th>Relay</th><th>Last seen</th><th></th></tr></thead><tbody>' + nodeTableRows(recent, 6) + "</tbody></table></div>"
      : emptyState("No devices registered", "Connect a device to see it here.", "server");
    var serviceKinds = [
      ["Control plane", "active_control_plane_count"],
      ["Signal", "active_signal_count"],
      ["STUN", "active_stun_count"],
      ["Relay", "active_relay_count"]
    ];
    var serviceRows = serviceKinds.map(function (entry) {
      var count = metrics[entry[1]] || 0;
      return '<div class="policy-summary-row"><span>' + escapeHtml(entry[0]) + '</span>'
        + statusPill(count >= 2 ? "healthy" : count === 1 ? "degraded" : "unreachable", count + " active")
        + '</div>';
    }).join("");
    var instanceRows = (directory.instances || []).map(function (instance) {
      var services = (instance.endpoints || []).map(function (endpoint) {
        return translateDynamicText(pretty(endpoint.kind));
      }).join(", ");
      return '<tr><td class="mono">' + escapeHtml(instance.instance_id) + '</td><td>'
        + escapeHtml(services || "-") + '</td><td class="faint">' + escapeHtml(formatTime(instance.lease_expires_at))
        + '</td><td>' + statusPill("healthy", "Active") + '</td></tr>';
    }).join("");
    var instanceContent = instanceRows
      ? '<div class="table-wrap"><table><thead><tr><th>Public instance</th><th>Services</th><th>Lease expires</th><th>Status</th></tr></thead><tbody>' + instanceRows + '</tbody></table></div>'
      : emptyState("No public services", "No active service lease is registered.", "server");
    return '<div class="metric-grid">'
      + metricCard("Devices", metrics.node_count || 0, (metrics.healthy_node_count || 0) + " healthy", "server", icon("circle-check") + (metrics.healthy_node_count || 0), "")
      + metricCard("Connections", metrics.path_count || 0, (metrics.stale_path_count || 0) + " stale", "network", icon(metrics.stale_path_count ? "circle-alert" : "activity") + (metrics.stale_path_count || 0), staleClass)
      + metricCard("Advertised routes", routeCount, "Across registered devices", "route", "", "")
      + metricCard("NAT profiles", natProfiles, natNote, "wifi", "", staleNatProfiles || natProfiles !== nodes.length ? "warn" : "")
      + metricCard("Access rules", (policy.acl_rules || []).length, policy.allow_relay_fallback ? "Relay fallback enabled" : "Relay fallback disabled", "shield-check", "", "")
      + metricCard("High availability", metrics.ha_ready ? "Ready" : "Degraded", (metrics.active_service_instance_count || 0) + " public instances", metrics.ha_ready ? "check-check" : "alert-triangle", "", metrics.ha_ready ? "" : "warn")
      + '</div><div class="overview-grid"><section class="section-panel"><div class="section-header"><div><h2>Connection health</h2><p>Selected path distribution</p></div><span class="status-pill info">' + paths.length + ' paths</span></div><div class="section-body"><div class="state-list">'
      + stateRows + '</div></div></section><section class="section-panel"><div class="section-header"><div><h2>Policy posture</h2><p>Runtime settings</p></div><button class="button button-secondary button-small" data-navigate="acl" type="button">Edit policy</button></div><div class="section-body"><div class="policy-summary">'
      + '<div class="policy-summary-row"><span>IPv6 direct</span>' + statusPill(policy.allow_ipv6_direct ? "healthy" : "unreachable", policy.allow_ipv6_direct ? "Enabled" : "Disabled") + '</div>'
      + '<div class="policy-summary-row"><span>NAT traversal</span>' + statusPill(policy.allow_nat_traversal ? "healthy" : "unreachable", policy.allow_nat_traversal ? "Enabled" : "Disabled") + '</div>'
      + '<div class="policy-summary-row"><span>Relay fallback</span>' + statusPill(policy.allow_relay_fallback ? "healthy" : "unreachable", policy.allow_relay_fallback ? "Enabled" : "Disabled") + '</div>'
      + '<div class="policy-summary-row"><span>Path state TTL</span><span class="policy-summary-value">' + escapeHtml(policy.path_state_ttl_seconds) + " seconds</span></div>"
      + '</div></div></section></div>' + renderTopology(nodes, paths) + '<section class="section-panel"><div class="section-header"><div><h2>Public service availability</h2><p>Lease-backed failover members</p></div>'
      + statusPill(metrics.ha_ready ? "healthy" : "degraded", metrics.ha_ready ? "HA ready" : "HA degraded")
      + '</div><div class="section-body"><div class="policy-summary">' + serviceRows + '</div></div>' + instanceContent
      + '</section><section class="section-panel"><div class="section-header"><div><h2>Recently seen devices</h2><p>Latest control-plane observations</p></div><button class="button button-secondary button-small" data-navigate="nodes" type="button">View all</button></div>'
      + recentContent + "</section>";
  }

  function renderServices() {
    var overview = state.overview;
    var metrics = overview.metrics || {};
    var directory = overview.service_directory || { instances: [], bootstrap_endpoints: [] };
    var kinds = [
      ["control_plane", "Control plane", metrics.active_control_plane_count || 0],
      ["signal", "Signal", metrics.active_signal_count || 0],
      ["stun", "STUN", metrics.active_stun_count || 0],
      ["relay", "Relay", metrics.active_relay_count || 0]
    ];
    var endpointRows = (directory.instances || []).map(function (instance) {
      var endpoints = instance.endpoints || [];
      var endpointByKind = {};
      endpoints.forEach(function (endpoint) { endpointByKind[endpoint.kind] = endpoint.url; });
      return '<tr><td><span class="table-primary"><span class="peer-avatar">'
        + escapeHtml(initials(instance.instance_id)) + '</span><span><strong>'
        + escapeHtml(shortId(instance.instance_id)) + '</strong><small class="mono" title="'
        + escapeHtml(instance.instance_id) + '">' + escapeHtml(instance.instance_id)
        + '</small></span></span></td>' + kinds.map(function (kind) {
          var endpoint = endpointByKind[kind[0]];
          return '<td>' + (endpoint
            ? '<span class="service-endpoint"><span>' + statusPill("healthy", "Active")
              + '</span><code title="' + escapeHtml(endpoint) + '">' + escapeHtml(endpoint) + '</code></span>'
            : statusPill("unreachable", "Missing")) + '</td>';
        }).join("") + '<td><span class="service-endpoint"><span>' + statusPill("healthy", "Leased")
        + '</span><span class="faint">' + escapeHtml(formatTime(instance.lease_expires_at))
        + '</span></span></td></tr>';
    }).join("");
    var table = endpointRows
      ? '<div class="table-wrap"><table class="service-matrix"><thead><tr><th>Public node</th>'
        + kinds.map(function (kind) { return '<th>' + escapeHtml(kind[1]) + '</th>'; }).join("")
        + '<th>Lease</th></tr></thead><tbody>' + endpointRows + '</tbody></table></div>'
      : emptyState("No public nodes", "No active public service lease is registered.", "server");
    return '<div class="metric-grid">'
      + metricCard("HA status", metrics.ha_ready ? "Ready" : "Degraded", (metrics.active_service_instance_count || 0) + " active public nodes", metrics.ha_ready ? "check-check" : "alert-triangle", "", metrics.ha_ready ? "" : "warn")
      + kinds.map(function (kind) {
        return metricCard(kind[1], kind[2], kind[2] >= 2 ? "Redundant" : kind[2] === 1 ? "Single endpoint" : "Unavailable", kind[2] >= 2 ? "circle-check" : "circle-alert", "", kind[2] >= 2 ? "" : "warn");
      }).join("")
      + '</div><section class="section-panel"><div class="section-header"><div><h2>Service matrix</h2><p>Active lease directory</p></div>'
      + statusPill(metrics.ha_ready ? "healthy" : "degraded", metrics.ha_ready ? "HA ready" : "HA degraded")
      + '</div>' + table + '</section>';
  }

  function filteredNodes() {
    var query = state.filters.nodes.toLowerCase();
    var healthFilter = state.filters.nodeHealth;
    return (state.overview.nodes || []).filter(function (entry) {
      var node = entry.node;
      var health = entry.health || {};
      var haystack = [node.node_id, node.vpn_ip, node.role, (node.tags || []).join(" ")].join(" ").toLowerCase();
      return (!query || haystack.indexOf(query) !== -1) && (healthFilter === "all" || statusClass(health.state) === healthFilter);
    });
  }

  function tableToolbar(filterKey, placeholder, selectId, options, count) {
    var select = selectId ? '<select id="' + selectId + '" class="select-field" data-filter="' + selectId + '">' + options.map(function (option) {
      return '<option value="' + escapeHtml(option.value) + '" ' + (state.filters[selectId] === option.value ? "selected" : "") + '>' + escapeHtml(option.label) + "</option>";
    }).join("") + "</select>" : "";
    return '<div class="toolbar"><div class="toolbar-group"><label class="search-field"><span data-icon="search"></span><input type="search" data-filter="' + filterKey + '" value="' + escapeHtml(state.filters[filterKey]) + '" placeholder="' + escapeHtml(placeholder) + '" aria-label="' + escapeHtml(placeholder) + '"></label>' + select + '</div><span class="result-count">' + count + " results</span></div>";
  }

  function renderNodes() {
    var entries = filteredNodes();
    var options = [
      { value: "all", label: "All statuses" },
      { value: "healthy", label: "Healthy" },
      { value: "degraded", label: "Degraded" },
      { value: "unreachable", label: "Unreachable" }
    ];
    var tableBody = entries.length
      ? '<div class="table-wrap"><table><thead><tr><th>Device</th><th>VPN address</th><th>Status</th><th>Role</th><th>Connectivity</th><th>Tags</th><th>Relay</th><th>Last seen</th><th></th></tr></thead><tbody>' + nodeTableRows(entries) + "</tbody></table></div>"
      : emptyState("No devices found", "Try changing the search or status filter.", "server");
    var table = '<section class="section-panel">' + tableToolbar("nodes", "Search devices", "nodeHealth", options, entries.length) + tableBody + "</section>";
    return table;
  }

  function filteredPaths() {
    var query = state.filters.paths.toLowerCase();
    var pathFilter = state.filters.pathState;
    return (state.overview.paths || []).filter(function (path) {
      var haystack = [path.key.local, path.key.remote, normalizePathState(path.selected_state), path.selected_candidate && path.selected_candidate.addr, path.relay_node].join(" ").toLowerCase();
      return (!query || haystack.indexOf(query) !== -1) && (pathFilter === "all" || statusClass(path.selected_state) === pathFilter);
    });
  }

  function renderPaths() {
    var paths = filteredPaths();
    var options = [
      { value: "all", label: "All states" },
      { value: "direct", label: "Direct" },
      { value: "relay", label: "Relay" },
      { value: "degraded", label: "Degraded" },
      { value: "unreachable", label: "Unreachable" }
    ];
    var rows = paths.map(function (path) {
      var local = path.key.local;
      var remote = path.key.remote;
      var candidate = path.selected_candidate && path.selected_candidate.addr;
      var score = path.score && path.score.value;
      return '<tr><td><span class="table-primary"><span class="peer-avatar cyan">' + escapeHtml(initials(local)) + '</span><span><strong class="mono">' + escapeHtml(shortId(local)) + '</strong><small title="' + escapeHtml(local) + '">' + escapeHtml(local) + '</small></span></span></td><td><span class="table-primary"><span class="peer-avatar">' + escapeHtml(initials(remote)) + '</span><span><strong class="mono">' + escapeHtml(shortId(remote)) + '</strong><small title="' + escapeHtml(remote) + '">' + escapeHtml(remote) + '</small></span></span></td><td>' + statusPill(path.selected_state) + '</td><td class="mono">' + escapeHtml(candidate || "-") + '</td><td class="mono">' + escapeHtml(path.relay_node ? shortId(path.relay_node) : "-") + '</td><td class="mono">' + escapeHtml(score == null ? "-" : score) + '</td><td class="faint">' + escapeHtml(age(path.updated_at)) + '</td><td><button class="pin-button ' + (path.pinned ? "active" : "") + '" data-pin-local="' + escapeHtml(local) + '" data-pin-remote="' + escapeHtml(remote) + '" data-pinned="' + path.pinned + '" type="button">' + icon(path.pinned ? "pin-off" : "pin") + '<span>' + (path.pinned ? "Unpin" : "Pin") + '</span></button></td></tr>';
    }).join("");
    var tableBody = paths.length
      ? '<div class="table-wrap"><table><thead><tr><th>Local device</th><th>Remote device</th><th>State</th><th>Endpoint</th><th>Relay</th><th>Score</th><th>Updated</th><th>Control</th></tr></thead><tbody>' + rows + "</tbody></table></div>"
      : emptyState("No connections found", "Try changing the search or state filter.", "network");
    return '<section class="section-panel"><div class="section-header"><div><h2>Connections</h2><p>Selected endpoint, relay, score, and operator pin state</p></div></div>'
      + tableToolbar("paths", "Search by node or endpoint", "pathState", options, paths.length)
      + tableBody + "</section>";
  }

  function allRoutes() {
    var routes = [];
    (state.overview.nodes || []).forEach(function (entry) {
      (entry.node.routes || []).forEach(function (route) { routes.push({ node: entry.node, route: route }); });
    });
    return routes;
  }

  function renderRoutes() {
    var query = state.filters.routes.toLowerCase();
    var routes = allRoutes().filter(function (item) {
      return !query || [item.route.id, item.route.cidr, item.node.node_id, item.node.role, (item.node.tags || []).join(" ")].join(" ").toLowerCase().indexOf(query) !== -1;
    });
    var rows = routes.map(function (item) {
      return '<tr><td class="mono route-id">' + escapeHtml(item.route.id || "-") + '</td><td class="route-network">' + escapeHtml(item.route.cidr || "-") + '</td><td><button class="primary-link" data-node-id="' + escapeHtml(item.node.node_id) + '" type="button"><span class="route-owner" data-no-i18n>' + escapeHtml(shortId(item.node.node_id)) + '</span></button></td><td><span class="role-badge" data-no-i18n>' + escapeHtml(localizedRole(item.node.role)) + '</span></td><td>' + listTags(item.node.tags) + '</td><td><span class="status-pill info">Advertised</span></td></tr>';
    }).join("");
    var tableBody = routes.length
      ? '<div class="table-wrap"><table><thead><tr><th>Route ID</th><th>Network</th><th>Advertised by</th><th>Role</th><th>Tags</th><th>Status</th></tr></thead><tbody>' + rows + "</tbody></table></div>"
      : emptyState("No routes found", "Registered devices have not advertised a matching route.", "route");
    return '<section class="section-panel"><div class="section-header"><div><h2>Network routes</h2><p>Networks advertised by registered devices</p></div><span class="status-pill info">' + routes.length + " routes</span></div>"
      + tableToolbar("routes", "Search routes or owners", null, [], routes.length)
      + tableBody + "</section>";
  }

  function csvValues(value) {
    return String(value || "").split(",").map(function (item) { return item.trim(); }).filter(Boolean);
  }

  function ruleField(index, field, value, label, wide) {
    return '<div class="form-field ' + (wide ? "wide" : "") + '"><label for="rule-' + index + '-' + field + '">' + label + '</label><input id="rule-' + index + '-' + field + '" data-rule-index="' + index + '" data-rule-field="' + field + '" value="' + escapeHtml((value || []).join(", ")) + '" placeholder="Comma separated"></div>';
  }

  function renderRule(rule, index) {
    var protocols = ["any", "ip_in_ip", "tcp", "udp", "sctp", "icmp", "ipv6_encap", "gre", "esp", "ah"];
    var protocolOptions = protocols.map(function (protocol) {
      return '<option value="' + protocol + '" ' + (rule.protocol === protocol ? "selected" : "") + '>' + protocol.toUpperCase() + "</option>";
    }).join("");
    return '<article class="rule-editor"><div class="rule-heading"><div class="rule-title"><span class="rule-number">' + (index + 1) + '</span><strong data-no-i18n>' + escapeHtml(rule.id || t("Unnamed rule")) + '</strong><span class="status-pill ' + (rule.action === "deny" ? "denied" : "healthy") + '">' + t(rule.action === "deny" ? "Deny" : "Allow") + '</span></div><div class="rule-actions"><button class="icon-text-button danger" data-delete-rule="' + index + '" type="button">' + icon("trash-2") + '<span>Delete</span></button></div></div><div class="form-grid">'
      + '<div class="form-field"><label for="rule-' + index + '-id">Rule ID</label><input id="rule-' + index + '-id" data-rule-index="' + index + '" data-rule-field="id" value="' + escapeHtml(rule.id || "") + '"></div>'
      + '<div class="form-field"><label for="rule-' + index + '-action">Action</label><select id="rule-' + index + '-action" data-rule-index="' + index + '" data-rule-field="action"><option value="allow" ' + (rule.action === "allow" ? "selected" : "") + '>Allow</option><option value="deny" ' + (rule.action === "deny" ? "selected" : "") + '>Deny</option></select></div>'
      + '<div class="form-field"><label for="rule-' + index + '-protocol">Protocol</label><select id="rule-' + index + '-protocol" data-rule-index="' + index + '" data-rule-field="protocol">' + protocolOptions + "</select></div>"
      + ruleField(index, "from_roles", rule.from_roles, "From roles", false)
      + ruleField(index, "from_tags", rule.from_tags, "From tags", false)
      + ruleField(index, "to_roles", rule.to_roles, "To roles", false)
      + ruleField(index, "to_tags", rule.to_tags, "To tags", false)
      + ruleField(index, "routes", rule.routes, "Routes (CIDR)", true)
      + "</div></article>";
  }

  function renderAcl() {
    var policy = state.overview.cluster_policy || {};
    var rules = policy.acl_rules || [];
    var filteredRules = rules.filter(function (rule) {
      var query = state.filters.acl.toLowerCase();
      return !query || [rule.id, rule.action, rule.protocol, (rule.from_roles || []).join(" "), (rule.from_tags || []).join(" "), (rule.to_roles || []).join(" "), (rule.to_tags || []).join(" "), (rule.routes || []).join(" ")].join(" ").toLowerCase().indexOf(query) !== -1;
    });
    var ruleMarkup = filteredRules.map(function (rule) { return renderRule(rule, rules.indexOf(rule)); }).join("");
    if (!ruleMarkup) ruleMarkup = '<div class="empty-state-card">' + icon("shield-check") + '<strong>No matching access rules</strong><p>Use Add rule to define a new policy entry.</p></div>';
    return '<div class="access-layout"><section class="section-panel policy-controls"><div class="section-header"><div><h2>Policy settings</h2><p>Runtime connectivity posture</p></div><span class="status-pill info">' + rules.length + ' rules</span></div><div class="section-body"><div class="toggle-list">'
      + toggleRow("allow_ipv6_direct", "IPv6 direct", "Permit direct IPv6 candidates", policy.allow_ipv6_direct)
      + toggleRow("allow_nat_traversal", "NAT traversal", "Use endpoint discovery and traversal", policy.allow_nat_traversal)
      + toggleRow("allow_relay_fallback", "Relay fallback", "Use relay when direct paths fail", policy.allow_relay_fallback)
      + '</div><div class="policy-numbers"><div class="form-field"><label for="idle-timeout">Idle timeout (seconds)</label><input id="idle-timeout" type="number" min="1" value="' + escapeHtml(policy.idle_timeout_seconds) + '"></div><div class="form-field"><label for="endpoint-ttl">Endpoint TTL (seconds)</label><input id="endpoint-ttl" type="number" min="1" value="' + escapeHtml(policy.endpoint_candidate_ttl_seconds) + '"></div><div class="form-field"><label for="path-ttl">Path TTL (seconds)</label><input id="path-ttl" type="number" min="1" value="' + escapeHtml(policy.path_state_ttl_seconds) + '"></div></div><div class="form-actions"><button class="button button-primary" id="save-policy" type="button">' + icon("save") + '<span>Save policy</span></button></div></div></section><section class="section-panel"><div class="section-header"><div><h2>Access rules</h2><p>Match identities, tags, routes, and protocol</p></div><div class="section-header-actions"><label class="search-field"><span data-icon="search"></span><input type="search" data-filter="acl" value="' + escapeHtml(state.filters.acl) + '" placeholder="Filter rules" aria-label="Filter access rules"></label><button class="button button-secondary button-small" id="add-rule" type="button">' + icon("plus") + '<span>Add rule</span></button></div></div><div class="rule-list">' + ruleMarkup + "</div></section></div>";
  }

  function toggleRow(field, label, description, checked) {
    return '<label class="toggle-row"><span class="toggle-copy"><strong>' + label + '</strong><small>' + description + '</small></span><span><input class="switch-input" type="checkbox" data-policy-boolean="' + field + '" ' + (checked ? "checked" : "") + '><span class="switch"></span></span></label>';
  }

  function enrollmentToggle(field, label, description, checked) {
    return '<label class="toggle-row enrollment-toggle"><span class="toggle-copy"><strong>' + label
      + '</strong><small>' + description + '</small></span><span><input class="switch-input" type="checkbox" data-enrollment-field="'
      + field + '" ' + (checked ? "checked" : "") + '><span class="switch"></span></span></label>';
  }

  function renderEnrollmentModeSwitch(enrollment) {
    var modes = [];
    if (state.config.node_enrollment_enabled) {
      modes.push('<button class="segmented-option ' + (enrollment.mode === "linux" ? "active" : "") + '" data-enrollment-mode="linux" type="button">' + icon("server") + '<span>Linux node</span></button>');
    }
    if (state.config.client_enrollment_enabled) {
      modes.push('<button class="segmented-option ' + (enrollment.mode === "macos" ? "active" : "") + '" data-enrollment-mode="macos" type="button">' + icon("shield-check") + '<span>macOS client</span></button>');
    }
    return '<div class="segmented-control enrollment-mode" role="group" aria-label="Device type">' + modes.join("") + '</div>';
  }

  function renderLinuxEnrollmentResult(result) {
    var tokenJson = JSON.stringify(result.token);
    return '<section class="section-panel enrollment-result"><div class="section-header"><div><h2>' + icon("circle-check")
      + '<span>Install command</span></h2><p>Run this command as a user with sudo access on the new Linux server.</p></div><span class="status-pill healthy">Ready</span></div>'
      + '<div class="section-body"><div class="secret-notice">' + icon("key") + '<span>Treat this token as a secret. It is not stored by this browser.</span></div>'
      + '<div class="command-block"><code>' + escapeHtml(result.install_command) + '</code><button class="icon-button command-copy" data-copy-enrollment="command" type="button" aria-label="Copy command" title="Copy command">' + icon("copy") + '</button></div>'
      + '<div class="enrollment-result-meta"><div><span>Expires</span><strong>' + escapeHtml(formatTime(result.expires_at)) + '</strong></div><div><span>Uses</span><strong>' + escapeHtml(result.max_uses) + '</strong></div><div><span>Architecture</span><strong>' + escapeHtml(result.architecture) + '</strong></div></div>'
      + '<div class="enrollment-actions"><button class="button button-primary" data-copy-enrollment="command" type="button">' + icon("copy") + '<span>Copy command</span></button><button class="button button-secondary" id="download-enrollment-script" type="button">' + icon("download") + '<span>Download script</span></button><button class="button button-secondary" id="reset-enrollment" type="button"><span>Create another</span></button></div>'
      + '<details class="token-details"><summary>Enrollment token</summary><div class="token-detail-body"><p>Treat this token as a secret. It is not stored by this browser.</p><pre>' + escapeHtml(tokenJson) + '</pre><button class="button button-secondary button-small" data-copy-enrollment="token" type="button">' + icon("copy") + '<span>Copy token</span></button></div></details></div></section>';
  }

  function renderClientEnrollmentResult(result) {
    var tokenJson = JSON.stringify(result.token);
    return '<section class="section-panel enrollment-result"><div class="section-header"><div><h2>' + icon("circle-check")
      + '<span>Enrollment link</span></h2><p>Open this link on the Mac where HeteroNetwork is installed.</p></div><span class="status-pill healthy">Ready</span></div>'
      + '<div class="section-body"><div class="secret-notice">' + icon("key") + '<span>Treat this token as a secret. It is not stored by this browser.</span></div>'
      + '<div class="command-block enrollment-link-block"><code>' + escapeHtml(result.enrollment_uri) + '</code><button class="icon-button command-copy" data-copy-enrollment="link" type="button" aria-label="Copy link" title="Copy link">' + icon("copy") + '</button></div>'
      + '<div class="enrollment-result-meta"><div><span>Expires</span><strong>' + escapeHtml(formatTime(result.expires_at)) + '</strong></div><div><span>Uses</span><strong>1</strong></div><div><span>Platform</span><strong>macOS</strong></div></div>'
      + '<div class="enrollment-actions"><a class="button button-primary" href="' + escapeHtml(result.enrollment_uri) + '">' + icon("external-link") + '<span>Open HeteroNetwork</span></a><button class="button button-secondary" data-copy-enrollment="link" type="button">' + icon("copy") + '<span>Copy link</span></button><button class="button button-secondary" id="reset-enrollment" type="button"><span>Create another</span></button></div>'
      + '<details class="token-details"><summary>Enrollment token</summary><div class="token-detail-body"><p>Treat this token as a secret. It is not stored by this browser.</p><pre>' + escapeHtml(tokenJson) + '</pre><button class="button button-secondary button-small" data-copy-enrollment="token" type="button">' + icon("copy") + '<span>Copy token</span></button></div></details></div></section>';
  }

  function renderLinuxEnrollment(enrollment) {
    var reusableUses = enrollment.reusable
      ? '<div class="form-field"><label for="enrollment-max-uses">Maximum uses</label><input id="enrollment-max-uses" data-enrollment-field="maxUses" type="number" min="2" max="1000" value="' + escapeHtml(enrollment.maxUses) + '"></div>'
      : '';
    var form = '<section class="section-panel enrollment-wizard"><div class="enrollment-step"><div class="step-marker">1</div><div class="step-content"><div class="step-heading"><h2>1. Device settings</h2><p>Choose the identity and capabilities assigned at enrollment.</p></div><div class="form-grid enrollment-form-grid"><div class="form-field"><label for="enrollment-role">Device role</label><select id="enrollment-role" data-enrollment-field="role"><option value="edge" ' + (enrollment.role === "edge" ? "selected" : "") + '>Edge</option><option value="worker" ' + (enrollment.role === "worker" ? "selected" : "") + '>Worker</option><option value="gateway" ' + (enrollment.role === "gateway" ? "selected" : "") + '>Gateway</option></select></div><div class="form-field wide"><label for="enrollment-tags">Tags (comma separated)</label><input id="enrollment-tags" data-enrollment-field="tags" value="' + escapeHtml(enrollment.tags) + '" placeholder="example: production, linux"></div></div>'
      + enrollmentToggle("allowRelay", "Allow relay service", "Permit this node to advertise relay capability.", enrollment.allowRelay) + '</div></div>'
      + '<div class="enrollment-step"><div class="step-marker">2</div><div class="step-content"><div class="step-heading"><h2>2. Authentication key</h2><p>Limit how long and how many times the enrollment token can be used.</p></div>'
      + enrollmentToggle("reusable", "Reusable", "Allow more than one device to use this token.", enrollment.reusable)
      + '<div class="form-grid enrollment-form-grid"><div class="form-field"><label for="enrollment-expiration">Expiration (days)</label><input id="enrollment-expiration" data-enrollment-field="expirationDays" type="number" min="1" max="30" value="' + escapeHtml(enrollment.expirationDays) + '"></div>' + reusableUses + '</div></div></div>'
      + '<div class="enrollment-step enrollment-generate-step"><div class="step-marker">3</div><div class="step-content"><div class="step-heading"><h2>3. Generate install script</h2><p>The command installs the signed Linux amd64 agent, enrolls once, removes the token, and starts systemd.</p></div><button class="button button-primary" id="generate-enrollment" type="button" ' + (enrollment.generating ? "disabled" : "") + '>' + icon(enrollment.generating ? "refresh-cw" : "terminal") + '<span>' + (enrollment.generating ? "Generating..." : "Generate install script") + '</span></button></div></div></section>';
    return '<div class="enrollment-intro"><span class="eyebrow">HETERONETWORK</span><h2>Add a Linux server</h2><p>Generate a secure install command for a new HeteroNetwork node.</p></div>'
      + renderEnrollmentModeSwitch(enrollment) + form
      + (enrollment.result ? renderLinuxEnrollmentResult(enrollment.result) : "");
  }

  function renderClientEnrollment(enrollment) {
    var form = '<section class="section-panel enrollment-wizard"><div class="enrollment-step"><div class="step-marker">1</div><div class="step-content"><div class="step-heading"><h2>1. Token lifetime</h2><p>The client token can be used once and cannot advertise routes or relay traffic.</p></div><div class="form-grid enrollment-form-grid"><div class="form-field"><label for="client-enrollment-expiration">Expiration (days)</label><input id="client-enrollment-expiration" data-enrollment-field="clientExpirationDays" type="number" min="1" max="30" value="' + escapeHtml(enrollment.clientExpirationDays) + '"></div></div></div></div>'
      + '<div class="enrollment-step enrollment-generate-step"><div class="step-marker">2</div><div class="step-content"><div class="step-heading"><h2>2. Generate enrollment link</h2></div><button class="button button-primary" id="generate-enrollment" type="button" ' + (enrollment.generating ? "disabled" : "") + '>' + icon(enrollment.generating ? "refresh-cw" : "external-link") + '<span>' + (enrollment.generating ? "Generating..." : "Generate macOS link") + '</span></button></div></div></section>';
    return '<div class="enrollment-intro"><span class="eyebrow">HETERONETWORK</span><h2>Add a macOS client</h2><p>Generate a one-use enrollment link for the native HeteroNetwork app.</p></div>'
      + renderEnrollmentModeSwitch(enrollment) + form
      + (enrollment.result ? renderClientEnrollmentResult(enrollment.result) : "");
  }

  function renderEnrollment() {
    if (!state.config || (!state.config.node_enrollment_enabled && !state.config.client_enrollment_enabled)) {
      return emptyState("Enrollment is not enabled on this control plane.", "", "key");
    }
    var enrollment = state.enrollment;
    if (enrollment.mode === "macos" && !state.config.client_enrollment_enabled) enrollment.mode = "linux";
    if (enrollment.mode === "linux" && !state.config.node_enrollment_enabled) enrollment.mode = "macos";
    return '<div class="enrollment-page">' + (enrollment.mode === "macos"
      ? renderClientEnrollment(enrollment)
      : renderLinuxEnrollment(enrollment)) + '</div>';
  }

  function updateEnrollmentField(input) {
    var field = input.dataset.enrollmentField;
    if (!field || !(field in state.enrollment)) return;
    if (input.type === "checkbox") {
      state.enrollment[field] = input.checked;
      if (field === "reusable") renderView();
      return;
    }
    if (input.type === "number") state.enrollment[field] = Number(input.value);
    else state.enrollment[field] = input.value;
  }

  function issueEnrollment() {
    var enrollment = state.enrollment;
    var days = Math.floor(Number(enrollment.mode === "macos" ? enrollment.clientExpirationDays : enrollment.expirationDays));
    var maxUses = Math.floor(Number(enrollment.maxUses));
    if (!Number.isFinite(days) || days < 1 || days > 30) {
      toast("Expiration must be between 1 and 30 days.", "error");
      return Promise.resolve();
    }
    if (enrollment.mode === "linux" && enrollment.reusable && (!Number.isFinite(maxUses) || maxUses < 2 || maxUses > 1000)) {
      toast("Maximum uses must be between 2 and 1000.", "error");
      return Promise.resolve();
    }
    enrollment.generating = true;
    enrollment.result = null;
    renderView();
    var path = enrollment.mode === "macos" ? "/v1/admin/client-enrollment" : "/v1/admin/enrollment";
    var body = enrollment.mode === "macos" ? {
      expires_in_seconds: days * 24 * 60 * 60
    } : {
      expires_in_seconds: days * 24 * 60 * 60,
      role: enrollment.role,
      tags: csvValues(enrollment.tags),
      allow_relay: enrollment.allowRelay,
      reusable: enrollment.reusable,
      max_uses: enrollment.reusable ? maxUses : 1
    };
    return api(path, {
      method: "POST",
      body: JSON.stringify(body)
    }).then(function (result) {
      enrollment.result = result;
      toast(enrollment.mode === "macos" ? "macOS enrollment token issued." : "Enrollment token issued.");
    }).catch(function (error) {
      toast(error.message, "error");
      setStatus(error.message, true);
    }).finally(function () {
      enrollment.generating = false;
      renderView();
    });
  }

  function copyText(value) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(value);
    var input = document.createElement("textarea");
    input.value = value;
    input.setAttribute("readonly", "");
    input.style.position = "fixed";
    input.style.opacity = "0";
    document.body.appendChild(input);
    input.select();
    var copied = document.execCommand("copy");
    input.remove();
    return copied ? Promise.resolve() : Promise.reject(new Error("Copy failed"));
  }

  function copyEnrollment(kind) {
    var result = state.enrollment.result;
    if (!result) return;
    var value = kind === "token" ? JSON.stringify(result.token)
      : kind === "link" ? result.enrollment_uri : result.install_command;
    copyText(value).then(function () {
      toast(kind === "token" ? "Token copied." : kind === "link" ? "Link copied." : "Command copied.");
    }).catch(function (error) { toast(error.message, "error"); });
  }

  function downloadEnrollmentScript() {
    var result = state.enrollment.result;
    if (!result) return;
    var url = URL.createObjectURL(new Blob([result.install_script], { type: "text/x-shellscript;charset=utf-8" }));
    var link = document.createElement("a");
    link.href = url;
    link.download = "install-heteronetwork.sh";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    toast("Install script downloaded.");
  }

  function renderView() {
    if (!state.overview) return;
    var metadata = {
      overview: ["Overview", "Network health at a glance."],
      nodes: ["Devices", "Registered nodes and their current health."],
      services: ["Public nodes", "Lease-backed control and traversal services."],
      paths: ["Connections", "Selected paths and operator controls."],
      routes: ["Network routes", "Advertised networks and their owners."],
      acl: ["Access control", "Runtime connectivity policy and rules."],
      enrollment: ["Add device", "Issue a short-lived token and install a node with one command."]
    }[state.activeView];
    if (state.activeView === "enrollment" && state.enrollment.mode === "macos") {
      metadata = ["Add device", "Issue a one-use link for the native macOS client."];
    }
    $("view-title").textContent = t(metadata[0]);
    $("view-subtitle").textContent = t(metadata[1]);
    $("breadcrumb-current").textContent = t(metadata[0]);
    $("view-content").innerHTML = {
      overview: renderOverview,
      nodes: renderNodes,
      services: renderServices,
      paths: renderPaths,
      routes: renderRoutes,
      acl: renderAcl,
      enrollment: renderEnrollment
    }[state.activeView]();
    document.querySelectorAll(".nav-button").forEach(function (button) {
      button.classList.toggle("active", button.dataset.view === state.activeView);
    });
    decorateIcons($("view-content"));
    translateTree($("view-content"));
  }

  function findNode(nodeId) {
    return (state.overview.nodes || []).find(function (entry) { return entry.node.node_id === nodeId; });
  }

  function openNodeDrawer(nodeId) {
    var entry = findNode(nodeId);
    if (!entry) return;
    var node = entry.node;
    var health = entry.health || {};
    var paths = (state.overview.paths || []).filter(function (path) { return path.key.local === nodeId || path.key.remote === nodeId; });
    var routes = node.routes || [];
    state.selectedNodeId = nodeId;
    $("drawer-root").innerHTML = '<div class="drawer-backdrop" data-close-drawer></div><aside class="drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-title"><header class="drawer-header"><div><h2 id="drawer-title">Device details</h2><span class="drawer-subtitle">Registered node</span></div><button class="drawer-close" data-close-drawer type="button" aria-label="Close device details" title="Close">' + icon("x") + '</button></header><div class="drawer-body"><div class="drawer-identity" data-no-i18n><span class="peer-avatar">' + escapeHtml(initials(node.node_id)) + '</span><div><strong>' + escapeHtml(shortId(node.node_id)) + '</strong><small>' + escapeHtml(node.node_id) + '</small></div></div><div class="drawer-section" style="border-top:0;margin-top:0;padding-top:0"><span class="status-pill ' + statusClass(health.state) + '">' + escapeHtml(pretty(health.state || "unknown")) + '</span></div><dl class="detail-list"><dt>VPN address</dt><dd class="mono">' + escapeHtml(node.vpn_ip) + '</dd><dt>Role</dt><dd data-no-i18n>' + escapeHtml(localizedRole(node.role)) + '</dd><dt>Last seen</dt><dd>' + escapeHtml(formatTime(health.last_seen_at)) + '</dd><dt>Registered</dt><dd>' + escapeHtml(formatTime(node.registered_at)) + '</dd><dt>Relay capability</dt><dd>' + escapeHtml(node.relay_capability ? "Available" : "No") + '</dd><dt>Connections</dt><dd>' + paths.length + '</dd></dl><div class="drawer-section"><h3>Tags</h3>' + listTags(node.tags) + '</div><div class="drawer-section"><h3>Advertised routes</h3>' + (routes.length ? '<div class="chip-list">' + routes.map(function (route) { return '<span class="tag mono">' + escapeHtml(route.cidr) + '</span>'; }).join("") + '</div>' : '<span class="faint">None</span>') + '</div><div class="drawer-actions"><button class="button button-danger" data-remove-node="' + escapeHtml(node.node_id) + '" type="button">' + icon("trash-2") + '<span>Remove device</span></button></div></div></aside>';
    var connectivity = connectivityInfo(entry);
    var profile = connectivity.profile || {};
    var natSection = document.createElement("div");
    natSection.className = "drawer-section nat-detail-section";
    natSection.innerHTML = '<h3>Connectivity</h3><div class="drawer-connectivity"><span class="topology-state topology-' + connectivity.state + '">' + escapeHtml(connectivity.label) + '</span><span>' + escapeHtml(connectivity.detail) + '</span></div><dl class="detail-list compact-detail-list"><dt>Observed endpoint</dt><dd class="mono">' + escapeHtml(connectivity.observed || "-") + '</dd><dt>Mapping</dt><dd>' + escapeHtml(pretty(profile.mapping_behavior || profile.mapping || "not reported")) + '</dd><dt>Filtering</dt><dd>' + escapeHtml(pretty(profile.filtering_behavior || profile.filtering || "not reported")) + '</dd><dt>Traversal</dt><dd>' + escapeHtml(pretty(profile.strategy || "not reported")) + '</dd><dt>Confidence</dt><dd>' + escapeHtml(connectivity.confidence == null ? "-" : connectivity.confidence + "%") + '</dd></dl>';
    var drawerActions = $("drawer-root").querySelector(".drawer-actions");
    if (drawerActions) drawerActions.parentNode.insertBefore(natSection, drawerActions);
    decorateIcons($("drawer-root"));
    translateTree($("drawer-root"));
  }

  function closeDrawer() {
    state.selectedNodeId = null;
    $("drawer-root").innerHTML = "";
    if (state.overview) renderView();
  }

  function removeNode(nodeId) {
    if (!window.confirm("Remove device " + shortId(nodeId) + " from this cluster?")) return;
    return api("/v1/admin/nodes/" + encodeURIComponent(nodeId), { method: "DELETE" }).then(function () {
      closeDrawer();
      toast("Device removed.");
      return loadOverview();
    }).catch(function (error) {
      setStatus(error.message, true);
      toast(error.message, "error");
    });
  }

  function pinPath(local, remote, pinned) {
    return api("/v1/admin/paths/" + encodeURIComponent(local) + "/" + encodeURIComponent(remote) + "/pin", {
      method: "POST",
      body: JSON.stringify({ pinned: pinned })
    }).then(function () {
      toast(pinned ? "Path pinned." : "Path unpinned.");
      return loadOverview();
    }).catch(function (error) {
      setStatus(error.message, true);
      toast(error.message, "error");
    });
  }

  function updatePolicyFromForm() {
    var policy = state.overview.cluster_policy;
    document.querySelectorAll("[data-policy-boolean]").forEach(function (input) {
      policy[input.dataset.policyBoolean] = input.checked;
    });
    policy.idle_timeout_seconds = Number($("idle-timeout").value);
    policy.endpoint_candidate_ttl_seconds = Number($("endpoint-ttl").value);
    policy.path_state_ttl_seconds = Number($("path-ttl").value);
  }

  function updateRuleField(input) {
    var index = Number(input.dataset.ruleIndex);
    var field = input.dataset.ruleField;
    var rule = state.overview.cluster_policy.acl_rules[index];
    if (!rule) return;
    rule[field] = ["from_roles", "from_tags", "to_roles", "to_tags", "routes"].indexOf(field) !== -1 ? csvValues(input.value) : input.value;
  }

  function savePolicy() {
    updatePolicyFromForm();
    var button = $("save-policy");
    if (button) button.disabled = true;
    setStatus("Saving policy...");
    return api("/v1/admin/policy", { method: "PUT", body: JSON.stringify({ cluster_policy: state.overview.cluster_policy }) }).then(function (response) {
      state.overview.cluster_policy = response.cluster_policy;
      state.policyDirty = false;
      setStatus("");
      toast("Policy saved.");
      renderView();
      updateNavigationCounts();
    }).catch(function (error) {
      setStatus(error.message, true);
      toast(error.message, "error");
    }).finally(function () {
      if (button) button.disabled = false;
    });
  }

  function addRule() {
    state.overview.cluster_policy.acl_rules.push({
      id: "rule-" + Date.now(),
      from_roles: [],
      from_tags: [],
      to_roles: [],
      to_tags: [],
      routes: [],
      protocol: "any",
      action: "allow"
    });
    state.policyDirty = true;
    state.filters.acl = "";
    toast("Rule added locally.");
    renderView();
  }

  function deleteRule(index) {
    state.overview.cluster_policy.acl_rules.splice(index, 1);
    state.policyDirty = true;
    toast("Rule deleted locally. Save policy to apply it.");
    renderView();
  }

  function signOut() {
    var provider = state.config && state.config.provider;
    var logoutEndpoint = state.config && state.config.logout_endpoint;
    clearSession();
    if (logoutEndpoint && state.config.client_id) {
      var params = new URLSearchParams({ client_id: state.config.client_id });
      params.set(provider === "cognito" ? "logout_uri" : "post_logout_redirect_uri", location.origin + "/ui/");
      location.assign(logoutEndpoint + "?" + params.toString());
      return;
    }
    showAuth("");
  }

  function closeMobileNav() {
    state.mobileNavOpen = false;
    $("sidebar").classList.remove("mobile-open");
    $("mobile-backdrop").hidden = true;
  }

  function toggleMobileNav() {
    state.mobileNavOpen = !state.mobileNavOpen;
    $("sidebar").classList.toggle("mobile-open", state.mobileNavOpen);
    $("mobile-backdrop").hidden = !state.mobileNavOpen;
  }

  function toggleSidebar() {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    document.documentElement.classList.toggle("sidebar-collapsed", state.sidebarCollapsed);
    localStorage.setItem("heteronetwork_sidebar_collapsed", state.sidebarCollapsed);
    $("sidebar-toggle").setAttribute("aria-label", t(state.sidebarCollapsed ? "Expand navigation" : "Collapse navigation"));
    $("sidebar-toggle").setAttribute("title", t(state.sidebarCollapsed ? "Expand navigation" : "Collapse navigation"));
  }

  function handleFilterInput(input) {
    var key = input.dataset.filter;
    if (!key || !(key in state.filters)) return;
    var cursor = input.selectionStart;
    state.filters[key] = input.value;
    renderView();
    var replacement = document.querySelector('[data-filter="' + key + '"]');
    if (replacement) {
      replacement.focus();
      try { replacement.setSelectionRange(cursor, cursor); } catch (_) { /* Search inputs may not expose a selection. */ }
    }
  }

  document.addEventListener("input", function (event) {
    if (event.target.matches("[data-enrollment-field]")) {
      updateEnrollmentField(event.target);
      return;
    }
    if (event.target.matches("[data-filter]")) {
      handleFilterInput(event.target);
      return;
    }
    if (event.target.matches("[data-rule-index][data-rule-field]")) {
      updateRuleField(event.target);
      state.policyDirty = true;
      return;
    }
    if (event.target.matches("[data-policy-boolean], #idle-timeout, #endpoint-ttl, #path-ttl")) {
      updatePolicyFromForm();
      state.policyDirty = true;
    }
  });

  document.addEventListener("change", function (event) {
    if (event.target.matches("#locale-select")) {
      setLocale(event.target.value);
      return;
    }
    if (event.target.matches("[data-enrollment-field]")) {
      updateEnrollmentField(event.target);
      return;
    }
    if (event.target.matches("[data-filter]")) {
      state.filters[event.target.dataset.filter] = event.target.value;
      renderView();
      return;
    }
    if (event.target.matches("[data-rule-index][data-rule-field]")) {
      updateRuleField(event.target);
      state.policyDirty = true;
      return;
    }
    if (event.target.matches("[data-policy-boolean], #idle-timeout, #endpoint-ttl, #path-ttl")) {
      updatePolicyFromForm();
      state.policyDirty = true;
    }
  });

  document.addEventListener("click", function (event) {
    var enrollmentMode = event.target.closest("[data-enrollment-mode]");
    if (enrollmentMode) {
      state.enrollment.mode = enrollmentMode.dataset.enrollmentMode;
      state.enrollment.result = null;
      renderView();
      return;
    }
    var nav = event.target.closest("[data-view]");
    if (nav) {
      state.activeView = nav.dataset.view;
      closeMobileNav();
      renderView();
      return;
    }
    var navigate = event.target.closest("[data-navigate]");
    if (navigate) {
      state.activeView = navigate.dataset.navigate;
      renderView();
      return;
    }
    var node = event.target.closest("[data-node-id]");
    if (node) {
      openNodeDrawer(node.dataset.nodeId);
      return;
    }
    if (event.target.closest("[data-close-drawer]")) {
      closeDrawer();
      return;
    }
    var remove = event.target.closest("[data-remove-node]");
    if (remove) {
      removeNode(remove.dataset.removeNode);
      return;
    }
    var pin = event.target.closest("[data-pin-local]");
    if (pin) {
      pinPath(pin.dataset.pinLocal, pin.dataset.pinRemote, pin.dataset.pinned !== "true");
      return;
    }
    var deleteButton = event.target.closest("[data-delete-rule]");
    if (deleteButton) {
      deleteRule(Number(deleteButton.dataset.deleteRule));
      return;
    }
    if (event.target.closest("#refresh-button") || event.target.closest("#refresh-button-top")) {
      loadOverview();
      return;
    }
    if (event.target.closest("#save-policy")) {
      savePolicy();
      return;
    }
    if (event.target.closest("#add-rule")) {
      addRule();
      return;
    }
    if (event.target.closest("#generate-enrollment")) {
      issueEnrollment();
      return;
    }
    var enrollmentCopy = event.target.closest("[data-copy-enrollment]");
    if (enrollmentCopy) {
      copyEnrollment(enrollmentCopy.dataset.copyEnrollment);
      return;
    }
    if (event.target.closest("#download-enrollment-script")) {
      downloadEnrollmentScript();
      return;
    }
    if (event.target.closest("#reset-enrollment")) {
      state.enrollment.result = null;
      renderView();
      return;
    }
    if (event.target.closest("#mobile-menu")) {
      toggleMobileNav();
      return;
    }
    if (event.target.closest("#mobile-backdrop")) {
      closeMobileNav();
      return;
    }
    if (event.target.closest("#sidebar-toggle")) {
      toggleSidebar();
      return;
    }
    if (event.target.closest("#theme-toggle")) {
      applyTheme(state.theme === "dark" ? "light" : "dark", true);
      return;
    }
  });

  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      closeMobileNav();
      if ($("drawer-root").firstElementChild) closeDrawer();
    }
  });

  $("oidc-login").addEventListener("click", function () {
    startLogin().catch(function (error) { $("auth-error").textContent = error.message; });
  });

  $("token-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var token = $("operator-token").value.trim();
    if (!token) return;
    state.token = token;
    sessionStorage.setItem("heteronetwork_operator_token", token);
    loadOverview();
  });

  $("auth-button").addEventListener("click", function () {
    if (state.token) signOut();
    else showAuth("");
  });

  document.documentElement.classList.toggle("sidebar-collapsed", state.sidebarCollapsed);
  $("locale-select").value = state.locale;
  applyStaticTranslations();
  applyTheme(state.theme, false);
  decorateIcons(document);
  $("sidebar-toggle").setAttribute("aria-label", t(state.sidebarCollapsed ? "Expand navigation" : "Collapse navigation"));
  $("sidebar-toggle").setAttribute("title", t(state.sidebarCollapsed ? "Expand navigation" : "Collapse navigation"));

  setInterval(function () {
    if (state.token && !state.loading && !state.policyDirty) loadOverview();
  }, 10000);

  loadConfig().then(function () {
    return exchangeCode();
  }).then(function (exchanged) {
    if (!state.token && !exchanged) {
      showAuth("");
      return;
    }
    return loadOverview();
  }).catch(function (error) {
    showAuth(error.message);
  });
})();
