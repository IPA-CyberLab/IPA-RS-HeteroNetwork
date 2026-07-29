(function () {
  "use strict";

  var ICONS = {
    "layout-dashboard": '<rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/>',
    server: '<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>',
    network: '<rect width="6" height="6" x="3" y="3" rx="1"/><rect width="6" height="6" x="15" y="15" rx="1"/><path d="M9 6h3a3 3 0 0 1 3 3v6"/><path d="M15 18h-3a3 3 0 0 1-3-3V9"/>',
    blocks: '<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><path d="M10 6.5h4"/><path d="M6.5 10v4"/><path d="M17.5 10v4"/><path d="M10 17.5h4"/>',
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
    "zoom-in": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/><path d="M11 8v6"/><path d="M8 11h6"/>',
    "zoom-out": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/><path d="M8 11h6"/>',
    "maximize-2": '<polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" x2="14" y1="3" y2="10"/><line x1="3" x2="10" y1="21" y2="14"/>',
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
    "Node services": "ノードサービス",
    "Connections": "接続",
    "Connection": "接続",
    "Overlay topology": "オーバーレイトポロジー",
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
    "Complete sign-in with code": "次のコードでログインを完了してください:",
    "Device sign-in expired": "デバイスログインの有効期限が切れました",
    "Device sign-in failed": "デバイスログインに失敗しました",
    "Gateway ready": "ゲートウェイ稼働中",
    "Gateway provisioning": "ゲートウェイ準備中",
    "Gateway standby": "ゲートウェイ待機中",
    "Gateway error": "ゲートウェイ異常",
    "Operator token": "オペレータートークン",
    "Paste a bearer token": "Bearer トークンを貼り付け",
    "Connect": "接続",
    "Session protected by the control plane": "セッションはコントロールプレーンで保護されています",
    "Live": "ライブ",
    "Refresh": "更新",
    "Network health at a glance.": "ネットワーク全体の状態を確認します。",
    "Registered nodes and their current health.": "登録済みノードと現在の状態を確認します。",
    "Lease-backed control and traversal services.": "リースで冗長化された制御・トラバーサルサービスです。",
    "Active service leases on registered nodes and infrastructure hosts.": "登録済みノードとインフラホスト上の有効なサービスリースを確認します。",
    "Selected paths and operator controls.": "選択中の経路とオペレーター制御です。",
    "Recursive groups and forwarding links.": "再帰グループと転送リンクを確認します。",
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
    "Web UI": "Web UI",
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
    "Node / host": "ノード / ホスト",
    "Agent health": "エージェント状態",
    "Hosts": "ホスト",
    "Lease active": "リース有効",
    "No active lease": "有効なリースなし",
    "Not advertised": "未広報",
    "Not registered": "未登録",
    "No lease": "リースなし",
    "Single host": "単一ホスト",
    "Infrastructure host": "インフラホスト",
    "Host ID": "ホスト ID",
    "Unmatched owner": "未対応の所有ノード",
    "Node service leases": "ノード別サービスリース",
    "Registered nodes and unmatched infrastructure hosts.": "登録済みノードと、登録ノードに対応しないインフラホストを表示します。",
    "No nodes or infrastructure hosts": "ノードまたはインフラホストはありません",
    "Register a node or advertise an infrastructure service lease.": "ノードを登録するか、インフラサービスのリースを広報してください。",
    "No public nodes": "公開ノードはありません",
    "No active public service lease is registered.": "有効な公開サービスリースは登録されていません。",
    "Service matrix": "サービスマトリクス",
    "Active lease directory": "有効なリースディレクトリ",
    "All statuses": "すべての状態",
    "Healthy": "正常",
    "Unhealthy": "異常",
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
    "2. Authentication key": "2. 認証キー",
    "Limit how long and how many times the enrollment token can be used.": "登録トークンの有効期間と利用回数を制限します。",
    "Reusable": "再利用可能",
    "Allow more than one device to use this token.": "複数デバイスでこのトークンを使用できるようにします。",
    "Expiration (days)": "有効期限 (日)",
    "Maximum uses": "最大利用回数",
    "3. Generate install script": "3. インストールスクリプトを生成",
    "The command installs the signed Linux amd64 agent, removes the token after enrollment, and automatically schedules the network and database HA services.": "署名済み Linux amd64 エージェントを導入し、登録後にトークンを削除して、ネットワークとデータベースの HA サービスを自動構成します。",
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
    "Desktop client": "デスクトップクライアント",
    "Add a desktop client": "デスクトップクライアントを追加",
    "Generate a one-use enrollment link for the native HeteroNetwork app.": "HeteroNetwork ネイティブアプリ用の単回登録リンクを生成します。",
    "1. Token lifetime": "1. トークン有効期間",
    "The client token can be used once and cannot advertise routes or relay traffic.": "クライアントトークンは 1 回だけ使用でき、ルートやリレートラフィックを広報できません。",
    "2. Generate enrollment link": "2. 登録リンクを生成",
    "Generate desktop link": "デスクトップリンクを生成",
    "Enrollment link": "登録リンク",
    "Open this link on the Mac or Windows PC where HeteroNetwork is installed.": "HeteroNetwork をインストールした Mac または Windows PC でこのリンクを開いてください。",
    "Copy link": "リンクをコピー",
    "Open HeteroNetwork": "HeteroNetwork を開く",
    "Platform": "プラットフォーム",
    "Link copied.": "リンクをコピーしました。",
    "Desktop enrollment token issued.": "デスクトップ登録トークンを発行しました。",
    "Device type": "デバイスタイプ",
    "Issue a one-use link for the native desktop clients.": "ネイティブデスクトップクライアント用の単回リンクを発行します。",
    "Web UI node": "Web UI ノード",
    "Check Web UI nodes": "Web UI ノードを確認",
    "Remove Web UI node": "Web UI ノードを削除",
    "Web UI address": "Web UI アドレス",
    "IP address or URL": "IP アドレスまたは URL",
    "Connect to your network": "ネットワークに接続",
    "Enter the first reachable Web UI IP address or URL.": "最初に到達可能な Web UI の IP アドレスまたは URL を入力してください。",
    "Reachable": "到達可能",
    "Unreachable": "到達不可",
    "Checking": "確認中",
    "Remove this manually added Web UI endpoint?": "手動追加した Web UI エンドポイントを削除しますか？",
    "Runtime overlay policy": "実行時オーバーレイポリシー",
    "Group fanout": "グループファンアウト",
    "Maximum children or nodes assigned to each group.": "各グループに割り当てる子グループまたはノードの上限です。",
    "Max peer degree": "最大ピア次数",
    "Maximum hierarchy neighbors per node.": "各ノードが持つ階層近傍の上限です。",
    "Save overlay settings": "オーバーレイ設定を保存",
    "Current": "適用中",
    "Unsaved changes": "未保存の変更",
    "Loading policy...": "ポリシーを読み込み中...",
    "Policy unavailable": "ポリシーを取得できません",
    "Loading overlay topology": "オーバーレイトポロジーを読み込み中",
    "Loading group hierarchy and links.": "グループ階層とリンクを読み込んでいます。",
    "Overlay topology unavailable": "オーバーレイトポロジーを取得できません",
    "Retry": "再試行",
    "No overlay topology": "オーバーレイトポロジーはありません",
    "Nodes will appear after joining the cluster.": "ノードがクラスターに参加するとここに表示されます。",
    "Nodes": "ノード",
    "Groups": "グループ",
    "Levels": "階層数",
    "Edges": "エッジ",
    "Max degree": "最大次数",
    "Diameter": "直径",
    "Diameter estimate": "推定直径",
    "Epoch": "エポック",
    "Synthesized topology": "合成トポロジー",
    "Observed topology": "観測済みトポロジー",
    "Group hierarchy": "グループ階層",
    "Parent-child hierarchy and forwarding links": "親子階層と転送リンク",
    "Zoom out": "縮小",
    "Reset zoom": "ズームをリセット",
    "Zoom in": "拡大",
    "Zoom": "ズーム",
    "Topology legend": "トポロジー凡例",
    "Parent-child": "親子",
    "Leaf links": "リーフ内リンク",
    "Sibling links": "兄弟間リンク",
    "Partial": "一部接続",
    "Stale": "期限切れ",
    "Observed connections": "観測済み接続",
    "Path states": "経路状態",
    "Last observed": "最終観測",
    "Node health": "ノード状態",
    "Representative": "代表",
    "No representatives": "代表なし",
    "Primary": "第1代表",
    "Secondary": "第2代表",
    "Leaf": "リーフ",
    "Member": "メンバー",
    "Group details": "グループ詳細",
    "Children": "子グループ",
    "Members": "メンバー",
    "Representatives": "代表",
    "Representative assignments": "代表割り当て",
    "Plane": "プレーン",
    "Depth": "深さ",
    "Degree": "次数",
    "Algorithm": "アルゴリズム",
    "Visible groups": "表示グループ",
    "Generated": "生成日時",
    "Mermaid source": "Mermaid ソース",
    "Copy Mermaid source": "Mermaid ソースをコピー",
    "Mermaid copied.": "Mermaid ソースをコピーしました。",
    "Diagram rendering failed. Showing the fallback topology.": "図の描画に失敗したため、フォールバックトポロジーを表示しています。",
    "Overlay settings saved.": "オーバーレイ設定を保存しました。",
    "Saving overlay settings...": "オーバーレイ設定を保存しています...",
    "Group fanout must be an integer between 4 and 64.": "グループファンアウトは 4 から 64 の整数で指定してください。",
    "Max peer degree must be 4 or 6.": "最大ピア次数は 4 または 6 を指定してください。",
    "Direct shortcuts must be an integer between 0 and 64.": "直接ショートカット数は 0 から 64 の整数で指定してください。"
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
    webUi: {
      endpoints: [],
      selectedUrl: null,
      publicGateway: null,
      loading: false
    },
    topology: {
      data: null,
      loading: false,
      error: "",
      policy: null,
      policyLoading: false,
      policyError: "",
      settings: null,
      dirty: false,
      saving: false,
      selectedGroupId: null,
      zoom: 1,
      mermaidInitialized: false,
      mermaidRenderSequence: 0,
      mermaidQueue: Promise.resolve(),
      mermaidCache: {
        epoch: null,
        scope: null,
        snapshot: null,
        source: null
      }
    },
    enrollment: {
      mode: "linux",
      role: "edge",
      tags: "",
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
      [/^(\d+) nodes$/, "$1 ノード"],
      [/^Depth (\d+) · Leaf$/, "深さ $1 · リーフ"],
      [/^Depth (\d+) · (\d+) nodes$/, "深さ $1 · $2 ノード"],
      [/^Depth (\d+) · (.+)$/, "深さ $1 · $2"],
      [/^Depth (\d+), (\d+) nodes$/, "深さ $1、$2 ノード"],
      [/^Depth (\d+)$/, "深さ $1"],
      [/^Plane (\d+) · Primary$/, "プレーン $1 · 第1代表"],
      [/^Plane (\d+) · Secondary$/, "プレーン $1 · 第2代表"],
      [/^Plane (\d+)$/, "プレーン $1"],
      [/^(.+) · No representatives$/, "$1 · 代表なし"],
      [/^Showing (\d+) of (\d+) descendant nodes\.$/, "配下ノード $2 台中 $1 台を表示しています。"],
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
    if (state.config.local_agent && state.config.bootstrap_required) {
      $("auth-title").textContent = t("Connect to your network");
      $("auth-copy").textContent = t("Enter the first reachable Web UI IP address or URL.");
      return;
    }
    $("auth-title").textContent = t("Sign in to your network");
    $("auth-copy").textContent = t("Use the configured identity provider to continue.");
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
    if (state.config && state.config.local_agent) renderWebUiEndpoints();
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
    if (text === "neutral" || text === "not_running" || text === "not_registered" || text === "no_lease") return "neutral";
    if (text.indexOf("unreachable") !== -1 || text.indexOf("unhealthy") !== -1 || text === "offline" || text === "denied") return "unreachable";
    if (text.indexOf("relay") !== -1) return "relay";
    if (text.indexOf("degraded") !== -1 || text.indexOf("stale") !== -1 || text.indexOf("partial") !== -1) return "degraded";
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
      var routedEndpoint = response.headers.get("X-HeteroNetwork-Web-UI-Endpoint");
      if (routedEndpoint && state.config && state.config.local_agent) {
        state.webUi.selectedUrl = routedEndpoint;
        renderWebUiEndpoints();
      }
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

  function deviceLoginPoll(handle, endpoint, delaySeconds, expiresAt) {
    if (Date.now() >= expiresAt) return Promise.reject(new Error(t("Device sign-in expired")));
    return new Promise(function (resolve) {
      setTimeout(resolve, Math.max(1, delaySeconds) * 1000);
    }).then(function () {
      return fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ handle: handle })
      });
    }).then(async function (response) {
      var body = {};
      try { body = await response.json(); } catch (_) { body = {}; }
      if (response.ok && body.status === "complete" && body.access_token) return body.access_token;
      if ((response.status === 202 || response.status === 429) && body.status === "pending") {
        return deviceLoginPoll(handle, endpoint, body.retry_after_seconds || delaySeconds, expiresAt);
      }
      throw new Error(body.error || (t("Device sign-in failed") + " (" + response.status + ")"));
    });
  }

  function startDeviceLogin() {
    var authWindow = window.open("about:blank", "_blank");
    return fetch(state.config.device_login_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}"
    }).then(async function (response) {
      var body = {};
      try { body = await response.json(); } catch (_) { body = {}; }
      if (!response.ok) throw new Error(body.error || (t("Device sign-in failed") + " (" + response.status + ")"));
      var verificationUrl = body.verification_uri_complete || body.verification_uri;
      if (authWindow && !authWindow.closed) {
        authWindow.location.replace(verificationUrl);
        authWindow.opener = null;
      } else {
        window.open(verificationUrl, "_blank", "noopener,noreferrer");
      }
      $("auth-error").textContent = t("Complete sign-in with code") + " " + body.user_code;
      return deviceLoginPoll(
        body.handle,
        state.config.device_login_poll_endpoint,
        body.interval || 5,
        Date.now() + Math.max(30, body.expires_in || 600) * 1000
      );
    }).then(function (accessToken) {
      if (authWindow && !authWindow.closed) authWindow.close();
      state.token = accessToken;
      sessionStorage.setItem("heteronetwork_access_token", accessToken);
      $("auth-error").textContent = "";
      return loadOverview();
    }).catch(function (error) {
      if (authWindow && !authWindow.closed) authWindow.close();
      throw error;
    });
  }

  function startLogin() {
    if (!state.config) return Promise.resolve();
    if (state.config.device_login_endpoint && state.config.device_login_poll_endpoint) {
      return startDeviceLogin();
    }
    if (!state.config.authorization_endpoint) return Promise.resolve();
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
      var bootstrapRequired = Boolean(config.local_agent && config.bootstrap_required);
      $("web-ui-bootstrap-form").hidden = !bootstrapRequired;
      $("oidc-login").hidden = bootstrapRequired || !config.auth_enabled;
      $("token-form").hidden = bootstrapRequired || !config.operator_token_enabled;
      $("web-ui-endpoint-control").hidden = !config.local_agent;
      $("enrollment-nav").hidden = !config.node_enrollment_enabled && !config.client_enrollment_enabled;
      if (bootstrapRequired && config.connection_error) {
        $("auth-error").textContent = config.connection_error;
      }
      updateAuthConfigText();
      if (config.local_agent) loadWebUiEndpoints();
    });
  }

  function localWebUiApi(path, options) {
    var request = options || {};
    var headers = new Headers(request.headers || {});
    headers.set("Accept", "application/json");
    if (request.body) headers.set("Content-Type", "application/json");
    return fetch(path, Object.assign({}, request, { headers: headers })).then(async function (response) {
      if (!response.ok) {
        var message = response.status + " " + response.statusText;
        try {
          var body = await response.json();
          if (body.error) message = body.error;
        } catch (_) {
          // Keep the HTTP status when the Agent did not return JSON.
        }
        throw new Error(message);
      }
      return response.json();
    });
  }

  function renderWebUiEndpoints() {
    var select = $("web-ui-endpoint-select");
    var endpoints = state.webUi.endpoints || [];
    if (state.webUi.loading) {
      select.innerHTML = '<option value="">' + t("Checking") + "...</option>";
      select.disabled = true;
      $("web-ui-endpoint-remove").hidden = true;
      return;
    }
    select.disabled = endpoints.length === 0;
    select.innerHTML = endpoints.length ? endpoints.map(function (endpoint) {
      var status = endpoint.reachable ? t("Reachable") : t("Unreachable");
      return '<option value="' + escapeHtml(endpoint.url) + '"'
        + (endpoint.url === state.webUi.selectedUrl ? " selected" : "") + ">"
        + escapeHtml(status + " - " + endpoint.url) + "</option>";
    }).join("") : '<option value="">' + t("Not connected") + "</option>";
    var selected = endpoints.find(function (endpoint) { return endpoint.url === select.value; });
    $("web-ui-endpoint-remove").hidden = !selected || selected.source !== "manual_seed";
    var gateway = state.webUi.publicGateway;
    var gatewayState = $("public-gateway-state");
    gatewayState.hidden = !gateway || gateway.phase === "disabled";
    if (!gatewayState.hidden) {
      var gatewayLabels = {
        ready: "Gateway ready",
        provisioning: "Gateway provisioning",
        standby: "Gateway standby",
        error: "Gateway error"
      };
      gatewayState.classList.toggle("online", gateway.phase === "ready");
      gatewayState.classList.toggle("offline", gateway.phase !== "ready");
      gatewayState.lastElementChild.textContent = t(gatewayLabels[gateway.phase] || "Gateway standby");
      gatewayState.title = gateway.last_error || gateway.url || "";
    }
  }

  function loadWebUiEndpoints() {
    if (!state.config || !state.config.local_agent || state.webUi.loading) return Promise.resolve();
    state.webUi.loading = true;
    renderWebUiEndpoints();
    return localWebUiApi("/v1/web-ui/endpoints").then(function (directory) {
      state.webUi.endpoints = directory.endpoints || [];
      state.webUi.selectedUrl = directory.selected_url || null;
      state.webUi.publicGateway = directory.public_gateway || null;
    }).catch(function (error) {
      $("auth-error").textContent = error.message;
    }).finally(function () {
      state.webUi.loading = false;
      renderWebUiEndpoints();
    });
  }

  function bootstrapWebUiEndpoint(endpoint) {
    var button = $("web-ui-bootstrap-submit");
    button.disabled = true;
    $("auth-error").textContent = "";
    return localWebUiApi("/v1/web-ui/bootstrap", {
      method: "POST",
      body: JSON.stringify({ endpoint: endpoint })
    }).then(function () {
      location.replace(location.origin + "/ui/");
    }).catch(function (error) {
      $("auth-error").textContent = error.message;
      button.disabled = false;
    });
  }

  function selectWebUiEndpoint(endpoint) {
    return localWebUiApi("/v1/web-ui/select", {
      method: "POST",
      body: JSON.stringify({ endpoint: endpoint })
    }).then(function () {
      location.reload();
    }).catch(function (error) {
      toast(error.message, "error");
      return loadWebUiEndpoints();
    });
  }

  function removeSelectedWebUiEndpoint() {
    var endpoint = $("web-ui-endpoint-select").value;
    if (!endpoint || !window.confirm(t("Remove this manually added Web UI endpoint?"))) return;
    return localWebUiApi("/v1/web-ui/endpoints", {
      method: "DELETE",
      body: JSON.stringify({ endpoint: endpoint })
    }).then(function () {
      return loadWebUiEndpoints();
    }).catch(function (error) {
      toast(error.message, "error");
    });
  }

  function buildServiceHostRows(overview) {
    var nodeEntries = Array.isArray(overview && overview.nodes) ? overview.nodes : [];
    var directory = overview && overview.service_directory || {};
    var instances = Array.isArray(directory.instances) ? directory.instances : [];
    var nodesById = Object.create(null);
    nodeEntries.forEach(function (entry) {
      var node = entry && entry.node || {};
      var nodeId = String(node.node_id || "");
      if (nodeId) nodesById[nodeId] = entry;
    });
    var hostGroupsById = Object.create(null);
    var hostGroups = [];
    instances.forEach(function (instance) {
      var ownerHostId = String(instance.owner_host_id || "legacy-unowned");
      var group = hostGroupsById[ownerHostId];
      if (!group) {
        group = {
          hostId: ownerHostId,
          leases: [],
          ownerNodeIds: []
        };
        hostGroupsById[ownerHostId] = group;
        hostGroups.push(group);
      }
      group.leases.push(instance);
      var ownerNodeId = typeof instance.owner_node_id === "string" && instance.owner_node_id
        ? instance.owner_node_id
        : null;
      if (ownerNodeId && group.ownerNodeIds.indexOf(ownerNodeId) === -1) {
        group.ownerNodeIds.push(ownerNodeId);
      }
    });
    hostGroups.forEach(function (group) {
      group.matchedNodeId = group.ownerNodeIds.find(function (nodeId) {
        return Boolean(nodesById[nodeId]);
      }) || null;
    });
    var matchedGroupsByNodeId = Object.create(null);
    hostGroups.forEach(function (group) {
      if (!group.matchedNodeId) return;
      if (!matchedGroupsByNodeId[group.matchedNodeId]) matchedGroupsByNodeId[group.matchedNodeId] = [];
      matchedGroupsByNodeId[group.matchedNodeId].push(group);
    });
    var nodeRows = [];
    nodeEntries.forEach(function (entry, index) {
      var node = entry && entry.node || {};
      var nodeId = String(node.node_id || "");
      var matchedGroups = matchedGroupsByNodeId[nodeId] || [];
      if (!matchedGroups.length) {
        nodeRows.push({
          entry: entry || { node: {}, health: {} },
          hostId: null,
          hostIds: [],
          key: "node:" + (nodeId || index),
          leases: [],
          nodeId: nodeId || "node-" + (index + 1),
          type: "node"
        });
        return;
      }
      var hostIds = matchedGroups.map(function (group) {
        return group.hostId;
      });
      nodeRows.push({
        entry: entry || { node: {}, health: {} },
        hostId: hostIds[0],
        hostIds: hostIds,
        key: "node:" + nodeId,
        leases: matchedGroups.reduce(function (leases, group) {
          return leases.concat(group.leases);
        }, []),
        nodeId: nodeId,
        type: "node"
      });
    });
    var infrastructureRows = hostGroups.filter(function (group) {
      return !group.matchedNodeId;
    }).map(function (group) {
      return {
        hostId: group.hostId,
        hostIds: [group.hostId],
        key: "host:" + group.hostId,
        leases: group.leases,
        ownerNodeId: group.ownerNodeIds[0] || null,
        type: "infrastructure"
      };
    });
    return nodeRows.concat(infrastructureRows);
  }

  function serviceEndpointsForHost(row, kind) {
    var seen = Object.create(null);
    var endpoints = [];
    row.leases.forEach(function (instance) {
      (Array.isArray(instance.endpoints) ? instance.endpoints : []).forEach(function (endpoint) {
        if (!endpoint || endpoint.kind !== kind) return;
        var url = String(endpoint.url || "");
        if (seen[url]) return;
        seen[url] = true;
        endpoints.push(url);
      });
    });
    return endpoints;
  }

  function serviceHostSummary(registeredCount, infrastructureCount) {
    if (state.locale === "ja") {
      return "登録済みノード " + registeredCount + " 台 · インフラホスト " + infrastructureCount + " 台";
    }
    return registeredCount + " registered node" + (registeredCount === 1 ? "" : "s")
      + " · " + infrastructureCount + " infrastructure host" + (infrastructureCount === 1 ? "" : "s");
  }

  function renderServiceHostIdentity(row) {
    if (row.type === "node") {
      var node = row.entry.node || {};
      return '<span class="table-primary service-host"><span class="peer-avatar">'
        + escapeHtml(initials(row.nodeId)) + '</span><span class="service-host-copy"><strong data-no-i18n title="'
        + escapeHtml(row.nodeId) + '">' + escapeHtml(shortId(row.nodeId))
        + '</strong><small class="mono" data-no-i18n title="' + escapeHtml(row.nodeId) + '">'
        + escapeHtml(row.nodeId) + '</small><small><span>Registered node</span> · <span class="mono" data-no-i18n>'
        + escapeHtml(node.vpn_ip || "-") + "</span></small>"
        + (row.hostIds.length ? '<small><span>Host ID</span>: <span class="mono" data-no-i18n title="'
          + escapeHtml(row.hostIds.join(", ")) + '">' + escapeHtml(row.hostIds.join(", ")) + "</span></small>" : "")
        + "</span></span>";
    }
    return '<span class="table-primary service-host"><span class="peer-avatar cyan">IH</span><span class="service-host-copy"><strong data-no-i18n title="'
      + escapeHtml(row.hostId) + '">' + escapeHtml(shortId(row.hostId))
      + '</strong><small class="mono" data-no-i18n title="' + escapeHtml(row.hostId) + '">'
      + escapeHtml(row.hostId) + '</small><small>Infrastructure host</small>'
      + (row.ownerNodeId ? '<small><span>Unmatched owner</span>: <span class="mono" data-no-i18n title="'
        + escapeHtml(row.ownerNodeId) + '">' + escapeHtml(shortId(row.ownerNodeId)) + "</span></small>" : "")
      + "</span></span>";
  }

  function renderAgentHealth(row) {
    if (row.type !== "node") return statusPill("not_registered", "Not registered");
    var node = row.entry.node || {};
    var health = row.entry.health || {};
    var lastSeenAt = health.last_seen_at || node.registered_at;
    return '<span class="service-agent-health">' + statusPill(health.state || "unknown")
      + (lastSeenAt ? '<small><span>Last seen</span>: <time>' + escapeHtml(age(lastSeenAt)) + "</time></small>" : "")
      + "</span>";
  }

  function renderHostService(row, kind) {
    var endpoints = serviceEndpointsForHost(row, kind);
    if (!endpoints.length) return statusPill("not_running", "No active lease");
    return '<span class="service-endpoint"><span>' + statusPill("healthy", "Lease active")
      + '</span><span class="service-endpoint-list">' + endpoints.map(function (endpoint) {
        return '<code data-no-i18n title="' + escapeHtml(endpoint) + '">' + escapeHtml(endpoint || "-") + "</code>";
      }).join("") + "</span></span>";
  }

  function renderHostLeases(row) {
    if (!row.leases.length) return statusPill("no_lease", "No lease");
    return '<span class="service-lease-list">' + row.leases.map(function (instance) {
      var instanceId = String(instance.instance_id || "-");
      return '<span class="service-lease"><span>' + statusPill("healthy", "Leased")
        + '</span><code data-no-i18n title="' + escapeHtml(instanceId) + '">' + escapeHtml(instanceId)
        + '</code><small class="faint"><span>Expires</span>: <time>'
        + escapeHtml(formatTime(instance.lease_expires_at)) + "</time></small></span>";
    }).join("") + "</span>";
  }

  function updateNavigationCounts() {
    if (!state.overview) return;
    var metrics = state.overview.metrics || {};
    $("nav-node-count").textContent = metrics.node_count == null ? "-" : metrics.node_count;
    $("nav-service-count").textContent = buildServiceHostRows(state.overview).length;
    $("nav-path-count").textContent = metrics.path_count == null ? "-" : metrics.path_count;
    $("nav-block-count").textContent = state.topology.data ? normalizedOverlayTopology().groups.length : "-";
    $("nav-rule-count").textContent = (state.overview.cluster_policy.acl_rules || []).length;
  }

  function loadOverview() {
    if (!state.token || state.loading || state.policyDirty) return Promise.resolve();
    state.loading = true;
    return api("/v1/admin/overview").then(function (overview) {
      state.overview = overview;
      $("auth-error").textContent = "";
      showDashboard();
      setConnection(true);
      $("cluster-name").textContent = overview.cluster_id;
      $("sidebar-cluster").textContent = overview.cluster_id;
      $("refresh-time").textContent = translateDynamicText("Updated " + formatTime(overview.generated_at));
      updateNavigationCounts();
      renderView();
    }).catch(function (error) {
      if (error.message !== "authentication required") {
        setStatus(error.message, true);
        if (!state.overview) $("auth-error").textContent = error.message;
      }
    }).finally(function () {
      state.loading = false;
    });
  }

  function topologyPolicyFromResponse(response) {
    if (!response || typeof response !== "object") return null;
    return response.cluster_policy || response.policy || response;
  }

  function integerSetting(value, fallback) {
    var number = Number(value);
    return Number.isFinite(number) && Math.floor(number) === number ? number : fallback;
  }

  function settingsFromTopologyPolicy(policy) {
    var snapshot = state.topology.data || {};
    var source = policy || {};
    var maxDegree = integerSetting(source.overlay_max_degree, integerSetting(snapshot.max_degree, 4));
    if ([4, 6].indexOf(maxDegree) === -1) maxDegree = 4;
    return {
      fanout: integerSetting(source.overlay_block_size, integerSetting(snapshot.fanout, 4)),
      maxDegree: maxDegree,
      shortcutLimit: integerSetting(
        source.overlay_direct_shortcut_limit,
        integerSetting(snapshot.direct_shortcut_limit, 0)
      )
    };
  }

  function renderTopologyWhenActive() {
    if (state.activeView === "topology" && state.overview) renderView();
  }

  function loadTopologyPolicy(forceSettings) {
    if (!state.token || state.topology.policyLoading) return Promise.resolve();
    state.topology.policyLoading = true;
    state.topology.policyError = "";
    renderTopologyWhenActive();
    return api("/v1/admin/policy").then(function (response) {
      var policy = topologyPolicyFromResponse(response);
      if (!policy || typeof policy !== "object") throw new Error("Policy response did not include cluster_policy");
      state.topology.policy = policy;
      if (state.overview && !state.policyDirty) state.overview.cluster_policy = policy;
      if (forceSettings || !state.topology.dirty || !state.topology.settings) {
        state.topology.settings = settingsFromTopologyPolicy(policy);
        state.topology.dirty = false;
      }
      updateNavigationCounts();
    }).catch(function (error) {
      state.topology.policyError = error.message;
      if (!state.topology.settings) {
        var overviewPolicy = state.overview && state.overview.cluster_policy;
        state.topology.settings = settingsFromTopologyPolicy(overviewPolicy);
      }
    }).finally(function () {
      state.topology.policyLoading = false;
      renderTopologyWhenActive();
    });
  }

  function loadOverlayTopology() {
    if (!state.token || state.topology.loading) return Promise.resolve();
    state.topology.loading = true;
    state.topology.error = "";
    renderTopologyWhenActive();
    return api("/v1/admin/topology").then(function (topology) {
      state.topology.data = topology && typeof topology === "object" ? topology : {};
      var groups = Array.isArray(state.topology.data.groups) ? state.topology.data.groups : [];
      if (!groups.some(function (group) { return String(group.group_id) === String(state.topology.selectedGroupId); })) {
        var rootGroupId = state.topology.data.root_group_id == null ? null : String(state.topology.data.root_group_id);
        state.topology.selectedGroupId = groups.some(function (group) { return String(group.group_id) === rootGroupId; })
          ? rootGroupId : (groups.length ? String(groups[0].group_id) : null);
      }
      updateNavigationCounts();
    }).catch(function (error) {
      state.topology.error = error.message;
    }).finally(function () {
      state.topology.loading = false;
      renderTopologyWhenActive();
    });
  }

  function loadTopologyView(forceSettings) {
    return Promise.all([
      loadOverlayTopology(),
      loadTopologyPolicy(Boolean(forceSettings))
    ]);
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

  function normalizedOverlayTopology() {
    var snapshot = state.topology.data || {};
    var nodes = [];
    var nodeById = {};
    (Array.isArray(snapshot.nodes) ? snapshot.nodes : []).forEach(function (entry) {
      if (!entry || entry.node_id == null) return;
      var node = Object.assign({}, entry, {
        node_id: String(entry.node_id),
        leaf_group_id: entry.leaf_group_id == null ? "" : String(entry.leaf_group_id),
        ancestry: (Array.isArray(entry.ancestry) ? entry.ancestry : []).map(String),
        tags: Array.isArray(entry.tags) ? entry.tags : [],
        representative_for: (Array.isArray(entry.representative_for) ? entry.representative_for : []).filter(function (assignment) {
          return assignment && assignment.group_id != null;
        }).map(function (assignment) {
          return {
            group_id: String(assignment.group_id),
            depth: integerSetting(assignment.depth, 0),
            plane: integerSetting(assignment.plane, 0)
          };
        }),
        health_state: entry.health_state == null ? null : String(entry.health_state).toLowerCase(),
        last_seen_at: entry.last_seen_at == null ? null : entry.last_seen_at
      });
      if (nodeById[node.node_id]) return;
      nodes.push(node);
      nodeById[node.node_id] = node;
    });

    var groups = [];
    var groupById = {};
    (Array.isArray(snapshot.groups) ? snapshot.groups : []).forEach(function (entry) {
      if (!entry || entry.group_id == null) return;
      var groupId = String(entry.group_id);
      if (groupById[groupId]) return;
      var group = {
        group_id: groupId,
        depth: integerSetting(entry.depth, 0),
        parent_group_id: entry.parent_group_id == null ? null : String(entry.parent_group_id),
        child_group_ids: (Array.isArray(entry.child_group_ids) ? entry.child_group_ids : []).map(String),
        node_ids: (Array.isArray(entry.node_ids) ? entry.node_ids : []).map(String),
        leaf: Boolean(entry.leaf),
        representatives: (Array.isArray(entry.representatives) ? entry.representatives : []).filter(function (representative) {
          return representative && representative.node_id != null;
        }).map(function (representative) {
          return {
            node_id: String(representative.node_id),
            plane: integerSetting(representative.plane, 0),
            role: String(representative.role || "")
          };
        })
      };
      groups.push(group);
      groupById[groupId] = group;
    });
    groups.sort(function (left, right) {
      return left.depth - right.depth || left.group_id.localeCompare(right.group_id);
    });

    groups.forEach(function (group) {
      group.child_group_ids = group.child_group_ids.filter(function (childId, index, values) {
        return childId !== group.group_id && Boolean(groupById[childId]) && values.indexOf(childId) === index;
      });
    });
    groups.forEach(function (group) {
      if (!group.parent_group_id || !groupById[group.parent_group_id]) return;
      var parent = groupById[group.parent_group_id];
      if (parent.child_group_ids.indexOf(group.group_id) === -1) parent.child_group_ids.push(group.group_id);
    });

    nodes.forEach(function (node) {
      node.ancestry = node.ancestry.filter(function (groupId) { return Boolean(groupById[groupId]); });
      if (!node.ancestry.length && node.leaf_group_id && groupById[node.leaf_group_id]) {
        var cursor = groupById[node.leaf_group_id];
        var ancestry = [];
        var seen = {};
        while (cursor && !seen[cursor.group_id]) {
          seen[cursor.group_id] = true;
          ancestry.unshift(cursor.group_id);
          cursor = cursor.parent_group_id ? groupById[cursor.parent_group_id] : null;
        }
        node.ancestry = ancestry;
      }
    });

    var edges = (Array.isArray(snapshot.edges) ? snapshot.edges : []).filter(function (edge) {
      return edge && edge.source != null && edge.target != null;
    }).map(function (edge) {
      var pathStates = (Array.isArray(edge.path_states) ? edge.path_states : []).map(String);
      var observedStatus = normalizedObservedStatus(edge.observed_status);
      var hasObservation = observedStatus !== "unknown"
        || pathStates.length > 0
        || edge.last_observed_at != null;
      return {
        source: String(edge.source),
        target: String(edge.target),
        placements: (Array.isArray(edge.placements) ? edge.placements : []).filter(function (placement) {
          return placement && placement.group_id != null;
        }).map(function (placement) {
          var kind = String(placement.kind || "");
          return {
            group_id: String(placement.group_id),
            depth: integerSetting(placement.depth, 0),
            plane: integerSetting(placement.plane, 0),
            kind: kind === "sibling_cycle" ? "sibling_cycle" : "leaf_cycle"
          };
        }),
        observed_status: hasObservation ? observedStatus : null,
        path_states: pathStates,
        last_observed_at: edge.last_observed_at == null ? null : edge.last_observed_at,
        has_observation: hasObservation
      };
    });

    var rootGroupId = snapshot.root_group_id == null ? null : String(snapshot.root_group_id);
    if (!rootGroupId || !groupById[rootGroupId]) {
      var root = groups.find(function (group) { return group.parent_group_id == null; });
      rootGroupId = root ? root.group_id : (groups.length ? groups[0].group_id : null);
    }
    return {
      snapshot: snapshot,
      nodes: nodes,
      nodeById: nodeById,
      groups: groups,
      groupById: groupById,
      rootGroupId: rootGroupId,
      edges: edges
    };
  }

  function representativeAssignments(node, group) {
    if (!node || !group) return [];
    var assignments = (node.representative_for || []).filter(function (assignment) {
      return assignment.group_id === group.group_id;
    });
    if (assignments.length) return assignments;
    return group.representatives.filter(function (representative) {
      return representative.node_id === node.node_id;
    }).map(function (representative) {
      return { group_id: group.group_id, depth: group.depth, plane: representative.plane };
    });
  }

  function edgePlacementType(placement) {
    if (placement && placement.kind === "leaf_cycle") return "intra";
    return placement && placement.plane > 0 ? "secondary" : "primary";
  }

  function normalizedObservedStatus(value) {
    var status = String(value || "unknown").toLowerCase();
    return ["connected", "partial", "unreachable", "stale", "unknown"].indexOf(status) === -1
      ? "unknown" : status;
  }

  function mermaidLabel(value) {
    return String(value == null ? "" : value)
      .replace(/\\/g, "/")
      .replace(/"/g, "'")
      .replace(/[\r\n]+/g, " ");
  }

  function groupForNodeBelow(model, parentGroupId, nodeId) {
    var node = model.nodeById[nodeId];
    if (!node) return parentGroupId;
    var index = node.ancestry.indexOf(parentGroupId);
    if (index >= 0 && index + 1 < node.ancestry.length) return node.ancestry[index + 1];
    return node.leaf_group_id || parentGroupId;
  }

  function aggregateTopologyEdges(model) {
    var aggregated = {};
    var statusRank = { unknown: 0, connected: 1, stale: 2, partial: 3, unreachable: 4 };
    model.edges.forEach(function (edge) {
      var placements = edge.placements.length ? edge.placements : [{
        group_id: model.rootGroupId,
        depth: 0,
        plane: 0,
        kind: "sibling_cycle"
      }];
      placements.forEach(function (placement) {
        if (!model.groupById[placement.group_id]) return;
        var sourceGroup = placement.kind === "leaf_cycle"
          ? placement.group_id : groupForNodeBelow(model, placement.group_id, edge.source);
        var targetGroup = placement.kind === "leaf_cycle"
          ? placement.group_id : groupForNodeBelow(model, placement.group_id, edge.target);
        if (!model.groupById[sourceGroup] || !model.groupById[targetGroup]) return;
        var type = edgePlacementType(placement);
        var pair = [sourceGroup, targetGroup].sort();
        var key = pair.join("|") + "|" + placement.group_id + "|" + placement.plane + "|" + placement.kind;
        if (!aggregated[key]) {
          aggregated[key] = {
            source_group_id: pair[0],
            target_group_id: pair[1],
            placement_group_id: placement.group_id,
            depth: placement.depth,
            plane: placement.plane,
            kind: placement.kind,
            type: type,
            count: 0,
            observed_status: null,
            last_observed_at: null,
            path_states: []
          };
        }
        var aggregate = aggregated[key];
        aggregate.count += 1;
        if (edge.has_observation && (!aggregate.observed_status
          || statusRank[edge.observed_status] > statusRank[aggregate.observed_status])) {
          aggregate.observed_status = edge.observed_status;
        }
        if (edge.last_observed_at && (!aggregate.last_observed_at
          || String(edge.last_observed_at) > String(aggregate.last_observed_at))) {
          aggregate.last_observed_at = edge.last_observed_at;
        }
        edge.path_states.forEach(function (pathState) {
          if (aggregate.path_states.indexOf(pathState) === -1) aggregate.path_states.push(pathState);
        });
      });
    });
    return Object.keys(aggregated).map(function (key) { return aggregated[key]; });
  }

  function generateTopologyMermaid(model, scopedGroups) {
    var lines = ["flowchart TB"];
    var aliases = {};
    var groups = Array.isArray(scopedGroups) ? scopedGroups : model.groups;
    groups.forEach(function (group, index) { aliases[group.group_id] = "group_" + index; });

    function appendGroup(groupId, indent) {
      var group = model.groupById[groupId];
      if (!group || !aliases[groupId]) return;
      var alias = aliases[groupId];
      var representatives = group.representatives.map(function (representative) {
        return shortId(representative.node_id) + " p" + representative.plane;
      }).join(", ");
      lines.push(indent + 'subgraph sg_' + alias + '["Depth ' + group.depth + " · " + mermaidLabel(shortId(group.group_id)) + '"]');
      lines.push(indent + "  direction TB");
      lines.push(indent + "  " + alias + '["' + group.node_ids.length + " nodes"
        + (representatives ? " · reps " + mermaidLabel(representatives) : "") + '"]');
      group.child_group_ids.filter(function (childId) {
        return Boolean(aliases[childId]);
      }).forEach(function (childId) { appendGroup(childId, indent + "  "); });
      lines.push(indent + "end");
    }

    groups.filter(function (group) {
      return !group.parent_group_id || !aliases[group.parent_group_id];
    }).forEach(function (group) { appendGroup(group.group_id, "  "); });

    var seenHierarchy = {};
    groups.forEach(function (group) {
      group.child_group_ids.forEach(function (childId) {
        if (!aliases[group.group_id] || !aliases[childId]) return;
        var key = group.group_id + "|" + childId;
        if (seenHierarchy[key]) return;
        seenHierarchy[key] = true;
        lines.push("  " + aliases[group.group_id] + " --> " + aliases[childId]);
      });
    });
    aggregateTopologyEdges(model).forEach(function (edge) {
      if (edge.source_group_id === edge.target_group_id) return;
      var source = aliases[edge.source_group_id];
      var target = aliases[edge.target_group_id];
      if (!source || !target) return;
      var label = (edge.kind === "leaf_cycle" ? "leaf" : "sibling") + " p" + edge.plane + " ×" + edge.count;
      lines.push("  " + source + (edge.type === "intra" ? " ---|" : " -.-|") + label + "| " + target);
    });
    if (Object.keys(aliases).length) lines.push("  class " + Object.keys(aliases).map(function (id) {
      return aliases[id];
    }).join(",") + " group");
    return lines.join("\n");
  }

  function cachedTopologyMermaid(model, scopedGroups) {
    var cache = state.topology.mermaidCache;
    var epoch = model.snapshot.topology_epoch == null
      ? null
      : String(model.snapshot.topology_epoch);
    var scope = (Array.isArray(scopedGroups) ? scopedGroups : model.groups).map(function (group) {
      return group.group_id;
    }).join("|");
    var cacheHit = cache.source != null
      && cache.scope === scope
      && (epoch == null ? cache.snapshot === model.snapshot : cache.epoch === epoch);
    if (!cacheHit) {
      cache.epoch = epoch;
      cache.scope = scope;
      cache.snapshot = model.snapshot;
      cache.source = generateTopologyMermaid(model, scopedGroups);
    }
    return cache.source;
  }

  function contextualTopologyGroups(model) {
    if (!model.groups.length) return [];
    var selected = model.groupById[String(state.topology.selectedGroupId)]
      || model.groupById[model.rootGroupId] || model.groups[0];
    var visible = {};
    function include(group) {
      if (group) visible[group.group_id] = true;
    }
    include(selected);
    selected.child_group_ids.forEach(function (childId) { include(model.groupById[childId]); });

    var cursor = selected;
    var visited = {};
    while (cursor && !visited[cursor.group_id]) {
      visited[cursor.group_id] = true;
      include(cursor);
      var parent = cursor.parent_group_id ? model.groupById[cursor.parent_group_id] : null;
      if (parent) {
        include(parent);
        parent.child_group_ids.forEach(function (childId) { include(model.groupById[childId]); });
      }
      cursor = parent;
    }
    return model.groups.filter(function (group) { return Boolean(visible[group.group_id]); });
  }

  function buildOverlayGraph(model, graphGroups) {
    var depthGroups = {};
    graphGroups.forEach(function (group) {
      if (!depthGroups[group.depth]) depthGroups[group.depth] = [];
      depthGroups[group.depth].push(group);
    });
    var depths = Object.keys(depthGroups).map(Number).sort(function (left, right) { return left - right; });
    var groupWidth = 184;
    var groupHeight = 78;
    var horizontalGap = 34;
    var bandHeight = 138;
    var largestDepth = depths.reduce(function (maximum, depth) {
      return Math.max(maximum, depthGroups[depth].length);
    }, 1);
    var canvasWidth = Math.max(760, largestDepth * (groupWidth + horizontalGap) + 80);
    var canvasHeight = Math.max(360, depths.length * bandHeight + 70);
    var positions = {};

    depths.forEach(function (depth, depthIndex) {
      var entries = depthGroups[depth];
      var rowWidth = entries.length * groupWidth + Math.max(0, entries.length - 1) * horizontalGap;
      var startX = (canvasWidth - rowWidth) / 2;
      entries.forEach(function (group, index) {
        positions[group.group_id] = {
          x: startX + index * (groupWidth + horizontalGap),
          y: 46 + depthIndex * bandHeight,
          centerX: startX + index * (groupWidth + horizontalGap) + groupWidth / 2,
          centerY: 46 + depthIndex * bandHeight + groupHeight / 2
        };
      });
    });

    var bandMarkup = depths.map(function (depth, index) {
      return '<g class="overlay-svg-depth-band"><line x1="20" y1="' + (28 + index * bandHeight)
        + '" x2="' + (canvasWidth - 20) + '" y2="' + (28 + index * bandHeight)
        + '"></line><text x="28" y="' + (22 + index * bandHeight) + '">Depth ' + depth + "</text></g>";
    }).join("");
    var hierarchyMarkup = graphGroups.map(function (group) {
      if (!group.parent_group_id || !positions[group.parent_group_id] || !positions[group.group_id]) return "";
      var parent = positions[group.parent_group_id];
      var child = positions[group.group_id];
      return '<line class="overlay-svg-hierarchy-edge" x1="' + parent.centerX + '" y1="' + (parent.y + groupHeight)
        + '" x2="' + child.centerX + '" y2="' + child.y + '" vector-effect="non-scaling-stroke"></line>';
    }).join("");

    var internalLinks = {};
    var statusRank = { unknown: 0, connected: 1, stale: 2, partial: 3, unreachable: 4 };
    var edgeMarkup = aggregateTopologyEdges(model).map(function (edge) {
      if (edge.source_group_id === edge.target_group_id) {
        if (!internalLinks[edge.source_group_id]) {
          internalLinks[edge.source_group_id] = { count: 0, observed_status: null };
        }
        var internal = internalLinks[edge.source_group_id];
        internal.count += edge.count;
        if (edge.observed_status && (!internal.observed_status
          || statusRank[edge.observed_status] > statusRank[internal.observed_status])) {
          internal.observed_status = edge.observed_status;
        }
        return "";
      }
      var source = positions[edge.source_group_id];
      var target = positions[edge.target_group_id];
      if (!source || !target) return "";
      var observationClass = edge.observed_status ? " overlay-svg-edge-observed-" + edge.observed_status : "";
      var label = (edge.kind === "leaf_cycle" ? "leaf links" : "sibling links") + " · plane " + edge.plane
        + " · " + edge.count + " links" + (edge.observed_status ? " · " + pretty(edge.observed_status) : "")
        + (edge.path_states.length ? " · " + edge.path_states.map(pretty).join(", ") : "")
        + (edge.last_observed_at ? " · " + formatTime(edge.last_observed_at) : "");
      return '<line class="overlay-svg-edge overlay-svg-edge-' + edge.type + observationClass + '" x1="' + source.centerX
        + '" y1="' + source.centerY + '" x2="' + target.centerX + '" y2="' + target.centerY
        + '" vector-effect="non-scaling-stroke"><title>' + escapeHtml(label) + "</title></line>";
    }).join("");

    var selectedGroupId = String(state.topology.selectedGroupId || "");
    var groupMarkup = graphGroups.map(function (group) {
      var position = positions[group.group_id];
      if (!position) return "";
      var selectedClass = group.group_id === selectedGroupId ? " selected" : "";
      var representatives = group.representatives.slice().sort(function (left, right) { return left.plane - right.plane; });
      var repLabel = representatives.length
        ? representatives.map(function (representative) { return "p" + representative.plane + " " + shortId(representative.node_id); }).join(" · ")
        : "No representatives";
      var nodeHealth = group.node_ids.map(function (nodeId) { return model.nodeById[nodeId]; }).filter(Boolean);
      var unhealthy = nodeHealth.some(function (node) {
        return node.health_state && ["healthy", "direct"].indexOf(node.health_state) === -1;
      });
      var internal = internalLinks[group.group_id] || { count: 0, observed_status: null };
      var observationClass = internal.observed_status ? " observed-" + internal.observed_status : "";
      return '<g class="overlay-svg-group' + selectedClass + (unhealthy ? " degraded" : "") + observationClass + '" data-topology-group="'
        + escapeHtml(group.group_id) + '" role="button" tabindex="0" aria-label="Depth ' + group.depth + ", "
        + group.node_ids.length + ' nodes"><title>' + escapeHtml(group.group_id + " · " + repLabel) + '</title><rect x="'
        + position.x + '" y="' + position.y + '" width="' + groupWidth + '" height="' + groupHeight
        + '" rx="6"></rect><text class="overlay-svg-group-title" x="' + (position.x + 14) + '" y="' + (position.y + 23)
        + '">Depth ' + group.depth + (group.leaf ? " · Leaf" : "") + '</text><text class="overlay-svg-group-id" x="'
        + (position.x + 14) + '" y="' + (position.y + 42) + '">' + escapeHtml(shortId(group.group_id))
        + '</text><text class="overlay-svg-group-count" x="' + (position.x + groupWidth - 14) + '" y="' + (position.y + 23)
        + '" text-anchor="end">' + group.node_ids.length + ' nodes</text><text class="overlay-svg-group-reps" x="'
        + (position.x + 14) + '" y="' + (position.y + 62) + '">' + escapeHtml(repLabel)
        + (internal.count ? " · " + internal.count + " local links"
          + (internal.observed_status ? " " + pretty(internal.observed_status) : "") : "") + "</text></g>";
    }).join("");

    var scaledWidth = Math.round(canvasWidth * state.topology.zoom);
    return '<svg class="overlay-topology-svg" width="' + canvasWidth + '" height="' + canvasHeight + '" viewBox="0 0 '
      + canvasWidth + " " + canvasHeight + '" data-base-width="' + canvasWidth + '" style="width:' + scaledWidth
      + 'px" role="img" aria-labelledby="overlay-graph-title"><title id="overlay-graph-title">'
      + t("Parent-child hierarchy and forwarding links") + '</title><g class="overlay-svg-depth-bands">' + bandMarkup
      + '</g><g class="overlay-svg-hierarchy">' + hierarchyMarkup + '</g><g class="overlay-svg-edges">' + edgeMarkup
      + '</g><g class="overlay-svg-groups">' + groupMarkup + "</g></svg>";
  }

  function initializeTopologyMermaid() {
    if (state.topology.mermaidInitialized) return true;
    if (!window.mermaid || typeof window.mermaid.initialize !== "function"
      || typeof window.mermaid.render !== "function") return false;
    try {
      window.mermaid.initialize({
        startOnLoad: false,
        securityLevel: "strict",
        suppressErrorRendering: true,
        logLevel: "error",
        maxEdges: 4096,
        maxTextSize: 1000000,
        theme: "base",
        fontFamily: "Lato, Helvetica Neue, Arial, sans-serif",
        flowchart: {
          htmlLabels: false,
          useMaxWidth: false
        }
      });
    } catch (error) {
      console.error("Mermaid topology initialization failed", error);
      return false;
    }
    state.topology.mermaidInitialized = true;
    return true;
  }

  function showTopologyMermaidFallback(target) {
    if (!target || !target.isConnected) return;
    target.dataset.renderer = "fallback";
    target.removeAttribute("aria-busy");
    if (target.querySelector(".overlay-mermaid-fallback-notice")) return;
    var notice = document.createElement("div");
    notice.className = "overlay-mermaid-fallback-notice";
    notice.setAttribute("role", "status");
    notice.textContent = t("Diagram rendering failed. Showing the fallback topology.");
    target.prepend(notice);
  }

  function topologySvgBaseWidth(svg) {
    var viewBox = String(svg.getAttribute("viewBox") || "").trim().split(/[\s,]+/).map(Number);
    if (viewBox.length === 4 && viewBox.every(Number.isFinite) && viewBox[2] > 0) {
      return Math.max(760, Math.ceil(viewBox[2]));
    }
    var width = Number.parseFloat(svg.getAttribute("width"));
    return Number.isFinite(width) && width > 0 ? Math.max(760, Math.ceil(width)) : 760;
  }

  function renderTopologyMermaid() {
    var target = $("overlay-mermaid-diagram");
    if (!target || !state.topology.data) return Promise.resolve();
    var model = normalizedOverlayTopology();
    var source = cachedTopologyMermaid(model, contextualTopologyGroups(model));
    var sequence = ++state.topology.mermaidRenderSequence;
    var renderId = "heteronetwork-topology-" + sequence;
    target.setAttribute("aria-busy", "true");
    var previousNotice = target.querySelector(".overlay-mermaid-fallback-notice");
    if (previousNotice) previousNotice.remove();
    if (!initializeTopologyMermaid()) {
      showTopologyMermaidFallback(target);
      return Promise.resolve();
    }

    var render = state.topology.mermaidQueue.catch(function () {
      // A prior failed render must not block the latest topology.
    }).then(function () {
      if (sequence !== state.topology.mermaidRenderSequence || !target.isConnected) return null;
      return window.mermaid.render(renderId, source);
    });
    state.topology.mermaidQueue = render.then(function () {}, function () {});
    return render.then(function (result) {
      if (!result || sequence !== state.topology.mermaidRenderSequence || !target.isConnected) return;
      var template = document.createElement("template");
      template.innerHTML = String(result.svg || "").trim();
      var svg = template.content.querySelector("svg");
      if (!svg) throw new Error("Mermaid did not return an SVG");
      var baseWidth = topologySvgBaseWidth(svg);
      svg.classList.add("overlay-topology-svg", "overlay-mermaid-svg");
      svg.dataset.baseWidth = String(baseWidth);
      svg.style.width = Math.round(baseWidth * state.topology.zoom) + "px";
      svg.setAttribute("role", "img");
      svg.setAttribute("aria-label", t("Parent-child hierarchy and forwarding links"));
      target.replaceChildren(svg);
      target.dataset.renderer = "mermaid";
      target.removeAttribute("aria-busy");
      var scroller = target.closest(".overlay-canvas-scroll");
      if (scroller) {
        var scheduleFrame = typeof window.requestAnimationFrame === "function"
          ? window.requestAnimationFrame.bind(window)
          : window.setTimeout.bind(window);
        scheduleFrame(function () {
          if (sequence !== state.topology.mermaidRenderSequence || !target.isConnected) return;
          scroller.scrollLeft = Math.max(0, (scroller.scrollWidth - scroller.clientWidth) / 2);
        });
      }
      if (typeof result.bindFunctions === "function") {
        try {
          result.bindFunctions(target);
        } catch (error) {
          console.error("Mermaid topology bindings failed", error);
        }
      }
    }).catch(function (error) {
      if (sequence !== state.topology.mermaidRenderSequence) return;
      console.error("Mermaid topology rendering failed", error);
      showTopologyMermaidFallback(target);
    });
  }

  function overlayStat(label, value, title) {
    return '<div class="overlay-stat"><span>' + escapeHtml(label) + '</span><strong title="' + escapeHtml(title || value)
      + '">' + escapeHtml(value) + "</strong></div>";
  }

  function renderOverlaySettings() {
    if (!state.topology.settings) {
      state.topology.settings = settingsFromTopologyPolicy(state.topology.policy || (state.overview && state.overview.cluster_policy));
    }
    var settings = state.topology.settings;
    var policyAvailable = Boolean(state.topology.policy || (state.overview && state.overview.cluster_policy));
    var status = state.topology.dirty ? statusPill("degraded", "Unsaved changes") : statusPill("healthy", "Current");
    if (state.topology.policyLoading && !policyAvailable) status = statusPill("unknown", "Loading policy...");
    var disabled = state.topology.saving || !policyAvailable ? " disabled" : "";
    var error = state.topology.policyError
      ? '<div class="overlay-policy-error" role="alert"><strong>Policy unavailable</strong><span>'
        + escapeHtml(state.topology.policyError) + "</span></div>" : "";
    return '<section class="section-panel overlay-settings-panel"><div class="section-header"><div><h2>Runtime overlay policy</h2>'
      + '<p>' + escapeHtml((state.topology.data && state.topology.data.algorithm) || "recursive hierarchy") + '</p></div>' + status
      + '</div><div class="section-body"><div class="overlay-settings-grid"><div class="overlay-setting"><div class="overlay-setting-copy">'
      + '<label for="overlay-group-fanout">Group fanout</label><small>Maximum children or nodes assigned to each group.</small></div>'
      + '<div class="overlay-range-control"><input id="overlay-group-fanout-range" data-topology-setting="fanout" type="range" min="4" max="64" step="1" value="'
      + escapeHtml(settings.fanout) + '" aria-label="Group fanout"><input id="overlay-group-fanout" data-topology-setting="fanout" type="number" min="4" max="64" step="1" value="'
      + escapeHtml(settings.fanout) + '"></div></div><div class="overlay-setting"><div class="overlay-setting-copy"><span id="overlay-degree-label">Max peer degree</span>'
      + '<small>Maximum hierarchy neighbors per node.</small></div><div class="segmented-control overlay-degree-control" role="group" aria-labelledby="overlay-degree-label">'
      + [4, 6].map(function (degree) {
        return '<button class="segmented-option ' + (settings.maxDegree === degree ? "active" : "") + '" data-overlay-degree="'
          + degree + '" type="button" aria-pressed="' + (settings.maxDegree === degree) + '">' + degree + "</button>";
      }).join("") + '</div></div></div>' + error
      + '<div class="form-actions overlay-settings-actions"><button class="button button-primary" id="save-overlay-settings" type="button"'
      + disabled + '>' + icon(state.topology.saving ? "refresh-cw" : "save") + '<span>'
      + (state.topology.saving ? "Saving overlay settings..." : "Save overlay settings") + "</span></button></div></div></section>";
  }

  function renderOverlayState(title, message, iconName, retry) {
    return '<section class="section-panel"><div class="overlay-state" role="' + (retry ? "alert" : "status") + '">'
      + icon(iconName || "blocks", 28) + "<strong>" + escapeHtml(title) + "</strong><p>" + escapeHtml(message || "") + "</p>"
      + (retry ? '<button class="button button-secondary button-small" id="retry-topology" type="button">'
        + icon("refresh-cw") + "<span>Retry</span></button>" : "") + "</div></section>";
  }

  function renderObservedConnections(model, group) {
    var memberSet = {};
    group.node_ids.forEach(function (nodeId) { memberSet[nodeId] = true; });
    var observedEdges = model.edges.filter(function (edge) {
      return edge.has_observation && (memberSet[edge.source] || memberSet[edge.target]
        || edge.placements.some(function (placement) { return placement.group_id === group.group_id; }));
    });
    if (!observedEdges.length) return "";
    var rows = observedEdges.slice(0, 100).map(function (edge) {
      var pathStates = edge.path_states.length
        ? '<span class="tag-list">' + edge.path_states.map(function (pathState) {
          return '<span class="tag">' + escapeHtml(pretty(pathState)) + "</span>";
        }).join("") + "</span>"
        : '<span class="faint">None</span>';
      return '<tr><td><span class="overlay-observed-pair" data-no-i18n><strong title="' + escapeHtml(edge.source) + '">'
        + escapeHtml(shortId(edge.source)) + '</strong><span>&harr;</span><strong title="' + escapeHtml(edge.target) + '">'
        + escapeHtml(shortId(edge.target)) + '</strong></span></td><td>' + statusPill(edge.observed_status, pretty(edge.observed_status))
        + '</td><td>' + pathStates + '</td><td class="faint">' + escapeHtml(formatTime(edge.last_observed_at)) + "</td></tr>";
    }).join("");
    return '<div class="overlay-observed-connections"><div class="overlay-observed-heading"><strong>Observed connections</strong><span>'
      + observedEdges.length + '</span></div><div class="table-wrap"><table><thead><tr><th>Connection</th><th>Status</th><th>Path states</th>'
      + "<th>Last observed</th></tr></thead><tbody>" + rows + "</tbody></table></div></div>";
  }

  function renderOverlayGroupDetails(model) {
    if (!model.groups.length) return "";
    var selected = model.groupById[String(state.topology.selectedGroupId)] || model.groupById[model.rootGroupId] || model.groups[0];
    state.topology.selectedGroupId = selected.group_id;
    var breadcrumbGroups = [];
    var cursor = selected;
    var seen = {};
    while (cursor && !seen[cursor.group_id]) {
      seen[cursor.group_id] = true;
      breadcrumbGroups.unshift(cursor);
      cursor = cursor.parent_group_id ? model.groupById[cursor.parent_group_id] : null;
    }
    var breadcrumbs = breadcrumbGroups.map(function (group, index) {
      var current = index === breadcrumbGroups.length - 1;
      return (index ? '<span class="overlay-group-breadcrumb-separator">' + icon("chevron-right", 13) + "</span>" : "")
        + '<button type="button" data-topology-group="' + escapeHtml(group.group_id) + '"' + (current ? ' aria-current="page"' : "")
        + ' title="' + escapeHtml(group.group_id) + '">Depth ' + group.depth + " · " + escapeHtml(shortId(group.group_id)) + "</button>";
    }).join("");
    var children = selected.child_group_ids.map(function (childId) {
      var child = model.groupById[childId];
      if (!child) return "";
      return '<button class="overlay-child-group" type="button" data-topology-group="' + escapeHtml(child.group_id)
        + '"><span>' + icon(child.leaf ? "server" : "blocks") + '<strong title="' + escapeHtml(child.group_id) + '">'
        + escapeHtml(shortId(child.group_id)) + '</strong></span><small>Depth ' + child.depth + " · " + child.node_ids.length
        + " nodes</small>" + icon("chevron-right") + "</button>";
    }).join("");
    var representativeRows = selected.representatives.slice().sort(function (left, right) {
      return left.plane - right.plane || left.node_id.localeCompare(right.node_id);
    }).map(function (representative) {
      return '<span class="overlay-representative-assignment"><small>Plane ' + representative.plane + " · "
        + escapeHtml(pretty(representative.role || "representative")) + '</small><code title="'
        + escapeHtml(representative.node_id) + '">' + escapeHtml(shortId(representative.node_id)) + "</code></span>";
    }).join("");
    var visibleMembers = selected.node_ids.slice(0, 100);
    var memberRows = visibleMembers.map(function (nodeId) {
      var node = model.nodeById[nodeId] || {
        node_id: nodeId, tags: [], representative_for: [], ancestry: [], health_state: null
      };
      var assignments = representativeAssignments(node, selected);
      var badges = assignments.map(function (assignment) {
        return statusPill(assignment.plane === 0 ? "healthy" : "info", "Plane " + assignment.plane);
      });
      if (!badges.length) badges.push('<span class="status-pill unknown">Member</span>');
      var health = node.health_state || node.last_seen_at
        ? '<span class="overlay-node-health">' + (node.health_state ? statusPill(node.health_state, pretty(node.health_state)) : "")
          + (node.last_seen_at ? '<small>' + escapeHtml(t("Last seen")) + ": " + escapeHtml(translateDynamicText(age(node.last_seen_at))) + "</small>" : "")
          + "</span>"
        : '<span class="overlay-node-health"><span class="faint">-</span></span>';
      var content = '<span class="peer-avatar">' + escapeHtml(initials(node.node_id)) + '</span><span class="overlay-member-identity" data-no-i18n>'
        + '<strong title="' + escapeHtml(node.node_id) + '">' + escapeHtml(shortId(node.node_id)) + '</strong><small>'
        + escapeHtml(node.vpn_ip || "-") + '</small></span><span class="overlay-member-role">'
        + escapeHtml(localizedRole(node.role)) + '</span><span class="overlay-member-tags">' + listTags(node.tags)
        + '</span><span class="overlay-member-degree"><small>Degree</small><strong>' + escapeHtml(node.degree == null ? "-" : node.degree)
        + '</strong></span>' + health + '<span class="overlay-member-badges">' + badges.join("") + "</span>";
      return findNode(node.node_id)
        ? '<button class="overlay-member-row" data-node-id="' + escapeHtml(node.node_id) + '" type="button">' + content + "</button>"
        : '<div class="overlay-member-row">' + content + "</div>";
    }).join("");
    var memberOverflow = selected.node_ids.length > visibleMembers.length
      ? '<div class="overlay-member-overflow">Showing ' + visibleMembers.length + " of " + selected.node_ids.length + " descendant nodes.</div>"
      : "";
    return '<section class="section-panel overlay-group-details"><div class="section-header"><div><h2>Group details</h2><p data-no-i18n>'
      + escapeHtml(selected.group_id) + '</p></div><span class="status-pill info">Depth ' + selected.depth + "</span></div>"
      + '<nav class="overlay-group-breadcrumb" aria-label="Group hierarchy">' + breadcrumbs + '</nav><div class="overlay-group-summary"><div><span>Members</span><strong>'
      + selected.node_ids.length + '</strong></div><div><span>Children</span><strong>' + selected.child_group_ids.length
      + '</strong></div><div><span>Representatives</span><strong>' + selected.representatives.length + "</strong></div></div>"
      + (representativeRows ? '<div class="overlay-representative-assignments"><strong>Representative assignments</strong><div>'
        + representativeRows + "</div></div>" : "")
      + (children ? '<div class="overlay-child-groups"><div class="overlay-observed-heading"><strong>Children</strong><span>'
        + selected.child_group_ids.length + '</span></div><div class="overlay-child-group-list">' + children + "</div></div>" : "")
      + renderObservedConnections(model, selected) + '<div class="overlay-member-list">' + memberRows + memberOverflow + "</div></section>";
  }

  function renderOverlayTopology() {
    var settingsPanel = renderOverlaySettings();
    if (state.topology.loading && !state.topology.data) {
      return settingsPanel + renderOverlayState("Loading overlay topology", "Loading group hierarchy and links.", "refresh-cw", false);
    }
    if (state.topology.error && !state.topology.data) {
      return settingsPanel + renderOverlayState("Overlay topology unavailable", state.topology.error, "circle-alert", true);
    }

    var model = normalizedOverlayTopology();
    var snapshot = model.snapshot;
    if (!model.nodes.length && !model.groups.length) {
      return settingsPanel + renderOverlayState("No overlay topology", "Nodes will appear after joining the cluster.", "blocks", false);
    }
    var nodeCount = snapshot.node_count == null ? model.nodes.length : snapshot.node_count;
    var groupCount = snapshot.group_count == null ? model.groups.length : snapshot.group_count;
    var levelCount = snapshot.level_count == null
      ? new Set(model.groups.map(function (group) { return group.depth; })).size : snapshot.level_count;
    var edgeCount = snapshot.edge_count == null ? model.edges.length : snapshot.edge_count;
    var maxDegree = snapshot.max_observed_degree == null
      ? model.nodes.reduce(function (maximum, node) { return Math.max(maximum, Number(node.degree) || 0); }, 0)
      : snapshot.max_observed_degree;
    var diameterLowerBound = snapshot.diameter_lower_bound == null
      ? "-"
      : "\u2265 " + snapshot.diameter_lower_bound;
    var epoch = String(snapshot.topology_epoch == null ? "-" : snapshot.topology_epoch);
    var graphGroups = contextualTopologyGroups(model);
    var graph = buildOverlayGraph(model, graphGroups);
    var mermaid = cachedTopologyMermaid(model, graphGroups);
    var observedEdges = model.edges.filter(function (edge) { return edge.has_observation; });
    var observedStatuses = observedEdges.map(function (edge) { return edge.observed_status; }).filter(function (status, index, values) {
      return values.indexOf(status) === index;
    });
    var fullyObserved = model.edges.length > 0 && observedEdges.length === model.edges.length;
    var fullyConnected = fullyObserved && observedEdges.every(function (edge) {
      return edge.observed_status === "connected";
    });
    var observationState = fullyConnected ? "healthy"
      : observedStatuses.indexOf("unreachable") !== -1 ? "unreachable"
      : observedStatuses.some(function (status) { return status === "partial" || status === "stale"; }) ? "degraded"
        : observedEdges.length ? "partial"
          : "unknown";
    var topologyStatus = observedEdges.length
      ? statusPill(observationState, "Observed topology")
      : statusPill("unknown", "Synthesized topology");
    var staleError = state.topology.error
      ? '<div class="overlay-inline-error" role="alert">' + icon("circle-alert") + '<span>'
        + escapeHtml(state.topology.error) + "</span></div>" : "";
    var legend = '<div class="overlay-legend" aria-label="Topology legend"><span><i class="overlay-legend-line hierarchy"></i>Parent-child</span>'
      + '<span><i class="overlay-legend-line intra"></i>Leaf links</span><span><i class="overlay-legend-line inter"></i>Sibling links</span>'
      + (observedStatuses.length ? '<i class="overlay-legend-separator" aria-hidden="true"></i>' + ["connected", "partial", "unreachable", "stale", "unknown"].filter(function (status) {
        return observedStatuses.indexOf(status) !== -1;
      }).map(function (status) {
        return '<span><i class="overlay-legend-status ' + status + '"></i>' + escapeHtml(pretty(status)) + "</span>";
      }).join("") : "")
      + (model.nodes.some(function (node) { return node.health_state; })
        ? '<span><i class="overlay-legend-health"></i>Node health</span>' : "") + "</div>";
    return settingsPanel + staleError + '<div class="overlay-stat-strip">'
      + overlayStat("Nodes", nodeCount) + overlayStat("Groups", groupCount) + overlayStat("Levels", levelCount)
      + overlayStat("Edges", edgeCount) + overlayStat("Max degree", maxDegree)
      + overlayStat("Diameter estimate", diameterLowerBound) + overlayStat("Epoch", shortId(epoch), epoch) + '</div>'
      + '<section class="section-panel overlay-graph-panel"><div class="section-header"><div><h2>Group hierarchy</h2><p>Parent-child hierarchy and forwarding links</p></div>'
      + '<div class="overlay-graph-actions">' + topologyStatus + '<div class="overlay-zoom-controls" role="group" aria-label="Zoom">'
      + '<button class="icon-button" data-topology-zoom="out" type="button" aria-label="Zoom out" title="Zoom out">' + icon("zoom-out") + '</button>'
      + '<button class="icon-button" data-topology-zoom="reset" type="button" aria-label="Reset zoom" title="Reset zoom">' + icon("maximize-2") + '</button>'
      + '<span id="overlay-zoom-value" aria-live="polite">' + Math.round(state.topology.zoom * 100) + '%</span>'
      + '<button class="icon-button" data-topology-zoom="in" type="button" aria-label="Zoom in" title="Zoom in">' + icon("zoom-in") + '</button>'
      + '</div></div></div>' + legend + '<div class="overlay-canvas-scroll"><div id="overlay-mermaid-diagram" class="overlay-mermaid-diagram"'
      + ' data-renderer="fallback">' + graph + '</div></div><div class="overlay-graph-meta">'
      + '<span><strong>Algorithm</strong><code data-no-i18n>' + escapeHtml(snapshot.algorithm || "-") + '</code></span>'
      + '<span><strong>Visible groups</strong><code data-no-i18n>' + graphGroups.length + " / " + model.groups.length + '</code></span>'
      + '<span><strong>Generated</strong><time>' + escapeHtml(formatTime(snapshot.generated_at)) + "</time></span></div></section>"
      + renderOverlayGroupDetails(model)
      + '<section class="section-panel overlay-mermaid-panel"><div class="section-header"><div><h2>Mermaid source</h2><p data-no-i18n>flowchart TB</p></div>'
      + '<button class="icon-button" id="copy-topology-mermaid" type="button" aria-label="Copy Mermaid source" title="Copy Mermaid source">'
      + icon("copy") + '</button></div><pre data-no-i18n><code>' + escapeHtml(mermaid) + "</code></pre></section>";
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
    var derivedWebUiCount = (directory.instances || []).filter(function (instance) {
      return (instance.endpoints || []).some(function (endpoint) { return endpoint.kind === "web_ui"; });
    }).length;
    var activeWebUiCount = metrics.active_web_ui_count == null ? derivedWebUiCount : metrics.active_web_ui_count;
    var serviceKinds = [
      ["Control plane", metrics.active_control_plane_count || 0],
      ["Signal", metrics.active_signal_count || 0],
      ["STUN", metrics.active_stun_count || 0],
      ["Relay", metrics.active_relay_count || 0],
      ["Web UI", activeWebUiCount]
    ];
    var serviceRows = serviceKinds.map(function (entry) {
      var count = entry[1];
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
    var hostRows = buildServiceHostRows(overview);
    var registeredNodeCount = Array.isArray(overview.nodes) ? overview.nodes.length : 0;
    var infrastructureHostCount = hostRows.filter(function (row) { return row.type === "infrastructure"; }).length;
    var kinds = [
      ["control_plane", "Control Plane", "active_control_plane_count"],
      ["signal", "Signal", "active_signal_count"],
      ["stun", "STUN", "active_stun_count"],
      ["relay", "Relay", "active_relay_count"],
      ["web_ui", "Web UI", "active_web_ui_count"]
    ];
    kinds.forEach(function (kind) {
      var observedCount = hostRows.filter(function (row) {
        return serviceEndpointsForHost(row, kind[0]).length > 0;
      }).length;
      kind.push(metrics[kind[2]] == null ? observedCount : Number(metrics[kind[2]]) || 0);
    });
    var endpointRows = hostRows.map(function (row) {
      return '<tr data-host-key="' + escapeHtml(row.key) + '"><td>' + renderServiceHostIdentity(row)
        + '</td><td>' + renderAgentHealth(row) + '</td>'
        + kinds.map(function (kind) { return "<td>" + renderHostService(row, kind[0]) + "</td>"; }).join("")
        + "<td>" + renderHostLeases(row) + "</td></tr>";
    }).join("");
    var table = endpointRows
      ? '<div class="table-wrap"><table class="service-matrix node-service-matrix"><thead><tr><th>Node / host</th><th>Agent health</th>'
        + kinds.map(function (kind) { return '<th>' + escapeHtml(kind[1]) + '</th>'; }).join("")
        + '<th>Lease</th></tr></thead><tbody>' + endpointRows + '</tbody></table></div>'
      : emptyState("No nodes or infrastructure hosts", "Register a node or advertise an infrastructure service lease.", "server");
    return '<div class="metric-grid">'
      + metricCard("Hosts", hostRows.length, serviceHostSummary(registeredNodeCount, infrastructureHostCount), "server", "", "")
      + kinds.map(function (kind) {
        return metricCard(kind[1], kind[3], kind[3] >= 2 ? "Redundant" : kind[3] === 1 ? "Single host" : "Not advertised", kind[3] >= 2 ? "circle-check" : "circle-alert", "", kind[3] >= 2 ? "" : "warn");
      }).join("")
      + '</div><section class="section-panel"><div class="section-header"><div><h2>Node service leases</h2><p>Registered nodes and unmatched infrastructure hosts.</p></div>'
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
      modes.push('<button class="segmented-option ' + (enrollment.mode === "macos" ? "active" : "") + '" data-enrollment-mode="macos" type="button">' + icon("shield-check") + '<span>Desktop client</span></button>');
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
      + '<span>Enrollment link</span></h2><p>Open this link on the Mac or Windows PC where HeteroNetwork is installed.</p></div><span class="status-pill healthy">Ready</span></div>'
      + '<div class="section-body"><div class="secret-notice">' + icon("key") + '<span>Treat this token as a secret. It is not stored by this browser.</span></div>'
      + '<div class="command-block enrollment-link-block"><code>' + escapeHtml(result.enrollment_uri) + '</code><button class="icon-button command-copy" data-copy-enrollment="link" type="button" aria-label="Copy link" title="Copy link">' + icon("copy") + '</button></div>'
      + '<div class="enrollment-result-meta"><div><span>Expires</span><strong>' + escapeHtml(formatTime(result.expires_at)) + '</strong></div><div><span>Uses</span><strong>1</strong></div><div><span>Platform</span><strong>macOS / Windows</strong></div></div>'
      + '<div class="enrollment-actions"><a class="button button-primary" href="' + escapeHtml(result.enrollment_uri) + '">' + icon("external-link") + '<span>Open HeteroNetwork</span></a><button class="button button-secondary" data-copy-enrollment="link" type="button">' + icon("copy") + '<span>Copy link</span></button><button class="button button-secondary" id="reset-enrollment" type="button"><span>Create another</span></button></div>'
      + '<details class="token-details"><summary>Enrollment token</summary><div class="token-detail-body"><p>Treat this token as a secret. It is not stored by this browser.</p><pre>' + escapeHtml(tokenJson) + '</pre><button class="button button-secondary button-small" data-copy-enrollment="token" type="button">' + icon("copy") + '<span>Copy token</span></button></div></details></div></section>';
  }

  function renderLinuxEnrollment(enrollment) {
    var reusableUses = enrollment.reusable
      ? '<div class="form-field"><label for="enrollment-max-uses">Maximum uses</label><input id="enrollment-max-uses" data-enrollment-field="maxUses" type="number" min="2" max="1000" value="' + escapeHtml(enrollment.maxUses) + '"></div>'
      : '';
    var form = '<section class="section-panel enrollment-wizard"><div class="enrollment-step"><div class="step-marker">1</div><div class="step-content"><div class="step-heading"><h2>1. Device settings</h2><p>Choose the identity and capabilities assigned at enrollment.</p></div><div class="form-grid enrollment-form-grid"><div class="form-field"><label for="enrollment-role">Device role</label><select id="enrollment-role" data-enrollment-field="role"><option value="edge" ' + (enrollment.role === "edge" ? "selected" : "") + '>Edge</option><option value="worker" ' + (enrollment.role === "worker" ? "selected" : "") + '>Worker</option><option value="gateway" ' + (enrollment.role === "gateway" ? "selected" : "") + '>Gateway</option></select></div><div class="form-field wide"><label for="enrollment-tags">Tags (comma separated)</label><input id="enrollment-tags" data-enrollment-field="tags" value="' + escapeHtml(enrollment.tags) + '" placeholder="example: production, linux"></div></div></div></div>'
      + '<div class="enrollment-step"><div class="step-marker">2</div><div class="step-content"><div class="step-heading"><h2>2. Authentication key</h2><p>Limit how long and how many times the enrollment token can be used.</p></div>'
      + enrollmentToggle("reusable", "Reusable", "Allow more than one device to use this token.", enrollment.reusable)
      + '<div class="form-grid enrollment-form-grid"><div class="form-field"><label for="enrollment-expiration">Expiration (days)</label><input id="enrollment-expiration" data-enrollment-field="expirationDays" type="number" min="1" max="30" value="' + escapeHtml(enrollment.expirationDays) + '"></div>' + reusableUses + '</div></div></div>'
      + '<div class="enrollment-step enrollment-generate-step"><div class="step-marker">3</div><div class="step-content"><div class="step-heading"><h2>3. Generate install script</h2><p>The command installs the signed Linux amd64 agent, removes the token after enrollment, and automatically schedules the network and database HA services.</p></div><button class="button button-primary" id="generate-enrollment" type="button" ' + (enrollment.generating ? "disabled" : "") + '>' + icon(enrollment.generating ? "refresh-cw" : "terminal") + '<span>' + (enrollment.generating ? "Generating..." : "Generate install script") + '</span></button></div></div></section>';
    return '<div class="enrollment-intro"><span class="eyebrow">HETERONETWORK</span><h2>Add a Linux server</h2><p>Generate a secure install command for a new HeteroNetwork node.</p></div>'
      + renderEnrollmentModeSwitch(enrollment) + form
      + (enrollment.result ? renderLinuxEnrollmentResult(enrollment.result) : "");
  }

  function renderClientEnrollment(enrollment) {
    var form = '<section class="section-panel enrollment-wizard"><div class="enrollment-step"><div class="step-marker">1</div><div class="step-content"><div class="step-heading"><h2>1. Token lifetime</h2><p>The client token can be used once and cannot advertise routes or relay traffic.</p></div><div class="form-grid enrollment-form-grid"><div class="form-field"><label for="client-enrollment-expiration">Expiration (days)</label><input id="client-enrollment-expiration" data-enrollment-field="clientExpirationDays" type="number" min="1" max="30" value="' + escapeHtml(enrollment.clientExpirationDays) + '"></div></div></div></div>'
      + '<div class="enrollment-step enrollment-generate-step"><div class="step-marker">2</div><div class="step-content"><div class="step-heading"><h2>2. Generate enrollment link</h2></div><button class="button button-primary" id="generate-enrollment" type="button" ' + (enrollment.generating ? "disabled" : "") + '>' + icon(enrollment.generating ? "refresh-cw" : "external-link") + '<span>' + (enrollment.generating ? "Generating..." : "Generate desktop link") + '</span></button></div></div></section>';
    return '<div class="enrollment-intro"><span class="eyebrow">HETERONETWORK</span><h2>Add a desktop client</h2><p>Generate a one-use enrollment link for the native HeteroNetwork app.</p></div>'
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
      reusable: enrollment.reusable,
      max_uses: enrollment.reusable ? maxUses : 1
    };
    return api(path, {
      method: "POST",
      body: JSON.stringify(body)
    }).then(function (result) {
      enrollment.result = result;
      toast(enrollment.mode === "macos" ? "Desktop enrollment token issued." : "Enrollment token issued.");
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
      services: ["Node services", "Active service leases on registered nodes and infrastructure hosts."],
      paths: ["Connections", "Selected paths and operator controls."],
      topology: ["Overlay topology", "Recursive groups and forwarding links."],
      routes: ["Network routes", "Advertised networks and their owners."],
      acl: ["Access control", "Runtime connectivity policy and rules."],
      enrollment: ["Add device", "Issue a short-lived token and install a node with one command."]
    }[state.activeView];
    if (state.activeView === "enrollment" && state.enrollment.mode === "macos") {
      metadata = ["Add device", "Issue a one-use link for the native desktop clients."];
    }
    $("view-title").textContent = t(metadata[0]);
    $("view-subtitle").textContent = t(metadata[1]);
    $("breadcrumb-current").textContent = t(metadata[0]);
    $("view-content").innerHTML = {
      overview: renderOverview,
      nodes: renderNodes,
      services: renderServices,
      paths: renderPaths,
      topology: renderOverlayTopology,
      routes: renderRoutes,
      acl: renderAcl,
      enrollment: renderEnrollment
    }[state.activeView]();
    document.querySelectorAll(".nav-button").forEach(function (button) {
      button.classList.toggle("active", button.dataset.view === state.activeView);
    });
    decorateIcons($("view-content"));
    translateTree($("view-content"));
    if (state.activeView === "topology") renderTopologyMermaid();
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
      state.topology.policy = response.cluster_policy;
      if (!state.topology.dirty) state.topology.settings = settingsFromTopologyPolicy(response.cluster_policy);
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

  function markTopologySettingsDirty() {
    state.topology.dirty = true;
    var status = document.querySelector(".overlay-settings-panel .status-pill");
    if (status) {
      status.className = "status-pill degraded";
      status.textContent = t("Unsaved changes");
    }
  }

  function updateTopologySetting(input) {
    if (!state.topology.settings) state.topology.settings = settingsFromTopologyPolicy(state.topology.policy);
    var field = input.dataset.topologySetting;
    if (!field || !(field in state.topology.settings)) return;
    var value = input.value === "" ? "" : Number(input.value);
    state.topology.settings[field] = value;
    document.querySelectorAll('[data-topology-setting="' + field + '"]').forEach(function (control) {
      if (control !== input) control.value = input.value;
    });
    markTopologySettingsDirty();
  }

  function setOverlayDegree(value) {
    var degree = Number(value);
    if ([4, 6].indexOf(degree) === -1) return;
    if (!state.topology.settings) state.topology.settings = settingsFromTopologyPolicy(state.topology.policy);
    state.topology.settings.maxDegree = degree;
    if (Number(state.topology.settings.shortcutLimit) > degree) state.topology.settings.shortcutLimit = degree;
    markTopologySettingsDirty();
    renderView();
  }

  function saveOverlaySettings() {
    var settings = state.topology.settings || settingsFromTopologyPolicy(state.topology.policy);
    var fanout = Number(settings.fanout);
    var maxDegree = Number(settings.maxDegree);
    var shortcutLimit = Number(settings.shortcutLimit);
    if (!Number.isInteger(fanout) || fanout < 4 || fanout > 64) {
      toast("Group fanout must be an integer between 4 and 64.", "error");
      return Promise.resolve();
    }
    if ([4, 6].indexOf(maxDegree) === -1) {
      toast("Max peer degree must be 4 or 6.", "error");
      return Promise.resolve();
    }
    if (!Number.isInteger(shortcutLimit) || shortcutLimit < 0 || shortcutLimit > 64) {
      toast("Direct shortcuts must be an integer between 0 and 64.", "error");
      return Promise.resolve();
    }
    var currentPolicy = state.topology.policy || (state.overview && state.overview.cluster_policy);
    if (!currentPolicy) {
      toast("Policy unavailable", "error");
      return Promise.resolve();
    }
    var nextPolicy = Object.assign({}, currentPolicy, {
      overlay_block_size: fanout,
      overlay_max_degree: maxDegree,
      overlay_direct_shortcut_limit: shortcutLimit
    });
    state.topology.saving = true;
    setStatus("Saving overlay settings...");
    renderTopologyWhenActive();
    return api("/v1/admin/policy", {
      method: "PUT",
      body: JSON.stringify({ cluster_policy: nextPolicy })
    }).then(function (response) {
      var savedPolicy = topologyPolicyFromResponse(response) || nextPolicy;
      state.topology.policy = savedPolicy;
      if (state.overview && state.policyDirty) {
        state.overview.cluster_policy.overlay_block_size = savedPolicy.overlay_block_size;
        state.overview.cluster_policy.overlay_max_degree = savedPolicy.overlay_max_degree;
        state.overview.cluster_policy.overlay_direct_shortcut_limit = savedPolicy.overlay_direct_shortcut_limit;
      } else if (state.overview) {
        state.overview.cluster_policy = savedPolicy;
      }
      state.topology.settings = settingsFromTopologyPolicy(savedPolicy);
      state.topology.dirty = false;
      setStatus("");
      toast("Overlay settings saved.");
      updateNavigationCounts();
      return loadOverlayTopology();
    }).catch(function (error) {
      setStatus(error.message, true);
      toast(error.message, "error");
    }).finally(function () {
      state.topology.saving = false;
      renderTopologyWhenActive();
    });
  }

  function copyTopologyMermaid() {
    var model = normalizedOverlayTopology();
    var source = cachedTopologyMermaid(model, contextualTopologyGroups(model));
    return copyText(source).then(function () {
      toast("Mermaid copied.");
    }).catch(function (error) {
      toast(error.message, "error");
    });
  }

  function changeTopologyZoom(action) {
    if (action === "in") state.topology.zoom = Math.min(2, state.topology.zoom + 0.2);
    else if (action === "out") state.topology.zoom = Math.max(0.6, state.topology.zoom - 0.2);
    else state.topology.zoom = 1;
    state.topology.zoom = Math.round(state.topology.zoom * 10) / 10;
    var graph = document.querySelector(".overlay-topology-svg");
    if (graph) {
      var baseWidth = Number(graph.dataset.baseWidth) || 760;
      graph.style.width = Math.round(baseWidth * state.topology.zoom) + "px";
    }
    var label = $("overlay-zoom-value");
    if (label) label.textContent = Math.round(state.topology.zoom * 100) + "%";
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
    if (location.protocol !== "https:") {
      showAuth("");
      return;
    }
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
    if (event.target.matches("[data-topology-setting]")) {
      updateTopologySetting(event.target);
      return;
    }
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
    if (event.target.matches("#web-ui-endpoint-select")) {
      var endpoint = event.target.value;
      var selected = state.webUi.endpoints.find(function (entry) { return entry.url === endpoint; });
      $("web-ui-endpoint-remove").hidden = !selected || selected.source !== "manual_seed";
      if (endpoint && endpoint !== state.webUi.selectedUrl) selectWebUiEndpoint(endpoint);
      return;
    }
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
    var degree = event.target.closest("[data-overlay-degree]");
    if (degree) {
      setOverlayDegree(degree.dataset.overlayDegree);
      return;
    }
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
      if (state.activeView === "topology") loadTopologyView(!state.topology.dirty);
      return;
    }
    var navigate = event.target.closest("[data-navigate]");
    if (navigate) {
      state.activeView = navigate.dataset.navigate;
      renderView();
      if (state.activeView === "topology") loadTopologyView(!state.topology.dirty);
      return;
    }
    var node = event.target.closest("[data-node-id]");
    if (node) {
      openNodeDrawer(node.dataset.nodeId);
      return;
    }
    var group = event.target.closest("[data-topology-group]");
    if (group) {
      state.topology.selectedGroupId = String(group.dataset.topologyGroup);
      renderView();
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
      if (state.activeView === "topology") loadTopologyView(false);
      else loadOverview();
      return;
    }
    if (event.target.closest("#retry-topology")) {
      loadTopologyView(false);
      return;
    }
    if (event.target.closest("#save-overlay-settings")) {
      saveOverlaySettings();
      return;
    }
    if (event.target.closest("#copy-topology-mermaid")) {
      copyTopologyMermaid();
      return;
    }
    var zoom = event.target.closest("[data-topology-zoom]");
    if (zoom) {
      changeTopologyZoom(zoom.dataset.topologyZoom);
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
    if (event.target.closest("#web-ui-endpoint-refresh")) {
      loadWebUiEndpoints();
      return;
    }
    if (event.target.closest("#web-ui-endpoint-remove")) {
      removeSelectedWebUiEndpoint();
      return;
    }
  });

  document.addEventListener("keydown", function (event) {
    if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-node-id]")) {
      event.preventDefault();
      openNodeDrawer(event.target.dataset.nodeId);
      return;
    }
    if ((event.key === "Enter" || event.key === " ") && event.target.matches("[data-topology-group]")) {
      event.preventDefault();
      state.topology.selectedGroupId = String(event.target.dataset.topologyGroup);
      renderView();
      return;
    }
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

  $("web-ui-bootstrap-form").addEventListener("submit", function (event) {
    event.preventDefault();
    var endpoint = $("web-ui-bootstrap-endpoint").value.trim();
    if (endpoint) bootstrapWebUiEndpoint(endpoint);
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
    if (state.activeView !== "topology" && state.token && !state.loading && !state.policyDirty) loadOverview();
  }, 10000);

  setInterval(function () {
    if (state.config && state.config.local_agent && !state.webUi.loading) loadWebUiEndpoints();
  }, 15000);

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
