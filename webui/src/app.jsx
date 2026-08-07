import AppLayout from "@cloudscape-design/components/app-layout";
import Box from "@cloudscape-design/components/box";
import BreadcrumbGroup from "@cloudscape-design/components/breadcrumb-group";
import Button from "@cloudscape-design/components/button";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import Flashbar from "@cloudscape-design/components/flashbar";
import Form from "@cloudscape-design/components/form";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import SideNavigation from "@cloudscape-design/components/side-navigation";
import SpaceBetween from "@cloudscape-design/components/space-between";
import StatusIndicator from "@cloudscape-design/components/status-indicator";
import TopNavigation from "@cloudscape-design/components/top-navigation";
import { applyMode, Mode } from "@cloudscape-design/global-styles";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api.js";
import { ErrorAlert, Loading } from "./components.jsx";
import { AclPage } from "./pages/acl-page.jsx";
import { EnrollmentPage } from "./pages/enrollment-page.jsx";
import { NodeDetailModal, NodesPage } from "./pages/nodes-page.jsx";
import { OverviewPage } from "./pages/overview-page.jsx";
import { PathsPage } from "./pages/paths-page.jsx";
import { RoutesPage } from "./pages/routes-page.jsx";
import { TopologyPage } from "./pages/topology-page.jsx";

const pageMetadata = {
  overview: ["概要", "ネットワーク全体の状態を確認します。"],
  nodes: ["ノード", "参加している実マシンと稼働サービスを確認します。"],
  paths: ["接続", "選択されたピア経路とオペレーター制御です。"],
  topology: ["オーバーレイトポロジー", "再帰グループと転送リンクを確認します。"],
  routes: ["ネットワークルート", "広報されたネットワークと所有ノードです。"],
  acl: ["アクセス制御", "実行時の接続ポリシーとルールです。"],
  enrollment: ["ノードを追加", "短期認証情報を発行して端末を参加させます。"],
};

function hashView() {
  const view = window.location.hash.replace(/^#\/?/, "");
  return pageMetadata[view] ? view : "overview";
}

function LoginPage({ config, error, onLogin, onBootstrap, busy }) {
  const [endpoint, setEndpoint] = useState("");
  const bootstrapRequired = Boolean(config?.local_agent && config?.bootstrap_required);
  const provider = config?.provider
    ? config.provider.charAt(0).toUpperCase() + config.provider.slice(1)
    : "SSO";

  return (
    <main className="login-page">
      <div className="login-page__content">
        <SpaceBetween size="l">
          <div>
            <Box variant="h1">HeteroNetwork</Box>
            <Box color="text-body-secondary">ネットワーク管理コンソール</Box>
          </div>
          <Container
            header={
              <Header
                variant="h2"
                description={
                  bootstrapRequired
                    ? "到達可能なHeteroNetworkノードを指定してください。"
                    : "設定済みのIDプロバイダーで続行します。"
                }
              >
                {bootstrapRequired ? "ネットワークへ接続" : "ログイン"}
              </Header>
            }
          >
            <SpaceBetween size="l">
              {error ? <ErrorAlert error={error} /> : null}
              {bootstrapRequired ? (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    if (endpoint.trim()) onBootstrap(endpoint.trim());
                  }}
                >
                  <Form
                    actions={
                      <Button variant="primary" loading={busy} formAction="submit">
                        接続
                      </Button>
                    }
                  >
                    <FormField label="Web UIアドレス">
                      <Input
                        value={endpoint}
                        placeholder="10.250.0.4 または http://10.250.0.4:18088"
                        onChange={({ detail }) => setEndpoint(detail.value)}
                      />
                    </FormField>
                  </Form>
                </form>
              ) : config?.auth_enabled ? (
                <Button
                  variant="primary"
                  fullWidth
                  iconName="user-profile"
                  loading={busy}
                  onClick={onLogin}
                >
                  {provider}でログイン
                </Button>
              ) : null}
            </SpaceBetween>
          </Container>
          <StatusIndicator type="info">
            セッションはコントロールプレーンで保護されます
          </StatusIndicator>
        </SpaceBetween>
      </div>
    </main>
  );
}

export function App() {
  const [config, setConfig] = useState(null);
  const [session, setSession] = useState(api.hasSession());
  const [overview, setOverview] = useState(null);
  const [topology, setTopology] = useState(null);
  const [activeView, setActiveView] = useState(hashView);
  const [loading, setLoading] = useState(true);
  const [topologyLoading, setTopologyLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [pinningKey, setPinningKey] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [removingNode, setRemovingNode] = useState(false);
  const [renamingNode, setRenamingNode] = useState(false);
  const [error, setError] = useState(null);
  const [topologyError, setTopologyError] = useState(null);
  const [navigationOpen, setNavigationOpen] = useState(true);
  const [directory, setDirectory] = useState(null);
  const [flashItems, setFlashItems] = useState([]);
  const [theme, setTheme] = useState(
    () => localStorage.getItem("heteronetwork_theme") || "light",
  );

  const notify = useCallback((content, type = "success") => {
    const id = `${Date.now()}-${Math.random()}`;
    setFlashItems((items) => [
      ...items,
      {
        id,
        type,
        content,
        dismissible: true,
        onDismiss: () => setFlashItems((current) => current.filter((item) => item.id !== id)),
      },
    ]);
  }, []);

  const loadOverview = useCallback(async (silent = false) => {
    if (!api.hasSession()) return;
    if (!silent) setLoading(true);
    try {
      const [nextOverview, keycloakPlacement] = await Promise.all([
        api.request("/v1/admin/overview"),
        api.request("/v1/admin/keycloak-placement").catch(() => null),
      ]);
      setOverview({ ...nextOverview, keycloak_placement: keycloakPlacement });
      setError(null);
    } catch (loadError) {
      if (loadError.message !== "authentication required") setError(loadError);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  const loadTopology = useCallback(async () => {
    if (!api.hasSession()) return;
    setTopologyLoading(true);
    try {
      const [snapshot, policyResponse] = await Promise.all([
        api.request("/v1/admin/topology"),
        api.request("/v1/admin/policy"),
      ]);
      setTopology(snapshot);
      const policy =
        policyResponse?.cluster_policy || policyResponse?.policy || policyResponse;
      setOverview((current) =>
        current ? { ...current, cluster_policy: policy || current.cluster_policy } : current,
      );
      setTopologyError(null);
    } catch (loadError) {
      if (loadError.message !== "authentication required") setTopologyError(loadError);
    } finally {
      setTopologyLoading(false);
    }
  }, []);

  const loadDirectory = useCallback(async () => {
    if (!api.config?.local_agent) return;
    try {
      setDirectory(await api.localRequest("/v1/web-ui/endpoints"));
    } catch (directoryError) {
      notify(directoryError.message, "error");
    }
  }, [notify]);

  useEffect(() => {
    let active = true;
    api.onAuthenticationRequired = () => {
      setSession(false);
      setOverview(null);
      setTopology(null);
      setError(new Error("セッションの有効期限が切れました。再度ログインしてください。"));
    };
    api
      .loadConfig()
      .then(async (loadedConfig) => {
        if (!active) return;
        setConfig(loadedConfig);
        if (!api.hasSession() && loadedConfig.session_refresh_endpoint) {
          try {
            await api.refreshSession();
          } catch {
            // A missing or expired refresh cookie is a normal signed-out state.
          }
        }
        if (active) setSession(api.hasSession());
      })
      .catch((loadError) => active && setError(loadError))
      .finally(() => active && setLoading(false));
    return () => {
      active = false;
      api.onAuthenticationRequired = null;
    };
  }, []);

  useEffect(() => {
    applyMode(theme === "dark" ? Mode.Dark : Mode.Light);
    localStorage.setItem("heteronetwork_theme", theme);
  }, [theme]);

  useEffect(() => {
    const onHashChange = () => setActiveView(hashView());
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  useEffect(() => {
    if (!session || !config) return undefined;
    void loadOverview();
    void loadDirectory();
    const overviewTimer = window.setInterval(() => void loadOverview(true), 10_000);
    const directoryTimer = window.setInterval(() => void loadDirectory(), 15_000);
    return () => {
      window.clearInterval(overviewTimer);
      window.clearInterval(directoryTimer);
    };
  }, [config, loadDirectory, loadOverview, session]);

  useEffect(() => {
    if (session && activeView === "topology") void loadTopology();
  }, [activeView, loadTopology, session]);

  useEffect(() => {
    if (typeof BroadcastChannel !== "function") return undefined;
    const channel = new BroadcastChannel("heteronetwork-auth");
    channel.onmessage = (event) => {
      if (event.data?.type === "logout") {
        api.clearSession();
        setSession(false);
        setOverview(null);
      }
    };
    return () => channel.close();
  }, []);

  const navigate = (view) => {
    window.location.hash = `/${view}`;
    setActiveView(view);
  };

  const startLogin = async () => {
    setError(null);
    if (config.device_login_endpoint && config.device_login_poll_endpoint) {
      setLoading(true);
      const authWindow = window.open("/ui/auth/wait", "_blank");
      try {
        const response = await fetch(config.device_login_endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        });
        const body = await response.json();
        if (!response.ok) throw new Error(body.error || `ログイン開始に失敗しました (${response.status})`);
        const verificationUrl = body.verification_uri_complete || body.verification_uri;
        if (authWindow && !authWindow.closed) {
          authWindow.location.replace(verificationUrl);
          authWindow.opener = null;
        } else {
          window.open(verificationUrl, "_blank", "noopener,noreferrer");
        }
        setError(new Error(`認証コード: ${body.user_code}`));
        const expiresAt = Date.now() + Math.max(30, body.expires_in || 600) * 1000;
        let tokens = null;
        let retryAfter = body.interval || 5;
        while (Date.now() < expiresAt && !tokens) {
          await new Promise((resolve) => window.setTimeout(resolve, retryAfter * 1000));
          const poll = await fetch(config.device_login_poll_endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ handle: body.handle }),
          });
          const pollBody = await poll.json().catch(() => ({}));
          if (poll.ok && pollBody.status === "complete" && pollBody.access_token) {
            tokens = pollBody;
          } else if ((poll.status === 202 || poll.status === 429) && pollBody.status === "pending") {
            retryAfter = pollBody.retry_after_seconds || retryAfter;
          } else {
            throw new Error(pollBody.error || `デバイスログインに失敗しました (${poll.status})`);
          }
        }
        if (!tokens) throw new Error("デバイスログインの有効期限が切れました");
        api.setOidcSession(tokens);
        setSession(true);
        setError(null);
        authWindow?.close();
      } catch (loginError) {
        authWindow?.close();
        setError(loginError);
      } finally {
        setLoading(false);
      }
      return;
    }
    if (config.login_endpoint) {
      window.location.assign(config.login_endpoint);
      return;
    }
    setError(new Error("サーバー側ログインを利用できません。"));
  };

  const signOut = async () => {
    const provider = config?.provider;
    const logoutEndpoint = config?.logout_endpoint;
    const sessionLogoutEndpoint = config?.session_logout_endpoint;
    api.clearSession();
    setSession(false);
    setOverview(null);
    try {
      new BroadcastChannel("heteronetwork-auth").postMessage({ type: "logout" });
    } catch {
      // Local sign-out remains valid when cross-tab coordination is unavailable.
    }
    if (sessionLogoutEndpoint) {
      await fetch(sessionLogoutEndpoint, {
        method: "POST",
        headers: { Accept: "application/json" },
        credentials: "same-origin",
        keepalive: true,
      }).catch(() => null);
    }
    if (window.location.protocol === "https:" && logoutEndpoint && config?.client_id) {
      const params = new URLSearchParams({ client_id: config.client_id });
      params.set(
        provider === "cognito" ? "logout_uri" : "post_logout_redirect_uri",
        `${window.location.origin}/ui/`,
      );
      window.location.assign(`${logoutEndpoint}?${params}`);
    }
  };

  if (!config || (!session && loading)) return <Loading label="Web UIを初期化しています" />;
  if (!session) {
    return (
      <LoginPage
        config={config}
        error={error || config.connection_error}
        busy={loading}
        onLogin={startLogin}
        onBootstrap={async (endpoint) => {
          setLoading(true);
          try {
            await api.localRequest("/v1/web-ui/bootstrap", {
              method: "POST",
              body: JSON.stringify({ endpoint }),
            });
            window.location.replace(`${window.location.origin}/ui/`);
          } catch (bootstrapError) {
            setError(bootstrapError);
            setLoading(false);
          }
        }}
      />
    );
  }

  const metrics = overview?.metrics || {};
  const navItems = [
    {
      type: "section",
      text: "ネットワーク",
      items: [
        { type: "link", text: "概要", href: "#/overview" },
        { type: "link", text: "ノード", href: "#/nodes", info: String(metrics.node_count ?? "-") },
        ...(config.node_enrollment_enabled || config.client_enrollment_enabled
          ? [{ type: "link", text: "ノードを追加", href: "#/enrollment" }]
          : []),
        { type: "link", text: "接続", href: "#/paths", info: String(metrics.path_count ?? "-") },
        {
          type: "link",
          text: "オーバーレイトポロジー",
          href: "#/topology",
          info: String(topology?.group_count ?? topology?.groups?.length ?? "-"),
        },
        { type: "link", text: "ネットワークルート", href: "#/routes" },
      ],
    },
    {
      type: "section",
      text: "セキュリティ",
      items: [
        {
          type: "link",
          text: "アクセス制御",
          href: "#/acl",
          info: String(overview?.cluster_policy?.acl_rules?.length ?? "-"),
        },
      ],
    },
  ];

  const endpointItems = (directory?.endpoints || []).map((endpoint) => ({
    id: `endpoint:${endpoint.url}`,
    text: `${endpoint.reachable ? "到達可能" : "到達不可"} - ${endpoint.url}`,
    iconName: endpoint.reachable ? "status-positive" : "status-negative",
  }));
  if (config.local_agent) {
    endpointItems.push({ id: "refresh-endpoints", text: "到達性を再確認", iconName: "refresh" });
    const selected = (directory?.endpoints || []).find(
      (endpoint) => endpoint.url === directory?.selected_url,
    );
    if (selected?.source === "manual_seed") {
      endpointItems.push({ id: "remove-endpoint", text: "選択中ノードを削除", iconName: "remove" });
    }
  }

  const renderPage = () => {
    if (loading && !overview) return <Loading label="クラスター状態を読み込んでいます" />;
    if (error && !overview) return <ErrorAlert error={error} onRetry={() => loadOverview()} />;
    if (!overview) return null;
    switch (activeView) {
      case "nodes":
        return <NodesPage overview={overview} onOpenNode={setSelectedNode} />;
      case "paths":
        return (
          <PathsPage
            overview={overview}
            pinningKey={pinningKey}
            onPin={async (path) => {
              const key = `${path.key.local}/${path.key.remote}`;
              setPinningKey(key);
              try {
                await api.request(
                  `/v1/admin/paths/${encodeURIComponent(path.key.local)}/${encodeURIComponent(path.key.remote)}/pin`,
                  { method: "POST", body: JSON.stringify({ pinned: !path.pinned }) },
                );
                notify(path.pinned ? "経路の固定を解除しました。" : "経路を固定しました。");
                await loadOverview(true);
              } catch (pinError) {
                notify(pinError.message, "error");
              } finally {
                setPinningKey(null);
              }
            }}
          />
        );
      case "routes":
        return <RoutesPage overview={overview} onOpenNode={setSelectedNode} />;
      case "acl":
        return (
          <AclPage
            overview={overview}
            saving={saving}
            onSave={async (policy) => {
              setSaving(true);
              try {
                const response = await api.request("/v1/admin/policy", {
                  method: "PUT",
                  body: JSON.stringify({ cluster_policy: policy }),
                });
                const saved = response.cluster_policy || response.policy || response;
                setOverview((current) => ({ ...current, cluster_policy: saved }));
                notify("ポリシーを保存しました。");
                return response;
              } finally {
                setSaving(false);
              }
            }}
          />
        );
      case "topology":
        return (
          <TopologyPage
            topology={topology}
            policy={overview.cluster_policy}
            loading={topologyLoading}
            error={topologyError}
            saving={saving}
            onReload={loadTopology}
            onNotify={notify}
            onSaveSettings={async (settings) => {
              setSaving(true);
              try {
                const nextPolicy = { ...overview.cluster_policy, ...settings };
                const response = await api.request("/v1/admin/policy", {
                  method: "PUT",
                  body: JSON.stringify({ cluster_policy: nextPolicy }),
                });
                const saved = response.cluster_policy || response.policy || response;
                setOverview((current) => ({ ...current, cluster_policy: saved }));
                notify("階層設定を保存しました。");
                await loadTopology();
              } catch (saveError) {
                notify(saveError.message, "error");
              } finally {
                setSaving(false);
              }
            }}
          />
        );
      case "enrollment":
        return (
          <EnrollmentPage
            config={config}
            issuing={issuing}
            onNotify={notify}
            onIssue={async (mode, body) => {
              setIssuing(true);
              try {
                return await api.request(
                  mode === "desktop" ? "/v1/admin/client-enrollment" : "/v1/admin/enrollment",
                  { method: "POST", body: JSON.stringify(body) },
                );
              } finally {
                setIssuing(false);
              }
            }}
          />
        );
      default:
        return (
          <OverviewPage
            overview={overview}
            onNavigate={navigate}
            onOpenNode={setSelectedNode}
          />
        );
    }
  };

  const hasOwnHeader = ["acl", "topology", "enrollment"].includes(activeView);
  const content = hasOwnHeader ? (
    renderPage()
  ) : (
    <ContentLayout
      header={
        <Header
          variant="h1"
          description={pageMetadata[activeView]?.[1]}
          actions={
            <Button iconName="refresh" loading={loading} onClick={() => loadOverview()}>
              更新
            </Button>
          }
        >
          {pageMetadata[activeView]?.[0]}
        </Header>
      }
    >
      {renderPage()}
    </ContentLayout>
  );

  return (
    <div className="network-console">
      <header id="hn-header" className="network-console__header">
        <TopNavigation
          identity={{ href: "#/overview", title: "HeteroNetwork" }}
          utilities={[
            {
              type: "button",
              text: overview ? "接続済み" : "接続中",
              iconName: overview ? "status-positive" : "status-pending",
              onClick: () => loadOverview(),
            },
            ...(config.local_agent
              ? [
                  {
                    type: "menu-dropdown",
                    text: "Web UIノード",
                    description: directory?.selected_url || "未接続",
                    iconName: "multiscreen",
                    items: endpointItems,
                    onItemClick: async ({ detail }) => {
                      if (detail.id === "refresh-endpoints") return loadDirectory();
                      if (detail.id === "remove-endpoint") {
                        await api.localRequest("/v1/web-ui/endpoints", {
                          method: "DELETE",
                          body: JSON.stringify({ endpoint: directory.selected_url }),
                        });
                        return loadDirectory();
                      }
                      if (detail.id.startsWith("endpoint:")) {
                        await api.localRequest("/v1/web-ui/select", {
                          method: "POST",
                          body: JSON.stringify({ endpoint: detail.id.slice("endpoint:".length) }),
                        });
                        window.location.reload();
                      }
                    },
                  },
                ]
              : []),
            {
              type: "button",
              iconName: "light-dark",
              ariaLabel: theme === "dark" ? "ライトモードに切り替え" : "ダークモードに切り替え",
              onClick: () => setTheme((current) => (current === "dark" ? "light" : "dark")),
            },
            {
              type: "menu-dropdown",
              text: "管理者",
              description: overview?.cluster_id || "HeteroNetwork",
              iconName: "user-profile",
              items: [{ id: "logout", text: "ログアウト", iconName: "sign-out" }],
              onItemClick: ({ detail }) => detail.id === "logout" && signOut(),
            },
          ]}
          i18nStrings={{
            overflowMenuTriggerText: "その他",
            overflowMenuTitleText: "メニュー",
          }}
        />
      </header>
      <AppLayout
        headerSelector="#hn-header"
        navigationOpen={navigationOpen}
        onNavigationChange={({ detail }) => setNavigationOpen(detail.open)}
        navigation={
          <SideNavigation
            header={{ href: "#/overview", text: "ネットワーク管理" }}
            activeHref={`#/${activeView}`}
            items={navItems}
            onFollow={(event) => {
              event.preventDefault();
              navigate(event.detail.href.replace(/^#\//, ""));
            }}
          />
        }
        breadcrumbs={
          <BreadcrumbGroup
            items={[
              { text: "HeteroNetwork", href: "#/overview" },
              { text: pageMetadata[activeView]?.[0] || "概要", href: `#/${activeView}` },
            ]}
          />
        }
        notifications={flashItems.length ? <Flashbar items={flashItems} /> : null}
        content={content}
        contentType={activeView === "overview" ? "dashboard" : activeView === "enrollment" || activeView === "acl" ? "form" : "table"}
        toolsHide
        ariaLabels={{
          navigation: "ナビゲーション",
          navigationToggle: "ナビゲーションを開く",
          navigationClose: "ナビゲーションを閉じる",
          notifications: "通知",
        }}
      />
      <NodeDetailModal
        entry={selectedNode}
        visible={Boolean(selectedNode)}
        loading={removingNode}
        renaming={renamingNode}
        onDismiss={() => setSelectedNode(null)}
        onRename={async (nodeId, displayName) => {
          setRenamingNode(true);
          try {
            const node = await api.request(
              `/v1/admin/nodes/${encodeURIComponent(nodeId)}/display-name`,
              {
                method: "PUT",
                body: JSON.stringify({ display_name: displayName }),
              },
            );
            setSelectedNode((current) =>
              current?.node?.node_id === nodeId ? { ...current, node } : current,
            );
            notify(displayName ? "ノード名を変更しました。" : "OSホスト名の表示に戻しました。");
            await loadOverview(true);
            return true;
          } catch (renameError) {
            notify(renameError.message, "error");
            return false;
          } finally {
            setRenamingNode(false);
          }
        }}
        onRemove={async (nodeId) => {
          setRemovingNode(true);
          try {
            await api.request(`/v1/admin/nodes/${encodeURIComponent(nodeId)}`, {
              method: "DELETE",
            });
            setSelectedNode(null);
            notify("ノードを削除しました。");
            await loadOverview(true);
          } catch (removeError) {
            notify(removeError.message, "error");
          } finally {
            setRemovingNode(false);
          }
        }}
      />
    </div>
  );
}
