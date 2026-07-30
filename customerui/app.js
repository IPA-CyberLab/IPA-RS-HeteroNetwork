const TOKEN_KEY = "heteronetwork_customer_access_token";
const EXPIRES_KEY = "heteronetwork_customer_access_token_expires_at";

const state = {
  config: null,
  session: null,
  projects: [],
  projectCursor: "",
  selectedProjectId: "",
  services: [],
  serviceCursor: "",
  view: "services",
};

const elements = Object.fromEntries([
  "auth-panel", "workspace", "account-name", "account-email", "account-avatar",
  "project-select", "view-title", "service-count", "direct-count", "forwarded-count",
  "address-count", "namespace-label", "services-body", "services-empty", "service-search",
  "services-more", "project-list", "projects-more", "quota-list", "toast",
  "project-dialog", "service-dialog",
].map((id) => [id, document.getElementById(id)]));

document.getElementById("logout-button").addEventListener("click", logout);
document.getElementById("refresh-button").addEventListener("click", () => loadAll(true));
document.getElementById("create-project-button").addEventListener("click", () => elements["project-dialog"].showModal());
document.getElementById("create-service-button").addEventListener("click", openServiceDialog);
elements["project-select"].addEventListener("change", async (event) => {
  state.selectedProjectId = event.target.value;
  await loadServices();
  render();
});
elements["service-search"].addEventListener("input", renderServices);
document.getElementById("project-form").addEventListener("submit", createProject);
document.getElementById("service-form").addEventListener("submit", createService);
elements["projects-more"].addEventListener("click", loadMoreProjects);
elements["services-more"].addEventListener("click", loadMoreServices);
document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => setView(button.dataset.view));
});

bootstrap().catch((error) => showFatal(error));

async function bootstrap() {
  state.config = await fetchJson("/cloud/config", { auth: false });
  if (!accessToken() && !await refreshSession()) {
    showAuth();
    return;
  }
  await loadAll(false);
}

async function loadAll(showNotice) {
  try {
    const [session, projects] = await Promise.all([
      api("/v1/customer/session"),
      api("/v1/customer/projects"),
    ]);
    state.session = session;
    state.projects = arrayFrom(projects, "projects").map(normalizeProject);
    state.projectCursor = String(projects.next_cursor || "");
    if (!state.projects.some((project) => project.id === state.selectedProjectId)) {
      state.selectedProjectId = state.projects[0]?.id || "";
    }
    await loadServices();
    showWorkspace();
    render();
    if (showNotice) toast("更新しました");
  } catch (error) {
    if (error.status === 401) {
      clearSession();
      showAuth();
      return;
    }
    throw error;
  }
}

async function loadServices() {
  if (!state.selectedProjectId) {
    state.services = [];
    state.serviceCursor = "";
    return;
  }
  const result = await api(
    `/v1/customer/projects/${encodeURIComponent(state.selectedProjectId)}/public-services`,
  );
  state.services = arrayFrom(result, "public_services", "services").map(normalizeService);
  state.serviceCursor = String(result.next_cursor || "");
}

async function loadMoreProjects() {
  if (!state.projectCursor) return;
  const button = elements["projects-more"];
  button.disabled = true;
  try {
    const result = await api(`/v1/customer/projects?cursor=${encodeURIComponent(state.projectCursor)}`);
    state.projects.push(...arrayFrom(result, "projects").map(normalizeProject));
    state.projectCursor = String(result.next_cursor || "");
    render();
  } finally {
    button.disabled = false;
  }
}

async function loadMoreServices() {
  if (!state.selectedProjectId || !state.serviceCursor) return;
  const button = elements["services-more"];
  button.disabled = true;
  try {
    const result = await api(
      `/v1/customer/projects/${encodeURIComponent(state.selectedProjectId)}/public-services`
      + `?cursor=${encodeURIComponent(state.serviceCursor)}`,
    );
    state.services.push(...arrayFrom(result, "public_services", "services").map(normalizeService));
    state.serviceCursor = String(result.next_cursor || "");
    render();
  } finally {
    button.disabled = false;
  }
}

function render() {
  renderAccount();
  renderProjects();
  renderServices();
  renderUsage();
  renderProjectPicker();
  setView(state.view);
}

function renderAccount() {
  const principal = state.session?.principal || state.session?.identity || {};
  const account = state.session?.account || {};
  const name = principal.display_name || principal.preferred_username || account.display_name || "Account";
  elements["account-name"].textContent = name;
  elements["account-email"].textContent = principal.email || account.account_id || account.id || "";
  elements["account-avatar"].textContent = [...name][0]?.toUpperCase() || "A";
}

function renderProjectPicker() {
  elements["project-select"].replaceChildren(...state.projects.map((project) => {
    const option = document.createElement("option");
    option.value = project.id;
    option.textContent = project.name;
    option.selected = project.id === state.selectedProjectId;
    return option;
  }));
  elements["project-select"].disabled = state.projects.length === 0;
  document.getElementById("create-service-button").disabled = !state.selectedProjectId;
}

function renderServices() {
  const query = elements["service-search"].value.trim().toLowerCase();
  const visible = state.services.filter((service) => {
    const spec = service.spec || service;
    return !query || [service.name, spec.backend_service, service.id]
      .some((value) => String(value || "").toLowerCase().includes(query));
  });
  elements["services-body"].replaceChildren(...visible.map(serviceRow));
  elements["services-empty"].hidden = visible.length !== 0;
  elements["services-more"].hidden = !state.serviceCursor;

  const project = selectedProject();
  elements["namespace-label"].textContent = `Kubernetes namespace: ${project?.kubernetes_namespace || "-"}`;
  elements["service-count"].textContent = String(state.services.length);
  elements["direct-count"].textContent = String(state.services.filter((item) => serviceMode(item) === "direct").length);
  elements["forwarded-count"].textContent = String(state.services.filter((item) => serviceMode(item) === "forwarded").length);
  elements["address-count"].textContent = String(
    state.services.reduce((count, item) => count + serviceAddresses(item).length, 0),
  );
}

function serviceRow(service) {
  const spec = service.spec || service;
  const status = service.status || {};
  const row = document.createElement("tr");
  const mode = serviceMode(service);
  const phase = String(status.phase || "pending").toLowerCase();
  row.innerHTML = `
    <td><span class="resource-name"><strong></strong><small></small></span></td>
    <td><span class="badge ${escapeClass(mode)}"></span></td>
    <td></td>
    <td></td>
    <td></td>
    <td><span class="status ${escapeClass(phase)}"></span></td>
    <td><span class="addresses"></span></td>
    <td><button class="icon-button danger-button" type="button" title="削除" aria-label="削除">×</button></td>
  `;
  row.querySelector(".resource-name strong").textContent = service.name;
  row.querySelector(".resource-name small").textContent = service.id;
  row.querySelector(".badge").textContent = titleCase(mode);
  row.children[2].textContent = String(spec.protocol || "-").toUpperCase();
  row.children[3].textContent = String(spec.public_port || "-");
  row.children[4].textContent = `${spec.backend_service || "-"}:${spec.backend_port || "-"}`;
  row.querySelector(".status").textContent = titleCase(phase);
  row.querySelector(".addresses").replaceChildren(...serviceAddresses(service).map((address) => {
    const span = document.createElement("span");
    span.textContent = address;
    return span;
  }));
  row.querySelector("button").addEventListener("click", () => deleteService(service));
  return row;
}

function renderProjects() {
  elements["project-list"].replaceChildren(...state.projects.map((project) => {
    const row = document.createElement("article");
    row.className = "project-row";
    row.innerHTML = `
      <div><h3></h3><p></p></div>
      <dl><dt>Namespace</dt><dd></dd></dl>
      <button class="icon-button danger-button" type="button" title="削除" aria-label="削除">×</button>
    `;
    row.querySelector("h3").textContent = project.name;
    row.querySelector("p").textContent = project.id;
    row.querySelector("dd").textContent = project.kubernetes_namespace || "-";
    row.querySelector("button").addEventListener("click", (event) => {
      event.stopPropagation();
      deleteProject(project);
    });
    row.addEventListener("click", async () => {
      state.selectedProjectId = project.id;
      await loadServices();
      setView("services");
      render();
    });
    return row;
  }));
  elements["projects-more"].hidden = !state.projectCursor;
}

function renderUsage() {
  const quota = state.session?.account?.quota || state.session?.quota || state.session?.quotas || {};
  const rows = [
    ["プロジェクト", state.projects.length, quota.max_projects, true],
    ["公開サービス（アカウント全体）", null, quota.max_public_services, false],
  ];
  elements["quota-list"].replaceChildren(...rows.map(([label, used, limit, showUsed]) => {
    const row = document.createElement("div");
    const dt = document.createElement("dt");
    const dd = document.createElement("dd");
    dt.textContent = label;
    if (limit == null) {
      dd.textContent = showUsed ? String(used) : "-";
    } else {
      dd.textContent = showUsed ? `${used} / ${limit}` : `上限 ${limit}`;
    }
    row.append(dt, dd);
    return row;
  }));
}

function setView(view) {
  state.view = view;
  const labels = { services: "公開サービス", projects: "プロジェクト", usage: "使用量" };
  elements["view-title"].textContent = labels[view] || labels.services;
  for (const name of Object.keys(labels)) {
    document.getElementById(`${name}-view`).hidden = name !== view;
  }
  document.querySelectorAll(".nav-item").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.view === view);
  });
  document.querySelector(".topbar-actions").hidden = view === "usage";
  document.getElementById("create-service-button").hidden = view !== "services";
}

async function createProject(event) {
  event.preventDefault();
  if (event.submitter?.value === "cancel") return elements["project-dialog"].close();
  const data = new FormData(event.currentTarget);
  try {
    const project = await api("/v1/customer/projects", {
      method: "POST",
      body: JSON.stringify({ name: data.get("name") }),
    });
    const created = normalizeProject(project.project || project);
    state.projects.push(created);
    state.selectedProjectId = created.id;
    event.currentTarget.reset();
    elements["project-dialog"].close();
    await loadServices();
    render();
    toast("プロジェクトを作成しました");
  } catch (error) {
    toast(error.message, true);
  }
}

function openServiceDialog() {
  if (!state.selectedProjectId) {
    toast("先にプロジェクトを作成してください", true);
    return;
  }
  elements["service-dialog"].showModal();
}

async function createService(event) {
  event.preventDefault();
  if (event.submitter?.value === "cancel") return elements["service-dialog"].close();
  const data = new FormData(event.currentTarget);
  const body = {
    name: data.get("name"),
    spec: {
      traffic_mode: data.get("traffic_mode"),
      protocol: String(data.get("protocol")).toUpperCase(),
      public_port: Number(data.get("public_port")),
      backend_service: data.get("backend_service"),
      backend_port: Number(data.get("backend_port")),
      ingress_replicas: Number(data.get("ingress_replicas")),
    },
  };
  try {
    const result = await api(
      `/v1/customer/projects/${encodeURIComponent(state.selectedProjectId)}/public-services`,
      { method: "POST", body: JSON.stringify(body) },
    );
    state.services.push(normalizeService(result.public_service || result.service || result));
    event.currentTarget.reset();
    event.currentTarget.elements.ingress_replicas.value = "2";
    event.currentTarget.elements.traffic_mode.value = "forwarded";
    elements["service-dialog"].close();
    render();
    toast("公開サービスを作成しました");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteService(service) {
  if (!confirm(`${service.name} を削除しますか？`)) return;
  try {
    await api(
      `/v1/customer/projects/${encodeURIComponent(state.selectedProjectId)}/public-services/${encodeURIComponent(service.id)}`,
      { method: "DELETE" },
    );
    state.services = state.services.filter((item) => item.id !== service.id);
    render();
    toast("公開サービスを削除しました");
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteProject(project) {
  if (!confirm(`${project.name} と配下の公開サービスを削除しますか？`)) return;
  try {
    await api(`/v1/customer/projects/${encodeURIComponent(project.id)}`, {
      method: "DELETE",
    });
    state.projects = state.projects.filter((item) => item.id !== project.id);
    if (state.selectedProjectId === project.id) {
      state.selectedProjectId = state.projects[0]?.id || "";
      await loadServices();
    }
    render();
    toast("プロジェクトを削除しました");
  } catch (error) {
    toast(error.message, true);
  }
}

async function logout() {
  try {
    await fetch(state.config?.session_logout_endpoint || "/cloud/auth/logout", {
      method: "POST",
      headers: sameOriginHeaders(),
    });
  } finally {
    clearSession();
    location.replace("/cloud/");
  }
}

async function api(path, init = {}) {
  let token = accessToken();
  if (!token) throw httpError(401, "ログインが必要です");
  let response = await fetch(path, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...(init.headers || {}),
      Authorization: `Bearer ${token}`,
    },
  });
  if (response.status === 401 && await refreshSession()) {
    token = accessToken();
    response = await fetch(path, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(init.headers || {}),
        Authorization: `Bearer ${token}`,
      },
    });
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw httpError(response.status, payload.error || `HTTP ${response.status}`);
  return payload;
}

async function refreshSession() {
  const endpoint = state.config?.session_refresh_endpoint;
  if (!endpoint) return false;
  const response = await fetch(endpoint, { method: "POST", headers: sameOriginHeaders() });
  if (!response.ok) {
    clearSession();
    return false;
  }
  const tokens = await response.json();
  sessionStorage.setItem(TOKEN_KEY, tokens.access_token);
  sessionStorage.setItem(EXPIRES_KEY, String(Date.now() + Number(tokens.expires_in || 0) * 1000));
  return true;
}

async function fetchJson(path, { auth = true } = {}) {
  return auth ? api(path) : fetch(path).then((response) => response.json());
}

function accessToken() {
  const token = sessionStorage.getItem(TOKEN_KEY) || "";
  const expires = Number(sessionStorage.getItem(EXPIRES_KEY) || 0);
  if (!token) return "";
  if (expires && expires <= Date.now() + 10_000) return "";
  return token;
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(EXPIRES_KEY);
}

function showAuth() {
  elements["auth-panel"].hidden = false;
  elements.workspace.hidden = true;
}

function showWorkspace() {
  elements["auth-panel"].hidden = true;
  elements.workspace.hidden = false;
}

function showFatal(error) {
  console.error(error);
  toast(error.message || "読み込みに失敗しました", true);
  if (!accessToken()) showAuth();
}

function toast(message, error = false) {
  const element = elements.toast;
  element.textContent = message;
  element.classList.toggle("error", error);
  element.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { element.hidden = true; }, 5000);
}

function selectedProject() {
  return state.projects.find((project) => project.id === state.selectedProjectId);
}

function serviceMode(service) {
  return String((service.spec || service).traffic_mode || "forwarded").toLowerCase();
}

function serviceAddresses(service) {
  const status = service.status || {};
  return Array.isArray(status.public_addresses)
    ? status.public_addresses.map((address) => (
      typeof address === "string"
        ? address
        : `${address.host || "-"}:${address.port || "-"}`
    ))
    : [];
}

function arrayFrom(value, ...keys) {
  if (Array.isArray(value)) return value;
  for (const key of keys) if (Array.isArray(value?.[key])) return value[key];
  return [];
}

function normalizeProject(project) {
  return { ...project, id: project?.id || project?.project_id || "" };
}

function normalizeService(service) {
  return { ...service, id: service?.id || service?.resource_id || "" };
}

function sameOriginHeaders() {
  return { Origin: location.origin, "Sec-Fetch-Site": "same-origin" };
}

function titleCase(value) {
  const text = String(value || "");
  return text ? text[0].toUpperCase() + text.slice(1) : "-";
}

function escapeClass(value) {
  return String(value || "").replace(/[^a-z0-9_-]/gi, "");
}

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}
