(function () {
  "use strict";

  var state = {
    config: null,
    overview: null,
    token: sessionStorage.getItem("ipars_access_token")
      || sessionStorage.getItem("ipars_operator_token")
      || "",
    activeView: "overview",
    selectedNodeId: null,
    loading: false
  };

  function $(id) {
    return document.getElementById(id);
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
    return text.length > 16 ? text.slice(0, 8) + "..." + text.slice(-6) : text || "-";
  }

  function formatTime(value) {
    if (!value) return "-";
    var date = new Date(value);
    return isNaN(date.getTime()) ? "-" : date.toLocaleString();
  }

  function age(value) {
    if (!value) return "-";
    var seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
    if (seconds < 60) return seconds + "s ago";
    if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
    return Math.floor(seconds / 3600) + "h ago";
  }

  function listTags(tags) {
    var values = Array.isArray(tags) ? tags : Object.keys(tags || {});
    if (!values.length) return "<span class='muted'>None</span>";
    return "<span class='tag-list'>" + values.map(function (tag) {
      return "<span class='tag'>" + escapeHtml(tag) + "</span>";
    }).join("") + "</span>";
  }

  function stateClass(value) {
    var text = String(value || "").toLowerCase();
    if (text.indexOf("healthy") !== -1) return "healthy";
    if (text.indexOf("degraded") !== -1) return "degraded";
    if (text.indexOf("unhealthy") !== -1) return "unhealthy";
    if (text.indexOf("relay") !== -1) return "relay";
    if (text.indexOf("nat") !== -1) return "nat";
    if (text.indexOf("ipv6") !== -1) return "ipv6";
    if (text.indexOf("unreachable") !== -1) return "unreachable";
    if (text.indexOf("direct") !== -1) return "direct";
    return "unknown";
  }

  function statusPill(value) {
    var text = String(value || "unknown").replace(/_/g, " ");
    return "<span class='status-pill " + stateClass(value) + "'>"
      + escapeHtml(text) + "</span>";
  }

  function setStatus(message, error) {
    var node = $("status-message");
    node.textContent = message || "";
    node.classList.toggle("error", Boolean(error));
  }

  function setConnection(online) {
    var node = $("connection-state");
    node.textContent = online ? "Connected" : "Offline";
    node.className = "connection-state " + (online ? "online" : "offline");
  }

  async function api(path, options) {
    var request = options || {};
    var headers = new Headers(request.headers || {});
    headers.set("Accept", "application/json");
    if (state.token) headers.set("Authorization", "Bearer " + state.token);
    if (request.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    var response = await fetch(path, Object.assign({}, request, { headers: headers }));
    if (response.status === 401) {
      clearSession();
      showAuth("Your session expired. Sign in again.");
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
  }

  function clearSession() {
    state.token = "";
    sessionStorage.removeItem("ipars_access_token");
    sessionStorage.removeItem("ipars_operator_token");
  }

  function showAuth(message) {
    $("auth-panel").hidden = false;
    $("dashboard").hidden = true;
    $("auth-error").textContent = message || "";
    $("auth-button").textContent = "Sign in";
  }

  function showDashboard() {
    $("auth-panel").hidden = true;
    $("dashboard").hidden = false;
    $("auth-button").textContent = "Sign out";
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

  async function pkceChallenge(verifier) {
    var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return base64Url(new Uint8Array(digest));
  }

  async function startLogin() {
    if (!state.config || !state.config.authorization_endpoint) return;
    var verifier = base64Url(randomBytes(32));
    var challenge = await pkceChallenge(verifier);
    var loginState = base64Url(randomBytes(24));
    sessionStorage.setItem("ipars_pkce_verifier", verifier);
    sessionStorage.setItem("ipars_login_state", loginState);
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
  }

  async function exchangeCode() {
    var query = new URLSearchParams(location.search);
    var code = query.get("code");
    if (!code) return false;
    if (query.get("state") !== sessionStorage.getItem("ipars_login_state")) {
      throw new Error("OIDC state validation failed");
    }
    var verifier = sessionStorage.getItem("ipars_pkce_verifier");
    if (!verifier) throw new Error("OIDC verifier is missing");
    var body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: state.config.client_id,
      code: code,
      redirect_uri: location.origin + "/ui/",
      code_verifier: verifier
    });
    var response = await fetch(state.config.token_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body
    });
    if (!response.ok) throw new Error("OIDC token exchange failed (" + response.status + ")");
    var tokens = await response.json();
    if (!tokens.access_token) throw new Error("OIDC response did not include an access token");
    state.token = tokens.access_token;
    sessionStorage.setItem("ipars_access_token", state.token);
    sessionStorage.removeItem("ipars_pkce_verifier");
    sessionStorage.removeItem("ipars_login_state");
    history.replaceState({}, document.title, location.origin + "/ui/");
    return true;
  }

  async function loadConfig() {
    var response = await fetch("/ui/config", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("Unable to load UI configuration (" + response.status + ")");
    state.config = await response.json();
    $("oidc-login").hidden = !state.config.auth_enabled;
    $("token-form").hidden = !state.config.operator_token_enabled;
    if (state.config.provider) {
      $("oidc-login").textContent = "Sign in with " + state.config.provider;
    }
    if (!state.config.enabled) {
      $("auth-title").textContent = "Web UI is not configured";
      $("auth-copy").textContent = "Enable the web UI and configure an operator bearer token or OIDC provider on the control-plane daemon.";
    }
  }

  async function loadOverview() {
    if (!state.token) return;
    state.loading = true;
    try {
      state.overview = await api("/v1/admin/overview");
      showDashboard();
      setConnection(true);
      $("cluster-name").textContent = state.overview.cluster_id;
      $("refresh-time").textContent = "Updated " + formatTime(state.overview.generated_at);
      renderView();
    } catch (error) {
      if (error.message !== "authentication required") setStatus(error.message, true);
    } finally {
      state.loading = false;
    }
  }

  function metricCard(label, value, note) {
    return "<div class='metric-card'><div class='metric-label'>" + escapeHtml(label)
      + "</div><div class='metric-value'>" + escapeHtml(value)
      + "</div><div class='metric-note'>" + escapeHtml(note) + "</div></div>";
  }

  function renderOverview() {
    var metrics = state.overview.metrics;
    var policy = state.overview.cluster_policy;
    var paths = state.overview.paths || [];
    var counts = {};
    paths.forEach(function (path) {
      counts[path.selected_state] = (counts[path.selected_state] || 0) + 1;
    });
    var totalStates = Object.values(counts).reduce(function (sum, value) {
      return sum + value;
    }, 0) || 1;
    var stateRows = ["direct_public", "direct_ipv6", "direct_nat_traversal", "relay", "unreachable"]
      .map(function (name) {
        var count = counts[name] || 0;
        var className = name === "unreachable" ? "bad" : name === "relay" ? "warn" : "";
        return "<div class='state-row " + className + "'><span class='state-name'>"
          + escapeHtml(name.replace(/_/g, " ")) + "</span><span class='state-bar'><span style='width:"
          + Math.round((count / totalStates) * 100) + "%'></span></span><span class='state-count'>"
          + count + "</span></div>";
      }).join("");
    var recentNodes = (state.overview.nodes || []).slice(0, 6);
    var nodeRows = recentNodes.length ? recentNodes.map(function (entry) {
      return "<tr><td class='primary-cell mono'>" + escapeHtml(shortId(entry.node.node_id))
        + "</td><td>" + escapeHtml(entry.node.vpn_ip) + "</td><td>"
        + escapeHtml(entry.node.role) + "</td><td>"
        + statusPill(entry.health ? entry.health.state : "unknown") + "</td></tr>";
    }).join("") : "<tr><td colspan='4' class='empty-state'>No devices registered.</td></tr>";
    return "<div class='metric-grid'>"
      + metricCard("Registered devices", metrics.node_count, metrics.healthy_node_count + " healthy")
      + metricCard("Active paths", metrics.path_count, metrics.stale_path_count + " stale")
      + metricCard("Relay candidates", metrics.relay_candidate_count, "Eligible relay nodes")
      + metricCard("VPN addresses free", metrics.vpn_pool_available_count, metrics.vpn_pool_allocated_count + " allocated")
      + "</div><div class='overview-grid'>"
      + "<section class='section-panel'><div class='section-header'><div><h2>Path state</h2><p>Fresh path telemetry in the control plane.</p></div></div><div class='section-body'><div class='state-list'>"
      + stateRows + "</div></div></section>"
      + "<section class='section-panel'><div class='section-header'><div><h2>Policy posture</h2><p>Current runtime policy.</p></div></div><div class='section-body'><div class='checkbox-row'>"
      + "<span class='status-pill " + (policy.allow_ipv6_direct ? "healthy" : "unhealthy") + "'>"
      + (policy.allow_ipv6_direct ? "IPv6 direct on" : "IPv6 direct off") + "</span>"
      + "<span class='status-pill " + (policy.allow_nat_traversal ? "healthy" : "unhealthy") + "'>"
      + (policy.allow_nat_traversal ? "NAT traversal on" : "NAT traversal off") + "</span>"
      + "<span class='status-pill " + (policy.allow_relay_fallback ? "healthy" : "unhealthy") + "'>"
      + (policy.allow_relay_fallback ? "Relay fallback on" : "Relay fallback off") + "</span>"
      + "</div><p class='muted' style='margin:18px 0 0'>Endpoint TTL "
      + escapeHtml(policy.endpoint_candidate_ttl_seconds) + "s · Path TTL "
      + escapeHtml(policy.path_state_ttl_seconds) + "s</p></div></section></div>"
      + "<section class='section-panel'><div class='section-header'><div><h2>Devices</h2><p>Most recently registered nodes.</p></div><button class='button button-quiet button-small' data-navigate='nodes' type='button'>View all</button></div><div class='table-wrap'><table><thead><tr><th>Node</th><th>VPN IP</th><th>Role</th><th>Health</th></tr></thead><tbody>"
      + nodeRows + "</tbody></table></div></section>";
  }

  function renderNodes() {
    var entries = state.overview.nodes || [];
    var selected = entries.find(function (entry) {
      return entry.node.node_id === state.selectedNodeId;
    });
    var rows = entries.length ? entries.map(function (entry) {
      var node = entry.node;
      var health = entry.health;
      return "<tr><td class='primary-cell'><button class='link-button mono' data-node-id='"
        + escapeHtml(node.node_id) + "' type='button'>" + escapeHtml(shortId(node.node_id))
        + "</button></td><td class='mono'>" + escapeHtml(node.vpn_ip) + "</td><td>"
        + escapeHtml(node.role) + "</td><td>" + statusPill(health ? health.state : "unknown")
        + "</td><td>" + listTags(node.tags) + "</td><td>"
        + escapeHtml(node.relay_capability ? "Available" : "No") + "</td><td>"
        + escapeHtml(formatTime(node.registered_at)) + "</td></tr>";
    }).join("") : "<tr><td colspan='7' class='empty-state'>No devices registered.</td></tr>";
    var detail = selected
      ? "<aside class='detail-panel'><span class='eyebrow'>DEVICE DETAILS</span><h2 class='mono' style='margin-top:10px'>"
        + escapeHtml(shortId(selected.node.node_id)) + "</h2><dl>"
        + "<dt>Node ID</dt><dd class='mono'>" + escapeHtml(selected.node.node_id) + "</dd>"
        + "<dt>VPN address</dt><dd class='mono'>" + escapeHtml(selected.node.vpn_ip) + "</dd>"
        + "<dt>Role</dt><dd>" + escapeHtml(selected.node.role) + "</dd>"
        + "<dt>Health</dt><dd>" + statusPill(selected.health ? selected.health.state : "unknown") + "</dd>"
        + "<dt>Last seen</dt><dd>" + escapeHtml(selected.health ? formatTime(selected.health.last_seen_at) : "Never") + "</dd>"
        + "<dt>Routes</dt><dd>" + selected.node.routes.length + "</dd>"
        + "<dt class='detail-tags'>Tags</dt><dd class='detail-tags'>" + listTags(selected.node.tags) + "</dd>"
        + "</dl><button class='button button-danger' data-remove-node='" + escapeHtml(selected.node.node_id) + "' type='button'>Remove device</button></aside>"
      : "<aside class='detail-panel'><span class='eyebrow'>DEVICE DETAILS</span><p class='muted' style='margin-top:14px'>Select a device to inspect it.</p></aside>";
    return "<div class='detail-layout'><section class='section-panel'><div class='section-header'><div><h2>Registered devices</h2><p>"
      + entries.length + " device" + (entries.length === 1 ? "" : "s")
      + " in this cluster.</p></div></div><div class='table-wrap'><table><thead><tr><th>Node</th><th>VPN IP</th><th>Role</th><th>Health</th><th>Tags</th><th>Relay</th><th>Registered</th></tr></thead><tbody>"
      + rows + "</tbody></table></div></section>" + detail + "</div>";
  }

  function renderPaths() {
    var paths = state.overview.paths || [];
    var rows = paths.length ? paths.map(function (path) {
      var label = path.key.local + "::" + path.key.remote;
      return "<tr><td class='primary-cell mono'>" + escapeHtml(shortId(path.key.local))
        + "</td><td class='mono'>" + escapeHtml(shortId(path.key.remote)) + "</td><td>"
        + statusPill(path.selected_state) + "</td><td class='mono'>"
        + escapeHtml(path.selected_candidate ? path.selected_candidate.addr : "-") + "</td><td class='mono'>"
        + escapeHtml(path.relay_node ? shortId(path.relay_node) : "-") + "</td><td>"
        + escapeHtml(path.score.value) + "</td><td>" + escapeHtml(age(path.updated_at))
        + "</td><td><button class='pin-button " + (path.pinned ? "active" : "")
        + "' data-pin-path='" + escapeHtml(label) + "' data-pinned='" + path.pinned
        + "' type='button'>" + (path.pinned ? "Pinned" : "Pin") + "</button></td></tr>";
    }).join("") : "<tr><td colspan='8' class='empty-state'>No path telemetry is available.</td></tr>";
    return "<section class='section-panel'><div class='section-header'><div><h2>Connections</h2><p>Selected path, endpoint, relay, and score from node telemetry.</p></div></div><div class='table-wrap'><table><thead><tr><th>Local</th><th>Remote</th><th>State</th><th>Candidate</th><th>Relay</th><th>Score</th><th>Updated</th><th>Control</th></tr></thead><tbody>"
      + rows + "</tbody></table></div></section>";
  }

  function renderRoutes() {
    var routes = [];
    (state.overview.nodes || []).forEach(function (entry) {
      (entry.node.routes || []).forEach(function (route) {
        routes.push({ node: entry.node, route: route });
      });
    });
    var rows = routes.length ? routes.map(function (item) {
      return "<tr><td class='primary-cell mono'>" + escapeHtml(item.route.id || "-")
        + "</td><td class='mono'>" + escapeHtml(item.route.cidr || "-") + "</td><td class='mono'>"
        + escapeHtml(shortId(item.node.node_id)) + "</td><td>" + escapeHtml(item.node.role)
        + "</td><td>" + listTags(item.node.tags) + "</td></tr>";
    }).join("") : "<tr><td colspan='5' class='empty-state'>No advertised routes.</td></tr>";
    return "<section class='section-panel'><div class='section-header'><div><h2>Advertised routes</h2><p>Routes currently owned by registered devices.</p></div></div><div class='table-wrap'><table><thead><tr><th>Route</th><th>Network</th><th>Advertised by</th><th>Role</th><th>Tags</th></tr></thead><tbody>"
      + rows + "</tbody></table></div></section>";
  }

  function csvValues(value) {
    return String(value || "").split(",").map(function (item) {
      return item.trim();
    }).filter(Boolean);
  }

  function ruleField(index, field, value, label, wide) {
    return "<div class='form-field " + (wide ? "wide" : "") + "'><label for='rule-"
      + index + "-" + field + "'>" + label + "</label><input id='rule-" + index + "-"
      + field + "' data-rule-index='" + index + "' data-rule-field='" + field + "' value='"
      + escapeHtml((value || []).join(", ")) + "' placeholder='Comma separated'></div>";
  }

  function renderAcl() {
    var policy = state.overview.cluster_policy;
    var rules = policy.acl_rules || [];
    var ruleEditors = rules.map(function (rule, index) {
      var protocols = ["any", "tcp", "udp", "icmp", "icmpv6", "sctp"];
      var protocolOptions = protocols.map(function (protocol) {
        return "<option value='" + protocol + "' " + (rule.protocol === protocol ? "selected" : "")
          + ">" + protocol + "</option>";
      }).join("");
      return "<div class='section-body' style='border-top:1px solid var(--border)'><div class='form-grid'>"
        + "<div class='form-field'><label for='rule-" + index + "-id'>Rule ID</label><input id='rule-"
        + index + "-id' data-rule-index='" + index + "' data-rule-field='id' value='"
        + escapeHtml(rule.id) + "'></div>"
        + "<div class='form-field'><label for='rule-" + index + "-action'>Action</label><select id='rule-"
        + index + "-action' data-rule-index='" + index + "' data-rule-field='action'><option value='allow' "
        + (rule.action === "allow" ? "selected" : "") + ">Allow</option><option value='deny' "
        + (rule.action === "deny" ? "selected" : "") + ">Deny</option></select></div>"
        + "<div class='form-field'><label for='rule-" + index + "-protocol'>Protocol</label><select id='rule-"
        + index + "-protocol' data-rule-index='" + index + "' data-rule-field='protocol'>"
        + protocolOptions + "</select></div>"
        + ruleField(index, "from_roles", rule.from_roles, "From roles", false)
        + ruleField(index, "from_tags", rule.from_tags, "From tags", false)
        + ruleField(index, "to_roles", rule.to_roles, "To roles", false)
        + ruleField(index, "to_tags", rule.to_tags, "To tags", false)
        + ruleField(index, "routes", rule.routes, "Routes (CIDR)", true)
        + "<div class='form-field' style='align-self:end'><button class='button button-danger button-small' data-delete-rule='"
        + index + "' type='button'>Delete rule</button></div></div></div>";
    }).join("");
    return "<section class='section-panel'><div class='section-header'><div><h2>Access control policy</h2><p>Changes apply to newly generated peer maps and path validation.</p></div><button class='button button-primary button-small' id='save-policy' type='button'>Save policy</button></div><div class='section-body'><div class='checkbox-row'>"
      + "<label class='checkbox-label'><input type='checkbox' data-policy-boolean='allow_ipv6_direct' "
      + (policy.allow_ipv6_direct ? "checked" : "") + "> IPv6 direct</label>"
      + "<label class='checkbox-label'><input type='checkbox' data-policy-boolean='allow_nat_traversal' "
      + (policy.allow_nat_traversal ? "checked" : "") + "> NAT traversal</label>"
      + "<label class='checkbox-label'><input type='checkbox' data-policy-boolean='allow_relay_fallback' "
      + (policy.allow_relay_fallback ? "checked" : "") + "> Relay fallback</label></div>"
      + "<div class='form-grid' style='margin-top:17px'><div class='form-field'><label for='idle-timeout'>Idle timeout (seconds)</label><input id='idle-timeout' type='number' min='1' value='"
      + escapeHtml(policy.idle_timeout_seconds) + "'></div><div class='form-field'><label for='endpoint-ttl'>Endpoint TTL (seconds)</label><input id='endpoint-ttl' type='number' min='1' value='"
      + escapeHtml(policy.endpoint_candidate_ttl_seconds) + "'></div><div class='form-field'><label for='path-ttl'>Path TTL (seconds)</label><input id='path-ttl' type='number' min='1' value='"
      + escapeHtml(policy.path_state_ttl_seconds) + "'></div></div></div></section>"
      + "<section class='section-panel'><div class='section-header'><div><h2>ACL rules</h2><p>Each rule can match roles, tags, routes, and protocol.</p></div><button class='button button-quiet button-small' id='add-rule' type='button'>Add rule</button></div>"
      + (ruleEditors || "<div class='empty-state'>No explicit ACL rules. Add one to override the default posture.</div>")
      + "</section>";
  }

  function renderView() {
    if (!state.overview) return;
    var metadata = {
      overview: ["Overview", "Live state from the IPARS control plane."],
      nodes: ["Devices", "Registered nodes, health, identity, and relay capability."],
      paths: ["Connections", "Selected path telemetry and operator pin state."],
      routes: ["Routes", "Advertised network routes and their owners."],
      acl: ["Access control", "Runtime connectivity policy and ACL rules."]
    }[state.activeView];
    $("view-title").textContent = metadata[0];
    $("view-subtitle").textContent = metadata[1];
    $("view-content").innerHTML = {
      overview: renderOverview,
      nodes: renderNodes,
      paths: renderPaths,
      routes: renderRoutes,
      acl: renderAcl
    }[state.activeView]();
    document.querySelectorAll(".nav-button").forEach(function (button) {
      button.classList.toggle("active", button.dataset.view === state.activeView);
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
    rule[field] = ["from_roles", "from_tags", "to_roles", "to_tags", "routes"].indexOf(field) !== -1
      ? csvValues(input.value) : input.value;
  }

  async function savePolicy() {
    updatePolicyFromForm();
    setStatus("Saving policy...");
    try {
      var response = await api("/v1/admin/policy", {
        method: "PUT",
        body: JSON.stringify({ cluster_policy: state.overview.cluster_policy })
      });
      state.overview.cluster_policy = response.cluster_policy;
      setStatus("Policy saved.");
      renderView();
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  async function removeNode(nodeId) {
    if (!confirm("Remove device " + shortId(nodeId) + " from this cluster?")) return;
    try {
      await api("/v1/admin/nodes/" + encodeURIComponent(nodeId), { method: "DELETE" });
      state.selectedNodeId = null;
      setStatus("Device removed.");
      await loadOverview();
    } catch (error) {
      setStatus(error.message, true);
    }
  }

  async function pinPath(label, pinned) {
    var parts = label.split("::");
    try {
      await api("/v1/admin/paths/" + encodeURIComponent(parts[0]) + "/"
        + encodeURIComponent(parts[1]) + "/pin", {
          method: "POST",
          body: JSON.stringify({ pinned: pinned })
        });
      setStatus(pinned ? "Path pinned." : "Path unpinned.");
      await loadOverview();
    } catch (error) {
      setStatus(error.message, true);
    }
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
    setStatus("Rule added locally. Save policy to apply it.");
    renderView();
  }

  function deleteRule(index) {
    state.overview.cluster_policy.acl_rules.splice(index, 1);
    setStatus("Rule deleted locally. Save policy to apply the change.");
    renderView();
  }

  function signOut() {
    var provider = state.config && state.config.provider;
    var logoutEndpoint = state.config && state.config.logout_endpoint;
    clearSession();
    if (logoutEndpoint && state.config.client_id) {
      var params = new URLSearchParams({ client_id: state.config.client_id });
      if (provider === "cognito") params.set("logout_uri", location.origin + "/ui/");
      else params.set("post_logout_redirect_uri", location.origin + "/ui/");
      location.assign(logoutEndpoint + "?" + params.toString());
      return;
    }
    showAuth("");
    setConnection(false);
  }

  document.addEventListener("input", function (event) {
    if (event.target.matches("[data-rule-index][data-rule-field]")) updateRuleField(event.target);
  });

  document.addEventListener("change", function (event) {
    if (event.target.matches("[data-rule-index][data-rule-field]")) updateRuleField(event.target);
  });

  document.addEventListener("click", function (event) {
    var nav = event.target.closest("[data-view]");
    if (nav) {
      state.activeView = nav.dataset.view;
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
      state.selectedNodeId = node.dataset.nodeId;
      renderView();
      return;
    }
    var remove = event.target.closest("[data-remove-node]");
    if (remove) {
      removeNode(remove.dataset.removeNode);
      return;
    }
    var pin = event.target.closest("[data-pin-path]");
    if (pin) {
      pinPath(pin.dataset.pinPath, pin.dataset.pinned !== "true");
      return;
    }
    var deleteButton = event.target.closest("[data-delete-rule]");
    if (deleteButton) {
      deleteRule(Number(deleteButton.dataset.deleteRule));
      return;
    }
    if (event.target.closest("#refresh-button")) loadOverview();
    if (event.target.closest("#save-policy")) savePolicy();
    if (event.target.closest("#add-rule")) addRule();
  });

  $("oidc-login").addEventListener("click", function () {
    startLogin().catch(function (error) { $("auth-error").textContent = error.message; });
  });

  $("token-form").addEventListener("submit", async function (event) {
    event.preventDefault();
    var token = $("operator-token").value.trim();
    if (!token) return;
    state.token = token;
    sessionStorage.setItem("ipars_operator_token", token);
    await loadOverview();
  });

  $("auth-button").addEventListener("click", function () {
    if (state.token) signOut();
    else showAuth("");
  });

  async function bootstrap() {
    try {
      await loadConfig();
      var exchanged = await exchangeCode();
      if (!state.token && !exchanged) {
        showAuth("");
        return;
      }
      await loadOverview();
    } catch (error) {
      showAuth(error.message);
      setConnection(false);
    }
  }

  setInterval(function () {
    if (state.token && !state.loading) loadOverview();
  }, 10000);
  bootstrap();
})();
