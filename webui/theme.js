(function () {
  "use strict";

  var storedTheme = localStorage.getItem("heteronetwork_theme");
  var theme = storedTheme === "dark" || storedTheme === "light"
    ? storedTheme
    : (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  var storedLocale = localStorage.getItem("heteronetwork_locale");
  var locale = storedLocale === "ja" || storedLocale === "en"
    ? storedLocale
    : (navigator.language.toLowerCase().indexOf("ja") === 0 ? "ja" : "en");

  document.documentElement.dataset.theme = theme;
  document.documentElement.lang = locale;

  // Start the small, same-origin configuration request while the browser is
  // still parsing the document. The full Cloudscape bundle is intentionally
  // not on the critical path for showing a usable login action.
  var configPromise = fetch("/ui/config", {
    headers: { Accept: "application/json" },
    credentials: "same-origin"
  }).then(function (response) {
    if (!response.ok) {
      throw new Error("Web UI configuration request failed");
    }
    return response.json();
  }).catch(function () {
    // The application retries and renders the detailed error state. Avoid an
    // unhandled rejection in the early shell.
    return null;
  });
  window.__heteronetworkConfigPromise = configPromise;

  window.__heteronetworkHideLoginBootstrap = function () {
    var shell = document.getElementById("hn-login-bootstrap");
    if (shell) shell.remove();
  };

  function hasSession() {
    return sessionStorage.getItem("heteronetwork_access_token")
      || sessionStorage.getItem("heteronetwork_operator_token");
  }

  function showPendingLogin() {
    if (hasSession()) return;
    var shell = document.getElementById("hn-login-bootstrap");
    if (shell) shell.hidden = false;
  }

  // Render the small disabled login shell as soon as HTML and CSS are ready.
  // Configuration enables the button; the full Cloudscape bundle can continue
  // downloading without consuming the three-second first-render budget.
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", showPendingLogin, { once: true });
  } else {
    showPendingLogin();
  }

  function prepareLogin(config) {
    var shell = document.getElementById("hn-login-bootstrap");
    var button = document.getElementById("hn-login-bootstrap-button");
    if (!config || !config.auth_enabled
        || (config.local_agent && config.bootstrap_required)
        || hasSession()
        || (!config.login_endpoint
          && !(config.device_login_endpoint && config.device_login_poll_endpoint))) {
      if (shell) shell.hidden = true;
      return;
    }
    if (!shell || !button) return;

    var provider = typeof config.provider === "string" && config.provider
      ? config.provider.charAt(0).toUpperCase() + config.provider.slice(1)
      : "SSO";
    button.textContent = provider + "でログイン";
    button.disabled = false;
    shell.hidden = false;
    button.addEventListener("click", function () {
      if (button.disabled) return;
      if (config.device_login_endpoint && config.device_login_poll_endpoint) {
        var authWindow = window.open("/ui/auth/wait", "_blank");
        window.__heteronetworkPendingLogin = { authWindow: authWindow };
        button.disabled = true;
        button.textContent = "ログインを開始しています";
        window.dispatchEvent(new Event("heteronetwork:login-requested"));
        return;
      }
      window.location.assign(config.login_endpoint);
    });
  }

  configPromise.then(function (config) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", function () {
        prepareLogin(config);
      }, { once: true });
    } else {
      prepareLogin(config);
    }
  });
}());
