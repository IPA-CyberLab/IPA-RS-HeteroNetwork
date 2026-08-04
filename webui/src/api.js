const ACCESS_TOKEN_KEY = "heteronetwork_access_token";
const ACCESS_TOKEN_EXPIRES_KEY = "heteronetwork_access_token_expires_at";
const OPERATOR_TOKEN_KEY = "heteronetwork_operator_token";
const REFRESH_SKEW_MS = 30_000;

function storedNumber(key) {
  const value = Number(sessionStorage.getItem(key));
  return Number.isFinite(value) && value > 0 ? value : null;
}

async function responseBody(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export class HeteroNetworkApi {
  constructor() {
    const accessToken = sessionStorage.getItem(ACCESS_TOKEN_KEY) || "";
    const operatorToken = sessionStorage.getItem(OPERATOR_TOKEN_KEY) || "";
    this.config = null;
    this.token = accessToken || operatorToken;
    this.tokenType = accessToken ? "oidc" : operatorToken ? "operator" : null;
    this.tokenExpiresAt = accessToken ? storedNumber(ACCESS_TOKEN_EXPIRES_KEY) : null;
    this.refreshPromise = null;
    this.generation = 0;
    this.onAuthenticationRequired = null;
  }

  hasSession() {
    return Boolean(this.token);
  }

  async loadConfig() {
    const response = await fetch("/ui/config", {
      headers: { Accept: "application/json" },
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw new Error(`Web UI設定を取得できませんでした (${response.status})`);
    }
    this.config = await response.json();
    return this.config;
  }

  setOidcSession(tokens) {
    this.token = tokens.access_token;
    this.tokenType = "oidc";
    const expiresIn = Number(tokens.expires_in);
    this.tokenExpiresAt =
      Number.isFinite(expiresIn) && expiresIn > 0
        ? Date.now() + expiresIn * 1000
        : null;
    sessionStorage.setItem(ACCESS_TOKEN_KEY, this.token);
    if (this.tokenExpiresAt) {
      sessionStorage.setItem(ACCESS_TOKEN_EXPIRES_KEY, String(this.tokenExpiresAt));
    } else {
      sessionStorage.removeItem(ACCESS_TOKEN_EXPIRES_KEY);
    }
  }

  setOperatorSession(token) {
    this.generation += 1;
    this.token = token;
    this.tokenType = "operator";
    this.tokenExpiresAt = null;
    sessionStorage.setItem(OPERATOR_TOKEN_KEY, token);
  }

  clearOidcSession() {
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(ACCESS_TOKEN_EXPIRES_KEY);
    if (this.tokenType === "oidc") {
      this.token = "";
      this.tokenType = null;
      this.tokenExpiresAt = null;
    }
  }

  clearOperatorSession() {
    sessionStorage.removeItem(OPERATOR_TOKEN_KEY);
    if (this.tokenType === "operator") {
      this.token = "";
      this.tokenType = null;
      this.tokenExpiresAt = null;
    }
  }

  clearSession() {
    this.generation += 1;
    this.token = "";
    this.tokenType = null;
    this.tokenExpiresAt = null;
    sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    sessionStorage.removeItem(ACCESS_TOKEN_EXPIRES_KEY);
    sessionStorage.removeItem(OPERATOR_TOKEN_KEY);
  }

  async refreshSession() {
    if (
      !this.config?.session_refresh_endpoint ||
      this.tokenType === "operator"
    ) {
      throw new Error("セッションを更新できません");
    }
    if (this.refreshPromise) return this.refreshPromise;
    const refreshGeneration = this.generation;
    const refresh = async () => {
      if (refreshGeneration !== this.generation) throw this.sessionChangedError();
      const response = await fetch(this.config.session_refresh_endpoint, {
        method: "POST",
        headers: { Accept: "application/json" },
        credentials: "same-origin",
      });
      if (refreshGeneration !== this.generation) {
        this.clearStaleRefreshCookie();
        throw this.sessionChangedError();
      }
      return response;
    };
    const locks = typeof navigator !== "undefined" ? navigator.locks : null;
    const request =
      locks && typeof locks.request === "function"
        ? locks.request("heteronetwork-auth-session", { mode: "exclusive" }, refresh)
        : refresh();
    this.refreshPromise = Promise.resolve(request)
      .then(async (response) => {
        const body = await responseBody(response);
        if (refreshGeneration !== this.generation) {
          this.clearStaleRefreshCookie();
          throw this.sessionChangedError();
        }
        if (!response.ok || !body?.access_token) {
          const error = new Error(
            body?.error || `セッション更新に失敗しました (${response.status})`,
          );
          error.authenticationRejected =
            response.status === 401 || response.status === 403;
          throw error;
        }
        this.setOidcSession(body);
        return body;
      })
      .finally(() => {
        this.refreshPromise = null;
      });
    return this.refreshPromise;
  }

  async request(path, options = {}, retried = false) {
    const requestGeneration = this.generation;
    const tokenUsed = this.token;
    const tokenTypeUsed = this.tokenType;
    const expiresSoon =
      this.tokenType === "oidc" &&
      this.tokenExpiresAt !== null &&
      Date.now() + REFRESH_SKEW_MS >= this.tokenExpiresAt;
    if (expiresSoon && !retried) {
      try {
        await this.refreshSession();
      } catch (error) {
        if (error.authenticationRejected) return this.authenticationRequired();
        if (!this.tokenExpiresAt || Date.now() >= this.tokenExpiresAt) throw error;
      }
    }

    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (this.token) headers.set("Authorization", `Bearer ${this.token}`);
    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    const response = await fetch(path, { ...options, headers });
    if (requestGeneration !== this.generation) throw this.sessionChangedError();
    if (response.status === 401) {
      if (this.token && this.token !== tokenUsed) {
        return this.request(path, options, true);
      }
      if (
        !retried &&
        tokenTypeUsed === "oidc" &&
        this.config?.session_refresh_endpoint
      ) {
        try {
          await this.refreshSession();
          return this.request(path, options, true);
        } catch {
          return this.authenticationRequired();
        }
      }
      return this.authenticationRequired(tokenTypeUsed);
    }
    const body = await responseBody(response);
    if (requestGeneration !== this.generation) throw this.sessionChangedError();
    if (!response.ok) {
      throw new Error(body?.error || `${response.status} ${response.statusText}`);
    }
    return body;
  }

  authenticationRequired(tokenType = this.tokenType) {
    this.generation += 1;
    if (tokenType === "oidc") this.clearOidcSession();
    if (tokenType === "operator") this.clearOperatorSession();
    this.onAuthenticationRequired?.();
    throw new Error("authentication required");
  }

  sessionChangedError() {
    const error = new Error("authentication required");
    error.sessionChanged = true;
    return error;
  }

  clearStaleRefreshCookie() {
    if (!this.config?.session_logout_endpoint) return;
    fetch(this.config.session_logout_endpoint, {
      method: "POST",
      headers: { Accept: "application/json" },
      credentials: "same-origin",
      keepalive: true,
    }).catch(() => null);
  }

  async localRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Accept", "application/json");
    if (options.body) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers });
    const body = await responseBody(response);
    if (!response.ok) {
      throw new Error(body?.error || `${response.status} ${response.statusText}`);
    }
    return body;
  }
}

export const api = new HeteroNetworkApi();
