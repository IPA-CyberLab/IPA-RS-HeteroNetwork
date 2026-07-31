# HeteroNetwork WebConsole Server

This server publishes the embedded `webui/` as a standalone WebConsole and
protects `/v1/admin/*` with Keycloak bearer-token validation.
It also provides `/ui/login` and `/ui/callback` so the browser can use
Authorization Code with PKCE even when the console is served from a plain HTTP
lab address where `crypto.subtle` is unavailable.
The authorization state and PKCE verifier are bound to the initiating browser
with a five-minute, path-limited HttpOnly cookie; a callback carrying another
browser's state is rejected before token exchange. They are not stored in
process memory, so login and callback may reach different console replicas.
The access token remains in per-tab `sessionStorage`; the refresh token is kept
in a path-limited `HttpOnly; SameSite=Strict` cookie and is rotated through the
same-origin `/ui/auth/refresh` endpoint. HTTPS deployments add `Secure`, and
`/ui/auth/logout` deletes the cookie before provider logout.
Refresh and logout requests must carry the exact configured public origin and
`Sec-Fetch-Site: same-origin`. Concurrent rotation requests for the same cookie
are coalesced and successful results are replayed briefly to prevent tab races.

Plain HTTP remains supported for private-overlay deployments. In that mode the
refresh cookie cannot use `Secure`, so the WebConsole address must only traverse
an authenticated, encrypted private overlay and must not be exposed to a public
or otherwise untrusted network. Use HTTPS whenever the deployment permits it.

It proxies the control-plane `/v1/admin/overview`, node, path, and policy
routes, forwarding the authenticated Keycloak bearer token so the standalone
console and the embedded console use the same management API.

```sh
HOST=0.0.0.0 \
PORT=18088 \
HETERONETWORK_WEB_PUBLIC_URL=https://163.220.236.51 \
HETERONETWORK_WEB_OIDC_ISSUER_URL=https://163.220.236.51/realms/kakurizai \
HETERONETWORK_WEB_OIDC_CLIENT_ID=heteronetwork-web \
HETERONETWORK_WEB_ALLOWED_EMAILS=hello@mizuame.works \
HETERONETWORK_CONTROL_PLANE_URL=https://hn-a.163-220-236-51.sslip.io \
node webconsole/server.mjs
```

Read endpoints allow `heteronetwork-admin`, `heteronetwork-operator`, and
`heteronetwork-viewer` realm roles by default. Write endpoints require
`heteronetwork-admin`. An optional email allowlist is an additional
restriction and never bypasses those roles. The standalone server does not
synthesize state or maintain a second copy of the control-plane data.
