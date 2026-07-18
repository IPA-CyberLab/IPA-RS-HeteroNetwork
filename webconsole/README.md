# HeteroNetwork WebConsole Server

This server publishes the embedded `webui/` as a standalone WebConsole and
protects `/v1/admin/*` with Keycloak bearer-token validation.
It also provides `/ui/login` and `/ui/callback` so the browser can use
Authorization Code with PKCE even when the console is served from a plain HTTP
lab address where `crypto.subtle` is unavailable.

It proxies the control-plane `/v1/admin/overview`, node, path, and policy
routes, forwarding the authenticated Keycloak bearer token so the standalone
console and the embedded console use the same management API.

```sh
HOST=0.0.0.0 \
PORT=18088 \
HETERONETWORK_WEB_PUBLIC_URL=http://100.105.153.15:18088 \
HETERONETWORK_WEB_OIDC_ISSUER_URL=http://100.105.153.15:18080/realms/heteronetwork \
HETERONETWORK_WEB_OIDC_CLIENT_ID=heteronetwork-web \
HETERONETWORK_WEB_ALLOWED_EMAILS=hello@mizuame.works \
HETERONETWORK_CONTROL_PLANE_URL=http://192.168.0.205:8443 \
node webconsole/server.mjs
```

Read endpoints allow `heteronetwork-admin`, `heteronetwork-operator`, and
`heteronetwork-viewer` realm roles by default. Write endpoints require
`heteronetwork-admin`. The standalone server does not synthesize state or
maintain a second copy of the control-plane data.
