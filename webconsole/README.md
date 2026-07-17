# HeteroNetwork WebConsole Server

This server publishes the embedded `webui/` as a standalone WebConsole and
protects `/v1/admin/*` with Keycloak bearer-token validation.
It also provides `/ui/login` and `/ui/callback` so the browser can use
Authorization Code with PKCE even when the console is served from a plain HTTP
lab address where `crypto.subtle` is unavailable.

It is intended for deployments where an older running control-plane already
exposes `/v1/metrics` and `/v1/policy`, but the newer embedded `/ui/` and
`/v1/admin/overview` routes are not yet running in `iparsd`.

```sh
HOST=0.0.0.0 \
PORT=18088 \
IPARS_WEB_PUBLIC_URL=http://100.105.153.15:18088 \
IPARS_WEB_OIDC_ISSUER_URL=http://100.105.153.15:18080/realms/kakurizai \
IPARS_WEB_OIDC_CLIENT_ID=ipars-web \
IPARS_WEB_ALLOWED_EMAILS=hello@mizuame.works \
IPARS_CONTROL_PLANE_URL=http://192.168.0.205:8443 \
IPARS_LAB_STATE_PATH=/home/mizuame/hetero-net-console/state.json \
node webconsole/server.mjs
```

Read endpoints allow `kakurizai-admin`, `kakurizai-operator`, and
`kakurizai-viewer` realm roles by default. Write endpoints require
`kakurizai-admin`; when the target control-plane does not support the newer
admin write APIs, the server returns `501`.
