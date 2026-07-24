#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_SERVER_URL="http://127.0.0.1:18080"
readonly DEFAULT_REALM="kakurizai"
readonly DEFAULT_ADMIN_USERNAME="admin"
readonly DEFAULT_IDP_ALIAS="github"
readonly DEFAULT_FLOW_ALIAS="github-deny-unlinked"
readonly DEFAULT_ALLOWED_LOGIN="mizuamedesu"
readonly MAX_REALM_USERS=1000
readonly GITHUB_AUTHORIZATION_URL="https://github.com/login/oauth/authorize"
readonly GITHUB_TOKEN_URL="https://github.com/login/oauth/access_token"
readonly GITHUB_USER_INFO_URL="https://api.github.com/user"

server_url="${HETERONETWORK_KEYCLOAK_SERVER_URL:-$DEFAULT_SERVER_URL}"
realm="${HETERONETWORK_KEYCLOAK_REALM:-$DEFAULT_REALM}"
admin_username="${HETERONETWORK_KEYCLOAK_ADMIN_USERNAME:-$DEFAULT_ADMIN_USERNAME}"
admin_password_file="${HETERONETWORK_KEYCLOAK_ADMIN_PASSWORD_FILE:-/etc/heteronetwork/keycloak/bootstrap-admin.password}"
github_client_id_file="${HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_ID_FILE:-/etc/heteronetwork/keycloak/github-client.id}"
github_client_secret_file="${HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_SECRET_FILE:-/etc/heteronetwork/keycloak/github-client.secret}"
github_allowed_login="${HETERONETWORK_KEYCLOAK_GITHUB_ALLOWED_LOGIN:-$DEFAULT_ALLOWED_LOGIN}"
github_allowed_user_id="${HETERONETWORK_KEYCLOAK_GITHUB_ALLOWED_USER_ID:-}"
idp_alias="${HETERONETWORK_KEYCLOAK_GITHUB_IDP_ALIAS:-$DEFAULT_IDP_ALIAS}"
flow_alias="${HETERONETWORK_KEYCLOAK_GITHUB_FLOW_ALIAS:-$DEFAULT_FLOW_ALIAS}"
kcadm_path="${HETERONETWORK_KEYCLOAK_KCADM_PATH:-/opt/heteronetwork/keycloak/bin/kcadm.sh}"
kcadm_config=""

usage() {
  cat <<'EOF'
Usage: keycloak-github-idp.sh COMMAND

Commands:
  configure  Reconcile the GitHub identity provider and exclusive account link
  verify     Verify the provider, deny flow, user, and exclusive account link
  self-test  Run offline validation and rendering checks

Required environment for configure and verify:
  HETERONETWORK_KEYCLOAK_GITHUB_ALLOWED_USER_ID

Optional environment:
  HETERONETWORK_KEYCLOAK_SERVER_URL
  HETERONETWORK_KEYCLOAK_REALM
  HETERONETWORK_KEYCLOAK_ADMIN_USERNAME
  HETERONETWORK_KEYCLOAK_ADMIN_PASSWORD_FILE
  HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_ID_FILE
  HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_SECRET_FILE
  HETERONETWORK_KEYCLOAK_GITHUB_ALLOWED_LOGIN
  HETERONETWORK_KEYCLOAK_GITHUB_IDP_ALIAS
  HETERONETWORK_KEYCLOAK_GITHUB_FLOW_ALIAS
  HETERONETWORK_KEYCLOAK_KCADM_PATH

The GitHub identity is linked by immutable numeric GitHub user ID. Every
unlinked GitHub account is rejected by a dedicated first-broker-login flow.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" == "0" ]] || die "this command must run as root"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

validate_safe_name() {
  local value="$1" name="$2"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$ ]] \
    || die "$name must be a 1-63 character safe identifier"
}

validate_github_login() {
  local value="$1"
  [[ ${#value} -le 39 ]] || return 1
  [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]]
}

validate_github_user_id() {
  [[ "$1" =~ ^[1-9][0-9]{0,19}$ ]]
}

validate_server_url() {
  [[ "$server_url" =~ ^https?://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?$ ]] \
    || die "HETERONETWORK_KEYCLOAK_SERVER_URL must use a loopback host"
}

validate_secret_file() {
  local path="$1" name="$2" size mode
  [[ "$path" == /* ]] || die "$name must be an absolute path"
  [[ -f "$path" && ! -L "$path" ]] || die "$name must be a non-symlink regular file"
  size="$(stat -c '%s' "$path")"
  ((size > 0 && size <= 4096)) || die "$name must contain 1-4096 bytes"
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 0007) == 0 )) || die "$name must not be accessible to other users"
}

read_single_line_file() {
  local path="$1" name="$2" value
  validate_secret_file "$path" "$name"
  value="$(<"$path")"
  [[ -n "$value" && "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
    || die "$name must contain one non-empty line"
  printf '%s' "$value"
}

validate_runtime_config() {
  require_root
  require_command jq
  validate_server_url
  validate_safe_name "$realm" "HETERONETWORK_KEYCLOAK_REALM"
  validate_safe_name "$admin_username" "HETERONETWORK_KEYCLOAK_ADMIN_USERNAME"
  validate_safe_name "$idp_alias" "HETERONETWORK_KEYCLOAK_GITHUB_IDP_ALIAS"
  validate_safe_name "$flow_alias" "HETERONETWORK_KEYCLOAK_GITHUB_FLOW_ALIAS"
  validate_github_login "$github_allowed_login" \
    || die "HETERONETWORK_KEYCLOAK_GITHUB_ALLOWED_LOGIN is not a valid GitHub login"
  validate_github_user_id "$github_allowed_user_id" \
    || die "HETERONETWORK_KEYCLOAK_GITHUB_ALLOWED_USER_ID must be a positive numeric GitHub user ID"
  [[ -x "$kcadm_path" ]] || die "kcadm is not executable: $kcadm_path"
  validate_secret_file \
    "$admin_password_file" "HETERONETWORK_KEYCLOAK_ADMIN_PASSWORD_FILE"
  validate_secret_file \
    "$github_client_id_file" "HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_ID_FILE"
  validate_secret_file \
    "$github_client_secret_file" "HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_SECRET_FILE"
}

kc() {
  "$kcadm_path" "$@" --config "$kcadm_config"
}

kc_with_json() {
  local method="$1" path="$2" body="$3"
  printf '%s' "$body" \
    | "$kcadm_path" "$method" "$path" -r "$realm" -f - --config "$kcadm_config"
}

login_admin() {
  local admin_password
  kcadm_config="$(mktemp /tmp/heteronetwork-kcadm.XXXXXX)"
  chmod 0600 "$kcadm_config"
  admin_password="$(read_single_line_file \
    "$admin_password_file" "HETERONETWORK_KEYCLOAK_ADMIN_PASSWORD_FILE")"
  KC_CLI_PASSWORD="$admin_password" "$kcadm_path" config credentials \
    --config "$kcadm_config" \
    --server "$server_url" \
    --realm master \
    --user "$admin_username" >/dev/null
  unset admin_password
}

cleanup() {
  if [[ -n "$kcadm_config" ]]; then
    rm -f "$kcadm_config"
  fi
}

ensure_deny_flow() {
  local flows flow_count executions deny_id
  flows="$(kc get authentication/flows -r "$realm")"
  flow_count="$(jq --arg alias "$flow_alias" \
    '[.[] | select(.alias == $alias)] | length' <<<"$flows")"
  if ((flow_count == 0)); then
    kc create authentication/flows -r "$realm" \
      -s "alias=$flow_alias" \
      -s providerId=basic-flow \
      -s topLevel=true \
      -s builtIn=false >/dev/null
  elif ((flow_count != 1)); then
    die "multiple authentication flows use alias $flow_alias"
  elif ! jq -e --arg alias "$flow_alias" \
    '.[] | select(.alias == $alias and .topLevel == true and .builtIn == false)' \
    >/dev/null <<<"$flows"; then
    die "existing authentication flow $flow_alias is not an owned top-level flow"
  fi

  executions="$(kc get "authentication/flows/$flow_alias/executions" -r "$realm")"
  if jq -e '.[] | select(.providerId != "deny-access-authenticator")' \
    >/dev/null <<<"$executions"; then
    die "authentication flow $flow_alias contains an unexpected execution"
  fi
  if [[ "$(jq '[.[] | select(.providerId == "deny-access-authenticator")] | length' \
      <<<"$executions")" == "0" ]]; then
    kc create "authentication/flows/$flow_alias/executions/execution" -r "$realm" \
      -s provider=deny-access-authenticator >/dev/null
    executions="$(kc get "authentication/flows/$flow_alias/executions" -r "$realm")"
  fi
  [[ "$(jq '[.[] | select(.providerId == "deny-access-authenticator")] | length' \
      <<<"$executions")" == "1" ]] \
    || die "authentication flow $flow_alias has duplicate deny executions"
  deny_id="$(jq -r \
    '.[] | select(.providerId == "deny-access-authenticator") | .id' \
    <<<"$executions")"
  if ! jq -e --arg id "$deny_id" \
    '.[] | select(.id == $id and .requirement == "REQUIRED")' \
    >/dev/null <<<"$executions"; then
    kc update "authentication/flows/$flow_alias/executions" -r "$realm" \
      -n -s "id=$deny_id" -s requirement=REQUIRED >/dev/null
  fi
}

ensure_allowed_user() {
  local users user_count user_id
  users="$(kc get users -r "$realm" \
    -q "username=$github_allowed_login" -q exact=true -q max=2)"
  user_count="$(jq --arg username "$github_allowed_login" \
    '[.[] | select(.username == $username)] | length' <<<"$users")"
  if ((user_count == 0)); then
    user_id="$(kc create users -r "$realm" -i \
      -s "username=$github_allowed_login" \
      -s enabled=true \
      -s emailVerified=false)"
  elif ((user_count == 1)); then
    user_id="$(jq -r --arg username "$github_allowed_login" \
      '.[] | select(.username == $username) | .id' <<<"$users")"
    kc update "users/$user_id" -r "$realm" -s enabled=true >/dev/null
  else
    die "multiple realm users have username $github_allowed_login"
  fi
  printf '%s' "$user_id"
}

render_identity_provider() {
  local client_id="$1" client_secret="$2"
  jq -n \
    --arg alias "$idp_alias" \
    --arg flow "$flow_alias" \
    --arg client_id "$client_id" \
    --arg client_secret "$client_secret" \
    '{
      alias: $alias,
      displayName: "GitHub",
      providerId: "oauth2",
      enabled: true,
      updateProfileFirstLoginMode: "off",
      trustEmail: false,
      storeToken: false,
      addReadTokenRoleOnCreate: false,
      authenticateByDefault: false,
      linkOnly: false,
      firstBrokerLoginFlowAlias: $flow,
      config: {
        authorizationUrl: "https://github.com/login/oauth/authorize",
        tokenUrl: "https://github.com/login/oauth/access_token",
        userInfoUrl: "https://api.github.com/user",
        clientAuthMethod: "client_secret_post",
        clientId: $client_id,
        clientSecret: $client_secret,
        userIDClaim: "id",
        userNameClaim: "login",
        emailClaim: "email",
        fullNameClaim: "name",
        pkceEnabled: "false",
        syncMode: "IMPORT",
        hideOnLoginPage: "false",
        guiOrder: "0"
      }
    }'
}

ensure_identity_provider() {
  local client_id client_secret representation existing
  client_id="$(read_single_line_file \
    "$github_client_id_file" "HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_ID_FILE")"
  client_secret="$(read_single_line_file \
    "$github_client_secret_file" "HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_SECRET_FILE")"
  [[ "$client_id" =~ ^[A-Za-z0-9._-]{8,128}$ ]] \
    || die "GitHub client ID has an invalid format"
  [[ "$client_secret" =~ ^[A-Za-z0-9._-]{20,512}$ ]] \
    || die "GitHub client secret has an invalid format"
  representation="$(render_identity_provider "$client_id" "$client_secret")"
  existing="$(kc get identity-provider/instances -r "$realm")"
  if jq -e --arg alias "$idp_alias" \
    '.[] | select(.alias == $alias and .providerId != "oauth2")' \
    >/dev/null <<<"$existing"; then
    die "identity provider alias $idp_alias is owned by another provider"
  fi
  if jq -e --arg alias "$idp_alias" '.[] | select(.alias == $alias)' \
    >/dev/null <<<"$existing"; then
    kc_with_json update "identity-provider/instances/$idp_alias" \
      "$representation" >/dev/null
  else
    kc_with_json create identity-provider/instances "$representation" >/dev/null
  fi
  unset client_secret representation
}

remove_other_github_links() {
  local allowed_user_id="$1" users count user_id links
  users="$(kc get users -r "$realm" \
    -q "max=$((MAX_REALM_USERS + 1))" -q briefRepresentation=true)"
  count="$(jq 'length' <<<"$users")"
  ((count <= MAX_REALM_USERS)) \
    || die "realm has more than $MAX_REALM_USERS users; refusing an unbounded link scan"
  while IFS= read -r user_id; do
    links="$(kc get "users/$user_id/federated-identity" -r "$realm")"
    if [[ "$user_id" != "$allowed_user_id" ]] \
      && jq -e --arg alias "$idp_alias" \
        '.[] | select(.identityProvider == $alias)' >/dev/null <<<"$links"; then
      kc delete "users/$user_id/federated-identity/$idp_alias" -r "$realm" >/dev/null
    fi
  done < <(jq -r '.[].id' <<<"$users")
}

ensure_allowed_github_link() {
  local user_id="$1" links current_count current_user_id current_username body
  links="$(kc get "users/$user_id/federated-identity" -r "$realm")"
  current_count="$(jq --arg alias "$idp_alias" \
    '[.[] | select(.identityProvider == $alias)] | length' <<<"$links")"
  if ((current_count > 1)); then
    die "allowed user has duplicate GitHub federated identities"
  fi
  if ((current_count == 1)); then
    current_user_id="$(jq -r --arg alias "$idp_alias" \
      '.[] | select(.identityProvider == $alias) | .userId' <<<"$links")"
    current_username="$(jq -r --arg alias "$idp_alias" \
      '.[] | select(.identityProvider == $alias) | .userName' <<<"$links")"
    if [[ "$current_user_id" == "$github_allowed_user_id" \
      && "$current_username" == "$github_allowed_login" ]]; then
      return
    fi
    kc delete "users/$user_id/federated-identity/$idp_alias" -r "$realm" >/dev/null
  fi
  body="$(jq -n \
    --arg provider "$idp_alias" \
    --arg user_id "$github_allowed_user_id" \
    --arg username "$github_allowed_login" \
    '{identityProvider:$provider,userId:$user_id,userName:$username}')"
  kc_with_json create "users/$user_id/federated-identity/$idp_alias" \
    "$body" >/dev/null
}

verify_configuration() {
  local expected_client_id providers flows executions users user_id links
  local all_users linked_count
  expected_client_id="$(read_single_line_file \
    "$github_client_id_file" "HETERONETWORK_KEYCLOAK_GITHUB_CLIENT_ID_FILE")"
  providers="$(kc get identity-provider/instances -r "$realm")"
  jq -e \
    --arg alias "$idp_alias" \
    --arg flow "$flow_alias" \
    --arg client_id "$expected_client_id" \
    --arg authorization_url "$GITHUB_AUTHORIZATION_URL" \
    --arg token_url "$GITHUB_TOKEN_URL" \
    --arg user_info_url "$GITHUB_USER_INFO_URL" \
    '.[] | select(
      .alias == $alias and
      .providerId == "oauth2" and
      .enabled == true and
      .firstBrokerLoginFlowAlias == $flow and
      .config.clientId == $client_id and
      .config.authorizationUrl == $authorization_url and
      .config.tokenUrl == $token_url and
      .config.userInfoUrl == $user_info_url and
      .config.clientAuthMethod == "client_secret_post" and
      .config.userIDClaim == "id" and
      .config.userNameClaim == "login" and
      .config.emailClaim == "email"
    )' >/dev/null <<<"$providers" \
    || die "GitHub identity provider does not match the required configuration"

  flows="$(kc get authentication/flows -r "$realm")"
  jq -e --arg alias "$flow_alias" \
    '.[] | select(.alias == $alias and .topLevel == true and .builtIn == false)' \
    >/dev/null <<<"$flows" || die "GitHub deny flow is missing"
  executions="$(kc get "authentication/flows/$flow_alias/executions" -r "$realm")"
  [[ "$(jq \
    '[.[] | select(
      .providerId == "deny-access-authenticator" and
      .requirement == "REQUIRED"
    )] | length' <<<"$executions")" == "1" ]] \
    || die "GitHub deny flow is not enforced"
  [[ "$(jq 'length' <<<"$executions")" == "1" ]] \
    || die "GitHub deny flow contains an unexpected execution"

  users="$(kc get users -r "$realm" \
    -q "username=$github_allowed_login" -q exact=true -q max=2)"
  [[ "$(jq --arg username "$github_allowed_login" \
    '[.[] | select(.username == $username and .enabled == true)] | length' \
    <<<"$users")" == "1" ]] || die "allowed GitHub realm user is missing or disabled"
  user_id="$(jq -r --arg username "$github_allowed_login" \
    '.[] | select(.username == $username) | .id' <<<"$users")"
  links="$(kc get "users/$user_id/federated-identity" -r "$realm")"
  jq -e \
    --arg alias "$idp_alias" \
    --arg external_id "$github_allowed_user_id" \
    --arg username "$github_allowed_login" \
    '.[] | select(
      .identityProvider == $alias and
      .userId == $external_id and
      .userName == $username
    )' >/dev/null <<<"$links" || die "allowed GitHub identity link is missing"

  all_users="$(kc get users -r "$realm" \
    -q "max=$((MAX_REALM_USERS + 1))" -q briefRepresentation=true)"
  (($(jq 'length' <<<"$all_users") <= MAX_REALM_USERS)) \
    || die "realm has more than $MAX_REALM_USERS users; refusing an unbounded link scan"
  linked_count=0
  while IFS= read -r candidate_id; do
    links="$(kc get "users/$candidate_id/federated-identity" -r "$realm")"
    if jq -e --arg alias "$idp_alias" \
      '.[] | select(.identityProvider == $alias)' >/dev/null <<<"$links"; then
      ((linked_count += 1))
      [[ "$candidate_id" == "$user_id" ]] \
        || die "another realm user is linked to GitHub"
    fi
  done < <(jq -r '.[].id' <<<"$all_users")
  ((linked_count == 1)) || die "GitHub must have exactly one linked realm user"

  jq -n \
    --arg realm "$realm" \
    --arg alias "$idp_alias" \
    --arg login "$github_allowed_login" \
    --arg user_id "$github_allowed_user_id" \
    '{
      realm: $realm,
      identity_provider: $alias,
      enabled: true,
      unlinked_accounts_denied: true,
      allowed_github_login: $login,
      allowed_github_user_id: $user_id,
      linked_realm_user_count: 1
    }'
}

configure() {
  local user_id
  validate_runtime_config
  trap cleanup EXIT
  login_admin
  ensure_deny_flow
  user_id="$(ensure_allowed_user)"
  ensure_identity_provider
  remove_other_github_links "$user_id"
  ensure_allowed_github_link "$user_id"
  verify_configuration
}

verify() {
  validate_runtime_config
  trap cleanup EXIT
  login_admin
  verify_configuration
}

self_test() {
  local rendered
  require_command jq
  validate_github_login "mizuamedesu" || die "valid GitHub login was rejected"
  ! validate_github_login "-invalid" || die "invalid GitHub login was accepted"
  ! validate_github_login "invalid-" || die "invalid GitHub login was accepted"
  validate_github_user_id "97249122" || die "valid GitHub user ID was rejected"
  ! validate_github_user_id "0" || die "invalid GitHub user ID was accepted"
  rendered="$(render_identity_provider "Iv1.0123456789abcdef" \
    "0123456789abcdef0123456789abcdef01234567")"
  jq -e \
    '.providerId == "oauth2" and
     .enabled == true and
     .firstBrokerLoginFlowAlias == "github-deny-unlinked" and
     .config.clientId == "Iv1.0123456789abcdef" and
     .config.clientSecret == "0123456789abcdef0123456789abcdef01234567" and
     .config.authorizationUrl == "https://github.com/login/oauth/authorize" and
     .config.tokenUrl == "https://github.com/login/oauth/access_token" and
     .config.userInfoUrl == "https://api.github.com/user" and
     .config.clientAuthMethod == "client_secret_post" and
     .config.userIDClaim == "id" and
     .config.userNameClaim == "login" and
     .config.emailClaim == "email"' \
    >/dev/null <<<"$rendered" || die "identity provider rendering failed"
  printf 'Keycloak GitHub identity provider self-test passed\n'
}

case "${1:-}" in
  configure)
    configure
    ;;
  verify)
    verify
    ;;
  self-test)
    self_test
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
