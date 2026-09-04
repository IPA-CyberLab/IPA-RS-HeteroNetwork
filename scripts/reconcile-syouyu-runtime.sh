#!/usr/bin/env bash
set -euo pipefail

readonly NAMESPACE="${SYOUYU_NAMESPACE:-heterocloud-syouyu}"
readonly SECRET_NAME="${SYOUYU_SECRET_NAME:-heterocloud-syouyu-secrets}"
readonly CLOUD_NAMESPACE="${HETEROCLOUD_NAMESPACE:-heterocloud}"
readonly CLOUD_ACCESS_SECRET_NAME="${HETEROCLOUD_SYOUYU_ACCESS_SECRET_NAME:-heterocloud-syouyu-access}"
readonly CLOUD_ACCESS_SECRET_KEY="${HETEROCLOUD_SYOUYU_ACCESS_SECRET_KEY:-hmac-secret}"
readonly CLOUD_API_DEPLOYMENT="${HETEROCLOUD_API_DEPLOYMENT:-heterocloud}"
readonly CLOUD_OWNER_DEPLOYMENT="${HETEROCLOUD_OWNER_DEPLOYMENT:-heterocloud-owner-console}"
readonly PROVIDER_SECRET_NAME="${HETEROCLOUD_PROVIDER_SECRET_NAME:-heterocloud-provider-signing}"
readonly PROVIDER_PRIVATE_KEY_KEY="${HETEROCLOUD_PROVIDER_PRIVATE_KEY_KEY:-ed25519-private.pem}"
readonly PROVIDER_KEY_ID="${HETEROCLOUD_PROVIDER_KEY_ID:-heterocloud-provider-1}"
readonly DB_ROLE="${SYOUYU_DB_ROLE:-syouyu}"
readonly DB_NAME="${SYOUYU_DB_NAME:-syouyu}"
readonly DB_BOOTSTRAP_HOST="${SYOUYU_DB_BOOTSTRAP_HOST:-127.0.0.1}"
readonly DB_SERVICE_HOST="${SYOUYU_DB_SERVICE_HOST:-postgres-ha-connector.kube-system.svc.cluster.local}"
readonly DB_PORT="${SYOUYU_DB_PORT:-25432}"
readonly DB_SUPERUSER="${SYOUYU_DB_SUPERUSER:-postgres}"
readonly SUPERUSER_PASSWORD_FILE="${POSTGRES_SUPERUSER_PASSWORD_FILE:-/etc/heteronetwork/postgres-autopilot/bundle/secrets/superuser.password}"
readonly API_DEPLOYMENT="${SYOUYU_API_DEPLOYMENT:-heterocloud-syouyu-api}"
readonly GARAGE_STATEFULSET="${SYOUYU_GARAGE_STATEFULSET:-heterocloud-syouyu-garage}"

if [[ ${EUID} -ne 0 ]]; then
  exec sudo --preserve-env=KUBECONFIG,SYOUYU_NAMESPACE,SYOUYU_SECRET_NAME,HETEROCLOUD_NAMESPACE,HETEROCLOUD_SYOUYU_ACCESS_SECRET_NAME,HETEROCLOUD_SYOUYU_ACCESS_SECRET_KEY,HETEROCLOUD_API_DEPLOYMENT,HETEROCLOUD_OWNER_DEPLOYMENT,HETEROCLOUD_PROVIDER_SECRET_NAME,HETEROCLOUD_PROVIDER_PRIVATE_KEY_KEY,HETEROCLOUD_PROVIDER_KEY_ID,SYOUYU_DB_ROLE,SYOUYU_DB_NAME,SYOUYU_DB_BOOTSTRAP_HOST,SYOUYU_DB_SERVICE_HOST,SYOUYU_DB_PORT,SYOUYU_DB_SUPERUSER,POSTGRES_SUPERUSER_PASSWORD_FILE,SYOUYU_API_DEPLOYMENT,SYOUYU_GARAGE_STATEFULSET \
    "${BASH_SOURCE[0]}" "$@"
fi

KUBECONFIG="${KUBECONFIG:-/etc/kubernetes/admin.conf}"
export KUBECONFIG

fail() {
  printf 'reconcile-syouyu-runtime: %s\n' "$*" >&2
  exit 1
}

for command in base64 grep jq kubectl mktemp openssl psql tr wc; do
  command -v "${command}" >/dev/null || fail "required command is missing: ${command}"
done

[[ ${NAMESPACE} =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] \
  || fail "SYOUYU_NAMESPACE must be a Kubernetes DNS label"
[[ ${SECRET_NAME} =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] \
  || fail "SYOUYU_SECRET_NAME must be a Kubernetes DNS subdomain"
[[ ${CLOUD_ACCESS_SECRET_NAME} =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] \
  || fail "HETEROCLOUD_SYOUYU_ACCESS_SECRET_NAME must be a Kubernetes DNS subdomain"
[[ ${CLOUD_ACCESS_SECRET_KEY} =~ ^[-._a-zA-Z0-9]+$ ]] \
  || fail "HETEROCLOUD_SYOUYU_ACCESS_SECRET_KEY is invalid"
[[ ${DB_ROLE} =~ ^[A-Za-z_][A-Za-z0-9_]*$ && ${DB_NAME} =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] \
  || fail "database role and name must be SQL identifiers"
[[ ${DB_PORT} =~ ^[0-9]+$ ]] && ((DB_PORT >= 1 && DB_PORT <= 65535)) \
  || fail "SYOUYU_DB_PORT must be between 1 and 65535"
[[ ${PROVIDER_KEY_ID} =~ ^[A-Za-z0-9._-]{1,64}$ ]] \
  || fail "HETEROCLOUD_PROVIDER_KEY_ID is invalid"
test -r "${KUBECONFIG}" || fail "Kubeconfig is not readable: ${KUBECONFIG}"
test -s "${SUPERUSER_PASSWORD_FILE}" \
  || fail "PostgreSQL superuser password file is missing: ${SUPERUSER_PASSWORD_FILE}"

secret_document() {
  local namespace=$1 name=$2
  kubectl -n "${namespace}" get secret "${name}" -o json 2>/dev/null || true
}

secret_value_from_document() {
  local document=$1 key=$2 encoded
  [[ -n ${document} ]] || return 0
  encoded="$(printf '%s' "${document}" | jq -er --arg key "${key}" '.data[$key] // empty' 2>/dev/null || true)"
  [[ -n ${encoded} ]] || return 0
  printf '%s' "${encoded}" | base64 --decode
}

random_hex() {
  openssl rand -hex "$1"
}

is_base64_32_bytes() {
  local value=$1 decoded_size
  decoded_size="$(printf '%s' "${value}" | base64 --decode 2>/dev/null | wc -c | tr -d ' ')" \
    || return 1
  [[ ${decoded_size} == 32 ]]
}

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml |
  kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null

provider_secret="$(secret_document "${CLOUD_NAMESPACE}" "${PROVIDER_SECRET_NAME}")"
[[ -n ${provider_secret} ]] \
  || fail "HeteroCloud provider Secret ${CLOUD_NAMESPACE}/${PROVIDER_SECRET_NAME} is unavailable"
provider_private_key="$(secret_value_from_document "${provider_secret}" "${PROVIDER_PRIVATE_KEY_KEY}")"
[[ -n ${provider_private_key} ]] \
  || fail "HeteroCloud provider Secret does not contain ${PROVIDER_PRIVATE_KEY_KEY}"

runtime_directory="$(mktemp -d /tmp/heterocloud-syouyu-runtime.XXXXXX)"
trap 'rm -rf -- "${runtime_directory}"' EXIT HUP INT TERM
chmod 0700 "${runtime_directory}"
umask 077
printf '%s\n' "${provider_private_key}" >"${runtime_directory}/provider-private.pem"
openssl pkey -in "${runtime_directory}/provider-private.pem" -pubout -text_pub -noout 2>/dev/null |
  grep -q '^ED25519 Public-Key:' \
  || fail "HeteroCloud provider key must be Ed25519"
openssl pkey \
  -in "${runtime_directory}/provider-private.pem" \
  -pubout \
  -out "${runtime_directory}/provider-public.pem" >/dev/null 2>&1 \
  || fail "HeteroCloud provider key is not a usable private key"
provider_public_keys_json="$(jq -cn \
  --arg kid "${PROVIDER_KEY_ID}" \
  --rawfile public_key "${runtime_directory}/provider-public.pem" \
  '{($kid): $public_key}')"

existing_secret="$(secret_document "${NAMESPACE}" "${SECRET_NAME}")"
cloud_access_secret="$(secret_document "${CLOUD_NAMESPACE}" "${CLOUD_ACCESS_SECRET_NAME}")"
existing_database_url="$(secret_value_from_document "${existing_secret}" database-url)"
database_password="$(secret_value_from_document "${existing_secret}" database-password)"
receipt_encryption_key="$(secret_value_from_document "${existing_secret}" receipt-encryption-key-base64)"
principal_context_hmac_secret="$(secret_value_from_document "${existing_secret}" principal-context-hmac-secret)"
if [[ -z ${principal_context_hmac_secret} ]]; then
  principal_context_hmac_secret="$(secret_value_from_document "${cloud_access_secret}" "${CLOUD_ACCESS_SECRET_KEY}")"
fi
garage_rpc_secret="$(secret_value_from_document "${existing_secret}" garage-rpc-secret)"
garage_admin_token="$(secret_value_from_document "${existing_secret}" garage-admin-token)"
garage_metrics_token="$(secret_value_from_document "${existing_secret}" garage-metrics-token)"

if [[ -z ${database_password} && -n ${existing_database_url} ]]; then
  database_authority="${existing_database_url#*://}"
  database_credentials="${database_authority%%@*}"
  recovered_password="${database_credentials#*:}"
  if [[ ${recovered_password} != "${database_credentials}" && ${recovered_password} =~ ^[A-Za-z0-9._~-]{16,128}$ ]]; then
    database_password="${recovered_password}"
  else
    fail "existing database-url password cannot be recovered safely; add database-password to ${NAMESPACE}/${SECRET_NAME}"
  fi
fi

database_password="${database_password:-$(random_hex 32)}"
receipt_encryption_key="${receipt_encryption_key:-$(openssl rand -base64 32 | tr -d '\r\n')}"
principal_context_hmac_secret="${principal_context_hmac_secret:-$(random_hex 32)}"
garage_rpc_secret="${garage_rpc_secret:-$(random_hex 32)}"
garage_admin_token="${garage_admin_token:-$(random_hex 32)}"
garage_metrics_token="${garage_metrics_token:-$(random_hex 32)}"

[[ ${database_password} =~ ^[A-Za-z0-9._~-]{16,128}$ ]] \
  || fail "existing database password is not URL-safe"
is_base64_32_bytes "${receipt_encryption_key}" \
  || fail "receipt encryption key must be base64-encoded 32-byte material"
[[ ${principal_context_hmac_secret} =~ ^[A-Za-z0-9._~-]{32,256}$ ]] \
  || fail "principal context HMAC secret is invalid"
[[ ${garage_rpc_secret} =~ ^[0-9a-fA-F]{64}$ ]] \
  || fail "Garage RPC secret must be exactly 32 bytes encoded as hexadecimal"
[[ ${garage_admin_token} =~ ^[A-Za-z0-9._~-]{32,256}$ ]] \
  || fail "Garage admin token is invalid"
[[ ${garage_metrics_token} =~ ^[A-Za-z0-9._~-]{32,256}$ ]] \
  || fail "Garage metrics token is invalid"

database_url="postgres://${DB_ROLE}:${database_password}@${DB_SERVICE_HOST}:${DB_PORT}/${DB_NAME}?sslmode=require"

export PGPASSWORD
PGPASSWORD="$(<"${SUPERUSER_PASSWORD_FILE}")"
psql "host=${DB_BOOTSTRAP_HOST} port=${DB_PORT} user=${DB_SUPERUSER} dbname=postgres sslmode=require" \
  --set=ON_ERROR_STOP=1 \
  --set=db_role="${DB_ROLE}" \
  --set=db_name="${DB_NAME}" \
  --set=db_password="${database_password}" <<'SQL' >/dev/null
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L CONNECTION LIMIT 96',
  :'db_role', :'db_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'db_role')
\gexec
SELECT format(
  'ALTER ROLE %I WITH LOGIN PASSWORD %L CONNECTION LIMIT 96',
  :'db_role', :'db_password'
)
\gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db_name', :'db_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name')
\gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', :'db_name', :'db_role')
\gexec
SQL
unset PGPASSWORD

write_secret_file() {
  local name=$1 value=$2
  printf '%s' "${value}" >"${runtime_directory}/${name}"
  chmod 0600 "${runtime_directory}/${name}"
}

write_secret_file database-url "${database_url}"
write_secret_file database-password "${database_password}"
write_secret_file provider-public-keys.json "${provider_public_keys_json}"
write_secret_file receipt-encryption-key-base64 "${receipt_encryption_key}"
write_secret_file principal-context-hmac-secret "${principal_context_hmac_secret}"
write_secret_file garage-rpc-secret "${garage_rpc_secret}"
write_secret_file garage-admin-token "${garage_admin_token}"
write_secret_file garage-metrics-token "${garage_metrics_token}"

runtime_secret_changed=false
for key in \
  database-url \
  database-password \
  provider-public-keys.json \
  receipt-encryption-key-base64 \
  principal-context-hmac-secret \
  garage-rpc-secret \
  garage-admin-token \
  garage-metrics-token; do
  if [[ "$(secret_value_from_document "${existing_secret}" "${key}")" != "$(<"${runtime_directory}/${key}")" ]]; then
    runtime_secret_changed=true
    break
  fi
done

garage_secret_changed=false
for key in garage-rpc-secret garage-admin-token garage-metrics-token; do
  if [[ "$(secret_value_from_document "${existing_secret}" "${key}")" != "$(<"${runtime_directory}/${key}")" ]]; then
    garage_secret_changed=true
    break
  fi
done

cloud_access_secret_changed=false
if [[ "$(secret_value_from_document "${cloud_access_secret}" "${CLOUD_ACCESS_SECRET_KEY}")" != "${principal_context_hmac_secret}" ]]; then
  cloud_access_secret_changed=true
fi

kubectl -n "${NAMESPACE}" create secret generic "${SECRET_NAME}" \
  --from-file="${runtime_directory}/database-url" \
  --from-file="${runtime_directory}/database-password" \
  --from-file="${runtime_directory}/provider-public-keys.json" \
  --from-file="${runtime_directory}/receipt-encryption-key-base64" \
  --from-file="${runtime_directory}/principal-context-hmac-secret" \
  --from-file="${runtime_directory}/garage-rpc-secret" \
  --from-file="${runtime_directory}/garage-admin-token" \
  --from-file="${runtime_directory}/garage-metrics-token" \
  --dry-run=client -o yaml |
  kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null

kubectl -n "${CLOUD_NAMESPACE}" create secret generic "${CLOUD_ACCESS_SECRET_NAME}" \
  --from-file="${CLOUD_ACCESS_SECRET_KEY}=${runtime_directory}/principal-context-hmac-secret" \
  --dry-run=client -o yaml |
  kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null

if [[ ${runtime_secret_changed} == true ]] \
  && kubectl -n "${NAMESPACE}" get deployment "${API_DEPLOYMENT}" >/dev/null 2>&1; then
  kubectl -n "${NAMESPACE}" rollout restart "deployment/${API_DEPLOYMENT}" >/dev/null
fi
if [[ ${garage_secret_changed} == true ]] \
  && kubectl -n "${NAMESPACE}" get statefulset "${GARAGE_STATEFULSET}" >/dev/null 2>&1; then
  kubectl -n "${NAMESPACE}" rollout restart "statefulset/${GARAGE_STATEFULSET}" >/dev/null
fi
if [[ ${cloud_access_secret_changed} == true ]]; then
  for deployment in "${CLOUD_API_DEPLOYMENT}" "${CLOUD_OWNER_DEPLOYMENT}"; do
    if kubectl -n "${CLOUD_NAMESPACE}" get deployment "${deployment}" >/dev/null 2>&1; then
      kubectl -n "${CLOUD_NAMESPACE}" rollout restart "deployment/${deployment}" >/dev/null
    fi
  done
fi

printf '%s\n' \
  'Syouyu PostgreSQL role, database, and runtime Secret reconciled.' \
  "Principal HMAC key was synchronized to ${CLOUD_NAMESPACE}/${CLOUD_ACCESS_SECRET_NAME}." \
  'Existing generated credentials were preserved.' \
  "Provider public key was derived from ${CLOUD_NAMESPACE}/${PROVIDER_SECRET_NAME}."
