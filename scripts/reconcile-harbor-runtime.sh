#!/usr/bin/env bash
set -euo pipefail

readonly REGISTRY_NAMESPACE="${HARBOR_NAMESPACE:-heterocloud-registry}"
readonly CLOUD_NAMESPACE="${HETEROCLOUD_NAMESPACE:-heterocloud}"
readonly FLASH_NAMESPACE="${HETEROCLOUD_FLASH_NAMESPACE:-heterocloud-flash}"
readonly FLASH_WORKLOAD_NAMESPACE="${HETEROCLOUD_FLASH_WORKLOAD_NAMESPACE:-heterocloud-flash-workloads}"
readonly REGISTRY_PUBLIC_HOST="${HARBOR_PUBLIC_HOST:-registry.heterocloud.mizuame.app}"
readonly DB_ROLE="${HARBOR_DB_ROLE:-heterocloud_registry}"
readonly DB_NAME="${HARBOR_DB_NAME:-heterocloud_registry}"
readonly DB_HOST="${HARBOR_DB_BOOTSTRAP_HOST:-127.0.0.1}"
readonly DB_PORT="${HARBOR_DB_PORT:-25432}"
readonly DB_SUPERUSER="${HARBOR_DB_SUPERUSER:-postgres}"
readonly SUPERUSER_PASSWORD_FILE="${POSTGRES_SUPERUSER_PASSWORD_FILE:-/etc/heteronetwork/postgres-autopilot/bundle/secrets/superuser.password}"

if [[ ${EUID} -ne 0 ]]; then
  exec sudo --preserve-env=KUBECONFIG,HARBOR_NAMESPACE,HETEROCLOUD_NAMESPACE,HETEROCLOUD_FLASH_NAMESPACE,HETEROCLOUD_FLASH_WORKLOAD_NAMESPACE,HARBOR_PUBLIC_HOST,HARBOR_DB_ROLE,HARBOR_DB_NAME,HARBOR_DB_BOOTSTRAP_HOST,HARBOR_DB_PORT,HARBOR_DB_SUPERUSER,POSTGRES_SUPERUSER_PASSWORD_FILE \
    "${BASH_SOURCE[0]}" "$@"
fi

for command in kubectl openssl psql base64; do
  command -v "${command}" >/dev/null || {
    printf 'required command is missing: %s\n' "${command}" >&2
    exit 1
  }
done
if ! command -v htpasswd >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends apache2-utils
fi

[[ ${DB_ROLE} =~ ^[A-Za-z_][A-Za-z0-9_]*$ && ${DB_NAME} =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || {
  printf 'database role and name must be SQL identifiers\n' >&2
  exit 1
}
test -s "${SUPERUSER_PASSWORD_FILE}"

kubectl create namespace "${REGISTRY_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create namespace "${CLOUD_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create namespace "${FLASH_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create namespace "${FLASH_WORKLOAD_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

secret_value() {
  local namespace=$1 secret=$2 key=$3 encoded
  encoded="$(kubectl -n "${namespace}" get secret "${secret}" \
    -o "jsonpath={.data.${key//-/\\-}}" 2>/dev/null || true)"
  if [[ -n ${encoded} ]]; then
    printf '%s' "${encoded}" | base64 --decode
  fi
}

random_hex() {
  openssl rand -hex "$1"
}

admin_password="$(secret_value "${REGISTRY_NAMESPACE}" heterocloud-registry-admin HARBOR_ADMIN_PASSWORD)"
admin_password="${admin_password:-$(random_hex 24)}"
database_password="$(secret_value "${REGISTRY_NAMESPACE}" harbor-database password)"
database_password="${database_password:-$(random_hex 24)}"
core_secret="$(secret_value "${REGISTRY_NAMESPACE}" harbor-core-runtime secret)"
core_secret="${core_secret:-$(random_hex 8)}"
core_secret_key="$(secret_value "${REGISTRY_NAMESPACE}" harbor-core-runtime secretKey)"
core_secret_key="${core_secret_key:-$(random_hex 8)}"
csrf_key="$(secret_value "${REGISTRY_NAMESPACE}" harbor-core-runtime CSRF_KEY)"
csrf_key="${csrf_key:-$(random_hex 16)}"
jobservice_secret="$(secret_value "${REGISTRY_NAMESPACE}" harbor-jobservice-runtime JOBSERVICE_SECRET)"
jobservice_secret="${jobservice_secret:-$(random_hex 8)}"
registry_http_secret="$(secret_value "${REGISTRY_NAMESPACE}" harbor-registry-runtime REGISTRY_HTTP_SECRET)"
registry_http_secret="${registry_http_secret:-$(random_hex 8)}"
registry_password="$(secret_value "${REGISTRY_NAMESPACE}" harbor-registry-credentials REGISTRY_PASSWD)"
registry_password="${registry_password:-$(random_hex 24)}"
registry_username=harbor_registry_user
registry_htpasswd="$(secret_value "${REGISTRY_NAMESPACE}" harbor-registry-credentials REGISTRY_HTPASSWD)"
registry_htpasswd="${registry_htpasswd:-$(htpasswd -nbBC 10 "${registry_username}" "${registry_password}")}"

export PGPASSWORD
PGPASSWORD="$(<"${SUPERUSER_PASSWORD_FILE}")"
psql "host=${DB_HOST} port=${DB_PORT} user=${DB_SUPERUSER} dbname=postgres sslmode=require" \
  --set=ON_ERROR_STOP=1 \
  --set=db_role="${DB_ROLE}" \
  --set=db_name="${DB_NAME}" \
  --set=db_password="${database_password}" <<'SQL' >/dev/null
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L CONNECTION LIMIT 500',
  :'db_role', :'db_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'db_role')
\gexec
SELECT format(
  'ALTER ROLE %I WITH LOGIN PASSWORD %L CONNECTION LIMIT 500',
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

apply_secret() {
  local namespace=$1 name=$2
  shift 2
  local args=()
  while (($#)); do
    args+=(--from-literal="$1")
    shift
  done
  kubectl -n "${namespace}" create secret generic "${name}" \
    "${args[@]}" --dry-run=client -o yaml |
    kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null
}

apply_secret "${REGISTRY_NAMESPACE}" heterocloud-registry-admin \
  "HARBOR_ADMIN_PASSWORD=${admin_password}"
apply_secret "${CLOUD_NAMESPACE}" heterocloud-registry-admin \
  "HARBOR_ADMIN_PASSWORD=${admin_password}"
apply_secret "${FLASH_NAMESPACE}" heterocloud-registry-pull-auth \
  'username=admin' \
  "password=${admin_password}"
apply_secret "${REGISTRY_NAMESPACE}" harbor-database \
  "password=${database_password}"
apply_secret "${REGISTRY_NAMESPACE}" harbor-core-runtime \
  "secret=${core_secret}" \
  "secretKey=${core_secret_key}" \
  "CSRF_KEY=${csrf_key}"
apply_secret "${REGISTRY_NAMESPACE}" harbor-jobservice-runtime \
  "JOBSERVICE_SECRET=${jobservice_secret}"
apply_secret "${REGISTRY_NAMESPACE}" harbor-registry-runtime \
  "REGISTRY_HTTP_SECRET=${registry_http_secret}"
apply_secret "${REGISTRY_NAMESPACE}" harbor-registry-credentials \
  "REGISTRY_PASSWD=${registry_password}" \
  "REGISTRY_HTPASSWD=${registry_htpasswd}"

kubectl -n "${FLASH_WORKLOAD_NAMESPACE}" create secret docker-registry heterocloud-registry-pull \
  --docker-server="${REGISTRY_PUBLIC_HOST}" \
  --docker-username=admin \
  --docker-password="${admin_password}" \
  --dry-run=client -o yaml |
  kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null

if ! kubectl -n "${REGISTRY_NAMESPACE}" get secret harbor-token >/dev/null 2>&1; then
  token_dir="$(mktemp -d /tmp/heterocloud-harbor-token.XXXXXX)"
  trap 'rm -rf -- "${token_dir}"' EXIT
  openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 3650 \
    -subj '/CN=harbor-token' \
    -keyout "${token_dir}/tls.key" \
    -out "${token_dir}/tls.crt" >/dev/null 2>&1
  kubectl -n "${REGISTRY_NAMESPACE}" create secret tls harbor-token \
    --cert="${token_dir}/tls.crt" \
    --key="${token_dir}/tls.key" >/dev/null
fi

printf '%s\n' \
  'Harbor PostgreSQL database and runtime Secrets are reconciled.' \
  'Existing credentials were preserved.'
