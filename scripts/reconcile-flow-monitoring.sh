#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${FLOW_NAMESPACE:-heterocloud-flow}"
SECRET_NAME="${FLOW_GRAFANA_SECRET_NAME:-heterocloud-flow-grafana}"
DB_ROLE="${FLOW_GRAFANA_DB_ROLE:-heterocloud_flow_grafana}"
DB_NAME="${FLOW_GRAFANA_DB_NAME:-heterocloud_flow_grafana}"
DB_HOST="${FLOW_GRAFANA_DB_HOST:-127.0.0.1}"
DB_PORT="${FLOW_GRAFANA_DB_PORT:-25432}"
DB_SUPERUSER="${FLOW_GRAFANA_DB_SUPERUSER:-postgres}"
SUPERUSER_PASSWORD_FILE="${POSTGRES_SUPERUSER_PASSWORD_FILE:-/etc/heteronetwork/postgres-autopilot/bundle/secrets/superuser.password}"

for command in kubectl openssl psql base64; do
  command -v "${command}" >/dev/null || {
    printf 'required command is missing: %s\n' "${command}" >&2
    exit 1
  }
done

if [[ ! "${DB_ROLE}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ || ! "${DB_NAME}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
  printf 'database role and name must be SQL identifiers containing only ASCII letters, digits, and underscores\n' >&2
  exit 1
fi

test -s "${SUPERUSER_PASSWORD_FILE}" || {
  printf 'PostgreSQL superuser password file is missing: %s\n' "${SUPERUSER_PASSWORD_FILE}" >&2
  exit 1
}

kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

secret_value() {
  local key="$1"
  local encoded
  encoded="$(kubectl -n "${NAMESPACE}" get secret "${SECRET_NAME}" \
    -o "jsonpath={.data.${key//-/\\-}}" 2>/dev/null || true)"
  if [[ -n "${encoded}" ]]; then
    printf '%s' "${encoded}" | base64 --decode
  fi
}

database_url="$(secret_value database-url)"
database_password="$(secret_value database-password)"
admin_user="$(secret_value admin-user)"
admin_password="$(secret_value admin-password)"
secret_key="$(secret_value secret-key)"

if [[ -z "${database_url}" ]]; then
  database_password="$(openssl rand -hex 32)"
  database_url="postgres://${DB_ROLE}:${database_password}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=require"
elif [[ -z "${database_password}" ]]; then
  authority="${database_url#postgres://}"
  authority="${authority%%/*}"
  credentials="${authority%@*}"
  database_password="${credentials#*:}"
  if [[ "${database_password}" == "${credentials}" || ! "${database_password}" =~ ^[A-Za-z0-9._~-]+$ ]]; then
    printf '%s\n' 'existing database-url password is not safely recoverable; add the database-password key before reconciling' >&2
    exit 1
  fi
fi

admin_user="${admin_user:-admin}"
admin_password="${admin_password:-$(openssl rand -hex 32)}"
secret_key="${secret_key:-$(openssl rand -hex 32)}"

export PGPASSWORD
PGPASSWORD="$(<"${SUPERUSER_PASSWORD_FILE}")"
psql "host=${DB_HOST} port=${DB_PORT} user=${DB_SUPERUSER} dbname=postgres sslmode=require" \
  --set=ON_ERROR_STOP=1 \
  --set=db_role="${DB_ROLE}" \
  --set=db_name="${DB_NAME}" \
  --set=db_password="${database_password}" <<'SQL' >/dev/null
SELECT format(
  'CREATE ROLE %I LOGIN PASSWORD %L CONNECTION LIMIT 36',
  :'db_role',
  :'db_password'
)
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'db_role')
\gexec
SELECT format(
  'ALTER ROLE %I WITH LOGIN PASSWORD %L CONNECTION LIMIT 36',
  :'db_role',
  :'db_password'
)
\gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'db_name', :'db_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db_name')
\gexec
SELECT format('ALTER DATABASE %I OWNER TO %I', :'db_name', :'db_role')
\gexec
SQL
unset PGPASSWORD

kubectl -n "${NAMESPACE}" create secret generic "${SECRET_NAME}" \
  --from-literal=database-url="${database_url}" \
  --from-literal=database-password="${database_password}" \
  --from-literal=admin-user="${admin_user}" \
  --from-literal=admin-password="${admin_password}" \
  --from-literal=secret-key="${secret_key}" \
  --dry-run=client -o yaml |
  kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null

printf 'Grafana PostgreSQL role, database, and Secret reconciled without credential rotation.\n'
