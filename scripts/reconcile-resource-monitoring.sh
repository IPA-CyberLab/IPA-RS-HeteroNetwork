#!/usr/bin/env bash
# Idempotent bootstrap of a metadata-only SQL role and a private Secret.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAMESPACE="${FLOW_NAMESPACE:-heterocloud-flow}"
SECRET_NAME="${RESOURCE_MONITORING_SECRET:-heterocloud-resource-monitoring}"
DB_ROLE=heterocloud_resource_monitoring
DB_NAME="${HETEROCLOUD_DB_NAME:-heterocloud}"
DB_HOST="${FLOW_GRAFANA_DB_HOST:-127.0.0.1}"
DB_PORT="${FLOW_GRAFANA_DB_PORT:-25432}"
EXPORTER_DB_HOST="${RESOURCE_MONITORING_DB_HOST:-heterocloud-flow-postgres-proxy.heterocloud-flow.svc.cluster.local}"
EXPORTER_DB_PORT="${RESOURCE_MONITORING_DB_PORT:-55432}"
PASSWORD_FILE="${POSTGRES_SUPERUSER_PASSWORD_FILE:-/etc/heteronetwork/postgres-autopilot/bundle/secrets/superuser.password}"
for command in kubectl openssl psql base64; do command -v "$command" >/dev/null; done
[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
test -s "$PASSWORD_FILE"
encoded="$(kubectl -n "$NAMESPACE" get secret "$SECRET_NAME" -o jsonpath='{.data.database-password}' 2>/dev/null || true)"
export RESOURCE_EXPORTER_PASSWORD
RESOURCE_EXPORTER_PASSWORD="$(printf '%s' "$encoded" | base64 --decode)"
RESOURCE_EXPORTER_PASSWORD="${RESOURCE_EXPORTER_PASSWORD:-$(openssl rand -hex 32)}"
[[ "$RESOURCE_EXPORTER_PASSWORD" =~ ^[a-f0-9]{64}$ ]]
export PGPASSWORD
PGPASSWORD="$(<"$PASSWORD_FILE")"
psql "host=$DB_HOST port=$DB_PORT user=postgres dbname=$DB_NAME sslmode=require" \
  --set=ON_ERROR_STOP=1 --set=db_role="$DB_ROLE" --set=db_name="$DB_NAME" \
  --file="${ROOT_DIR}/deploy/monitoring/resource-services.sql" >/dev/null
psql "host=$DB_HOST port=$DB_PORT user=postgres dbname=$DB_NAME sslmode=require" \
  --set=ON_ERROR_STOP=1 --set=db_role="$DB_ROLE" --set=db_name="$DB_NAME" <<'SQL' >/dev/null
\getenv collector_password RESOURCE_EXPORTER_PASSWORD
SELECT format('CREATE ROLE %I LOGIN', :'db_role')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'db_role') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 6 PASSWORD %L', :'db_role', :'collector_password') \gexec
SELECT format('ALTER ROLE %I SET default_transaction_read_only = on', :'db_role') \gexec
SELECT format('ALTER ROLE %I SET statement_timeout = %L', :'db_role', '10s') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db_name', :'db_role') \gexec
SELECT format('GRANT USAGE ON SCHEMA monitoring TO %I', :'db_role') \gexec
SELECT format('GRANT SELECT ON monitoring.resource_services TO %I', :'db_role') \gexec
SQL
unset PGPASSWORD
umask 077
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
printf 'postgresql://%s:%s@%s:%s/%s?sslmode=require' "$DB_ROLE" "$RESOURCE_EXPORTER_PASSWORD" "$EXPORTER_DB_HOST" "$EXPORTER_DB_PORT" "$DB_NAME" > "$temp_dir/database-url"
printf '%s' "$RESOURCE_EXPORTER_PASSWORD" > "$temp_dir/database-password"
kubectl -n "$NAMESPACE" create secret generic "$SECRET_NAME" \
  --from-file=database-url="$temp_dir/database-url" --from-file=database-password="$temp_dir/database-password" \
  --dry-run=client -o yaml | kubectl apply --field-manager=heteronetwork-bootstrap -f - >/dev/null
printf 'Resource monitoring read-only SQL projection and Secret reconciled.\n'
