use async_trait::async_trait;
use ipars_control_plane::{
    ControlPlaneError, ControlPlaneStore, HeartbeatStoreUpdate, RemovedNode, TokenLedger,
};
use ipars_types::{
    ClusterId, EndpointCandidate, NodeHealth, NodeId, NodeRecord, PathRecord, RelayCapability,
    Route, TokenLedgerMetrics, TokenLedgerRecord, TokenStatus, VpnIp,
};
use sqlx::{Executor, PgPool, Row, SqlitePool};

#[derive(Debug, Clone)]
pub struct SqliteControlPlaneStore {
    pool: SqlitePool,
}

impl SqliteControlPlaneStore {
    pub async fn connect(database_url: &str) -> Result<Self, ControlPlaneError> {
        let pool = SqlitePool::connect(database_url).await.map_err(sql_error)?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub async fn from_pool(pool: SqlitePool) -> Result<Self, ControlPlaneError> {
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), ControlPlaneError> {
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY NOT NULL,
                    record_json TEXT NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS nodes_vpn_ip_unique
                ON nodes(json_extract(record_json, '$.vpn_ip'));
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS paths (
                    local_node_id TEXT NOT NULL,
                    remote_node_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (local_node_id, remote_node_id)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS health (
                    node_id TEXT PRIMARY KEY NOT NULL,
                    record_json TEXT NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS tokens (
                    cluster_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (cluster_id, nonce)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        Ok(())
    }
}

#[async_trait]
impl ControlPlaneStore for SqliteControlPlaneStore {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        let node_id = node.node_id.clone();
        let vpn_ip = node.vpn_ip;
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES (?1, ?2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(|error| node_insert_error(error, &node_id, &vpn_ip))?;
        Ok(())
    }

    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(row_to_node).transpose()
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        sqlx::query("SELECT record_json FROM nodes ORDER BY node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .into_iter()
            .map(row_to_node)
            .collect()
    }

    async fn remove_node(&self, node_id: &NodeId) -> Result<RemovedNode, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let node = row
            .map(row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        let health_result = sqlx::query("DELETE FROM health WHERE node_id = ?1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let path_result =
            sqlx::query("DELETE FROM paths WHERE local_node_id = ?1 OR remote_node_id = ?1")
                .bind(node_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(sql_error)?;
        sqlx::query("DELETE FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(RemovedNode {
            node,
            removed_path_count: path_result.rows_affected() as usize,
            removed_health: health_result.rows_affected() > 0,
        })
    }

    async fn update_node_candidates(
        &self,
        node_id: &NodeId,
        candidates: Vec<EndpointCandidate>,
    ) -> Result<(), ControlPlaneError> {
        let result = sqlx::query(
            "UPDATE nodes SET record_json = json_set(record_json, '$.endpoint_candidates', json(?2)) WHERE node_id = ?1",
        )
            .bind(node_id.as_str())
            .bind(serde_json::to_string(&candidates).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        Ok(())
    }

    async fn update_node_relay_capability(
        &self,
        node_id: &NodeId,
        relay_capability: Option<RelayCapability>,
    ) -> Result<(), ControlPlaneError> {
        let result = sqlx::query(
            "UPDATE nodes SET record_json = json_set(record_json, '$.relay_capability', json(?2)) WHERE node_id = ?1",
        )
            .bind(node_id.as_str())
            .bind(serde_json::to_string(&relay_capability).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        Ok(())
    }

    async fn update_node_routes(
        &self,
        node_id: &NodeId,
        routes: Vec<Route>,
    ) -> Result<(), ControlPlaneError> {
        let result = sqlx::query(
            "UPDATE nodes SET record_json = json_set(record_json, '$.routes', json(?2)) WHERE node_id = ?1",
        )
            .bind(node_id.as_str())
            .bind(serde_json::to_string(&routes).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        Ok(())
    }

    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let result = sqlx::query(
            r#"
            UPDATE nodes
            SET record_json = json_set(record_json, '$.wireguard_public_key', ?3)
            WHERE node_id = ?1
              AND json_extract(record_json, '$.wireguard_public_key') = ?2
            "#,
        )
        .bind(node_id.as_str())
        .bind(expected_current_public_key)
        .bind(next_public_key)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            if self.get_node(node_id).await?.is_none() {
                return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
            }
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "wireguard public key changed before rotation completed".to_string(),
            });
        }
        self.get_node(node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))
    }

    async fn upsert_health(
        &self,
        node_id: NodeId,
        health: NodeHealth,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO health (node_id, record_json)
            VALUES (?1, ?2)
            ON CONFLICT(node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(node_id.as_str())
        .bind(serde_json::to_string(&health).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn get_health(&self, node_id: &NodeId) -> Result<Option<NodeHealth>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM health WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(row_to_health).transpose()
    }

    async fn apply_heartbeat(&self, update: HeartbeatStoreUpdate) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query("UPDATE nodes SET record_json = record_json WHERE node_id = ?1")
            .bind(update.node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(update.node_id.clone()))?;
        let previous_health = sqlx::query("SELECT record_json FROM health WHERE node_id = ?1")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?
            .map(row_to_health)
            .transpose()?;
        ensure_heartbeat_is_newer(&update, previous_health.as_ref())?;

        node.endpoint_candidates = update.candidates;
        node.relay_capability = update.relay_capability;
        if let Some(routes) = update.routes {
            node.routes = routes;
        }
        sqlx::query("UPDATE nodes SET record_json = ?2 WHERE node_id = ?1")
            .bind(update.node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        sqlx::query(
            r#"
            INSERT INTO health (node_id, record_json)
            VALUES (?1, ?2)
            ON CONFLICT(node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(update.node_id.as_str())
        .bind(serde_json::to_string(&update.health).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        sqlx::query("DELETE FROM paths WHERE local_node_id = ?1")
            .bind(update.node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        for path in update.paths {
            sqlx::query(
                r#"
                INSERT INTO paths (local_node_id, remote_node_id, record_json)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(local_node_id, remote_node_id)
                DO UPDATE SET record_json = excluded.record_json
                "#,
            )
            .bind(path.key.local.as_str())
            .bind(path.key.remote.as_str())
            .bind(serde_json::to_string(&path).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO paths (local_node_id, remote_node_id, record_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(local_node_id, remote_node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(path.key.local.as_str())
        .bind(path.key.remote.as_str())
        .bind(serde_json::to_string(&path).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn replace_node_paths(
        &self,
        node_id: &NodeId,
        paths: Vec<PathRecord>,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query("DELETE FROM paths WHERE local_node_id = ?1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        for path in paths {
            sqlx::query(
                r#"
                INSERT INTO paths (local_node_id, remote_node_id, record_json)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(local_node_id, remote_node_id)
                DO UPDATE SET record_json = excluded.record_json
                "#,
            )
            .bind(path.key.local.as_str())
            .bind(path.key.remote.as_str())
            .bind(serde_json::to_string(&path).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn list_paths_for(&self, node_id: &NodeId) -> Result<Vec<PathRecord>, ControlPlaneError> {
        sqlx::query(
            r#"
            SELECT record_json FROM paths
            WHERE local_node_id = ?1 OR remote_node_id = ?1
            ORDER BY local_node_id, remote_node_id
            "#,
        )
        .bind(node_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        .into_iter()
        .map(row_to_path)
        .collect()
    }
}

#[async_trait]
impl TokenLedger for SqliteControlPlaneStore {
    async fn upsert_token(&self, record: TokenLedgerRecord) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO tokens (cluster_id, nonce, record_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(cluster_id, nonce)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_string(&record).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn get_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
    ) -> Result<Option<TokenLedgerRecord>, ControlPlaneError> {
        let row =
            sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = ?1 AND nonce = ?2")
                .bind(cluster_id.as_str())
                .bind(nonce)
                .fetch_optional(&self.pool)
                .await
                .map_err(sql_error)?;
        row.map(row_to_token).transpose()
    }

    async fn revoke_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut record = self
            .get_token(cluster_id, nonce)
            .await?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(nonce.to_string()))?;
        record.revoked_at = Some(revoked_at);
        self.upsert_token(record.clone()).await?;
        Ok(record)
    }

    async fn record_token_use(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        loop {
            let record = self
                .get_token(cluster_id, nonce)
                .await?
                .ok_or_else(|| ControlPlaneError::TokenNotFound(nonce.to_string()))?;
            let status = record.status(now);
            if status != TokenStatus::Active {
                return Err(ControlPlaneError::TokenRejected {
                    nonce: nonce.to_string(),
                    status,
                });
            }
            let previous_json = serde_json::to_string(&record).map_err(json_error)?;
            let mut updated = record;
            updated.uses = updated.uses.saturating_add(1);
            let updated_json = serde_json::to_string(&updated).map_err(json_error)?;
            let result = sqlx::query(
                r#"
                UPDATE tokens
                SET record_json = ?4
                WHERE cluster_id = ?1
                  AND nonce = ?2
                  AND record_json = ?3
                "#,
            )
            .bind(cluster_id.as_str())
            .bind(nonce)
            .bind(previous_json)
            .bind(updated_json)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
            if result.rows_affected() == 1 {
                return Ok(updated);
            }
        }
    }

    async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        let records = sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = ?1")
            .bind(cluster_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?;
        let mut metrics = TokenLedgerMetrics::default();
        for record in records.into_iter().map(row_to_token) {
            metrics.observe_record(&record?, now);
        }
        Ok(metrics)
    }
}

#[derive(Debug, Clone)]
pub struct PostgresControlPlaneStore {
    pool: PgPool,
}

// PostgreSQL can race internally even for concurrent `IF NOT EXISTS` DDL.
const POSTGRES_MIGRATION_ADVISORY_LOCK_ID: i64 = 0x4950_4152_534d_4947;

impl PostgresControlPlaneStore {
    pub async fn connect(database_url: &str) -> Result<Self, ControlPlaneError> {
        let pool = PgPool::connect(database_url).await.map_err(sql_error)?;
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    pub async fn from_pool(pool: PgPool) -> Result<Self, ControlPlaneError> {
        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    async fn migrate(&self) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(POSTGRES_MIGRATION_ADVISORY_LOCK_ID)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY NOT NULL,
                    record_json JSONB NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE UNIQUE INDEX IF NOT EXISTS nodes_vpn_ip_unique
                ON nodes ((record_json->>'vpn_ip'));
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS paths (
                    local_node_id TEXT NOT NULL,
                    remote_node_id TEXT NOT NULL,
                    record_json JSONB NOT NULL,
                    PRIMARY KEY (local_node_id, remote_node_id)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS health (
                    node_id TEXT PRIMARY KEY NOT NULL,
                    record_json JSONB NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS tokens (
                    cluster_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    record_json JSONB NOT NULL,
                    PRIMARY KEY (cluster_id, nonce)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }
}

#[async_trait]
impl ControlPlaneStore for PostgresControlPlaneStore {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        let node_id = node.node_id.clone();
        let vpn_ip = node.vpn_ip;
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES ($1, $2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(|error| node_insert_error(error, &node_id, &vpn_ip))?;
        Ok(())
    }

    async fn get_node(&self, node_id: &NodeId) -> Result<Option<NodeRecord>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1")
            .bind(node_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(pg_row_to_node).transpose()
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, ControlPlaneError> {
        sqlx::query("SELECT record_json FROM nodes ORDER BY node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .into_iter()
            .map(pg_row_to_node)
            .collect()
    }

    async fn remove_node(&self, node_id: &NodeId) -> Result<RemovedNode, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let node = row
            .map(pg_row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        let health_result = sqlx::query("DELETE FROM health WHERE node_id = $1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let path_result =
            sqlx::query("DELETE FROM paths WHERE local_node_id = $1 OR remote_node_id = $1")
                .bind(node_id.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(sql_error)?;
        sqlx::query("DELETE FROM nodes WHERE node_id = $1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(RemovedNode {
            node,
            removed_path_count: path_result.rows_affected() as usize,
            removed_health: health_result.rows_affected() > 0,
        })
    }

    async fn update_node_candidates(
        &self,
        node_id: &NodeId,
        candidates: Vec<EndpointCandidate>,
    ) -> Result<(), ControlPlaneError> {
        let result = sqlx::query(
            "UPDATE nodes SET record_json = jsonb_set(record_json, '{endpoint_candidates}', $2) WHERE node_id = $1",
        )
            .bind(node_id.as_str())
            .bind(serde_json::to_value(&candidates).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        Ok(())
    }

    async fn update_node_relay_capability(
        &self,
        node_id: &NodeId,
        relay_capability: Option<RelayCapability>,
    ) -> Result<(), ControlPlaneError> {
        let result = sqlx::query(
            "UPDATE nodes SET record_json = jsonb_set(record_json, '{relay_capability}', $2) WHERE node_id = $1",
        )
            .bind(node_id.as_str())
            .bind(serde_json::to_value(&relay_capability).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        Ok(())
    }

    async fn update_node_routes(
        &self,
        node_id: &NodeId,
        routes: Vec<Route>,
    ) -> Result<(), ControlPlaneError> {
        let result = sqlx::query(
            "UPDATE nodes SET record_json = jsonb_set(record_json, '{routes}', $2) WHERE node_id = $1",
        )
            .bind(node_id.as_str())
            .bind(serde_json::to_value(&routes).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
        }
        Ok(())
    }

    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let result = sqlx::query(
            r#"
            UPDATE nodes
            SET record_json = jsonb_set(record_json, '{wireguard_public_key}', $3)
            WHERE node_id = $1
              AND record_json->>'wireguard_public_key' = $2
            "#,
        )
        .bind(node_id.as_str())
        .bind(expected_current_public_key)
        .bind(serde_json::Value::String(next_public_key))
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        if result.rows_affected() == 0 {
            if self.get_node(node_id).await?.is_none() {
                return Err(ControlPlaneError::NodeNotFound(node_id.clone()));
            }
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "wireguard public key changed before rotation completed".to_string(),
            });
        }
        self.get_node(node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))
    }

    async fn upsert_health(
        &self,
        node_id: NodeId,
        health: NodeHealth,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO health (node_id, record_json)
            VALUES ($1, $2)
            ON CONFLICT(node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(node_id.as_str())
        .bind(serde_json::to_value(&health).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn get_health(&self, node_id: &NodeId) -> Result<Option<NodeHealth>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM health WHERE node_id = $1")
            .bind(node_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(pg_row_to_health).transpose()
    }

    async fn apply_heartbeat(&self, update: HeartbeatStoreUpdate) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(pg_row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(update.node_id.clone()))?;
        let previous_health = sqlx::query("SELECT record_json FROM health WHERE node_id = $1")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?
            .map(pg_row_to_health)
            .transpose()?;
        ensure_heartbeat_is_newer(&update, previous_health.as_ref())?;

        node.endpoint_candidates = update.candidates;
        node.relay_capability = update.relay_capability;
        if let Some(routes) = update.routes {
            node.routes = routes;
        }
        sqlx::query("UPDATE nodes SET record_json = $2 WHERE node_id = $1")
            .bind(update.node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        sqlx::query(
            r#"
            INSERT INTO health (node_id, record_json)
            VALUES ($1, $2)
            ON CONFLICT(node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(update.node_id.as_str())
        .bind(serde_json::to_value(&update.health).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        sqlx::query("DELETE FROM paths WHERE local_node_id = $1")
            .bind(update.node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        for path in update.paths {
            sqlx::query(
                r#"
                INSERT INTO paths (local_node_id, remote_node_id, record_json)
                VALUES ($1, $2, $3)
                ON CONFLICT(local_node_id, remote_node_id)
                DO UPDATE SET record_json = excluded.record_json
                "#,
            )
            .bind(path.key.local.as_str())
            .bind(path.key.remote.as_str())
            .bind(serde_json::to_value(&path).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn upsert_path(&self, path: PathRecord) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO paths (local_node_id, remote_node_id, record_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(local_node_id, remote_node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(path.key.local.as_str())
        .bind(path.key.remote.as_str())
        .bind(serde_json::to_value(&path).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn replace_node_paths(
        &self,
        node_id: &NodeId,
        paths: Vec<PathRecord>,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query("DELETE FROM paths WHERE local_node_id = $1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        for path in paths {
            sqlx::query(
                r#"
                INSERT INTO paths (local_node_id, remote_node_id, record_json)
                VALUES ($1, $2, $3)
                ON CONFLICT(local_node_id, remote_node_id)
                DO UPDATE SET record_json = excluded.record_json
                "#,
            )
            .bind(path.key.local.as_str())
            .bind(path.key.remote.as_str())
            .bind(serde_json::to_value(&path).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn list_paths_for(&self, node_id: &NodeId) -> Result<Vec<PathRecord>, ControlPlaneError> {
        sqlx::query(
            r#"
            SELECT record_json FROM paths
            WHERE local_node_id = $1 OR remote_node_id = $1
            ORDER BY local_node_id, remote_node_id
            "#,
        )
        .bind(node_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        .into_iter()
        .map(pg_row_to_path)
        .collect()
    }
}

#[async_trait]
impl TokenLedger for PostgresControlPlaneStore {
    async fn upsert_token(&self, record: TokenLedgerRecord) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO tokens (cluster_id, nonce, record_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(cluster_id, nonce)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_value(&record).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn get_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
    ) -> Result<Option<TokenLedgerRecord>, ControlPlaneError> {
        let row =
            sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = $1 AND nonce = $2")
                .bind(cluster_id.as_str())
                .bind(nonce)
                .fetch_optional(&self.pool)
                .await
                .map_err(sql_error)?;
        row.map(pg_row_to_token).transpose()
    }

    async fn revoke_token(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut record = self
            .get_token(cluster_id, nonce)
            .await?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(nonce.to_string()))?;
        record.revoked_at = Some(revoked_at);
        self.upsert_token(record.clone()).await?;
        Ok(record)
    }

    async fn record_token_use(
        &self,
        cluster_id: &ClusterId,
        nonce: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        loop {
            let record = self
                .get_token(cluster_id, nonce)
                .await?
                .ok_or_else(|| ControlPlaneError::TokenNotFound(nonce.to_string()))?;
            let status = record.status(now);
            if status != TokenStatus::Active {
                return Err(ControlPlaneError::TokenRejected {
                    nonce: nonce.to_string(),
                    status,
                });
            }
            let previous_json = serde_json::to_value(&record).map_err(json_error)?;
            let mut updated = record;
            updated.uses = updated.uses.saturating_add(1);
            let updated_json = serde_json::to_value(&updated).map_err(json_error)?;
            let result = sqlx::query(
                r#"
                UPDATE tokens
                SET record_json = $4
                WHERE cluster_id = $1
                  AND nonce = $2
                  AND record_json = $3
                "#,
            )
            .bind(cluster_id.as_str())
            .bind(nonce)
            .bind(previous_json)
            .bind(updated_json)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
            if result.rows_affected() == 1 {
                return Ok(updated);
            }
        }
    }

    async fn token_metrics(
        &self,
        cluster_id: &ClusterId,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerMetrics, ControlPlaneError> {
        let records = sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = $1")
            .bind(cluster_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?;
        let mut metrics = TokenLedgerMetrics::default();
        for record in records.into_iter().map(pg_row_to_token) {
            metrics.observe_record(&record?, now);
        }
        Ok(metrics)
    }
}

fn row_to_node(row: sqlx::sqlite::SqliteRow) -> Result<NodeRecord, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_path(row: sqlx::sqlite::SqliteRow) -> Result<PathRecord, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_health(row: sqlx::sqlite::SqliteRow) -> Result<NodeHealth, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_token(row: sqlx::sqlite::SqliteRow) -> Result<TokenLedgerRecord, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn pg_row_to_node(row: sqlx::postgres::PgRow) -> Result<NodeRecord, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_path(row: sqlx::postgres::PgRow) -> Result<PathRecord, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_health(row: sqlx::postgres::PgRow) -> Result<NodeHealth, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_token(row: sqlx::postgres::PgRow) -> Result<TokenLedgerRecord, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn ensure_heartbeat_is_newer(
    update: &HeartbeatStoreUpdate,
    previous: Option<&NodeHealth>,
) -> Result<(), ControlPlaneError> {
    if let Some(previous) = previous {
        if update.health.last_seen_at <= previous.last_seen_at {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: update.node_id.clone(),
                reason: format!(
                    "signed_at {} is not newer than last accepted heartbeat {}",
                    update.health.last_seen_at, previous.last_seen_at
                ),
            });
        }
    }
    Ok(())
}

fn sql_error(error: sqlx::Error) -> ControlPlaneError {
    ControlPlaneError::Store(error.to_string())
}

fn node_insert_error(error: sqlx::Error, node_id: &NodeId, vpn_ip: &VpnIp) -> ControlPlaneError {
    if let sqlx::Error::Database(database_error) = &error {
        let constraint = database_error.constraint().unwrap_or_default();
        let message = database_error.message();
        if constraint == "nodes_pkey" || message.contains("nodes.node_id") {
            return ControlPlaneError::NodeAlreadyExists(node_id.clone());
        }
        if constraint == "nodes_vpn_ip_unique" || message.contains("nodes_vpn_ip_unique") {
            return ControlPlaneError::VpnIpAlreadyAllocated(*vpn_ip);
        }
    }
    sql_error(error)
}

fn json_error(error: serde_json::Error) -> ControlPlaneError {
    ControlPlaneError::Store(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use chrono::Utc;
    use ipars_control_plane::{ControlPlaneStore, TokenAdmission};
    use ipars_types::{
        CandidateSource, ClusterId, EndpointCandidate, EndpointCandidateKind, HealthState,
        JoinTokenClaims, KeyId, NodeHealth, NodeRecord, PathMetrics, PathRecord, PathScore,
        PathState, PeerPathKey, RelayCapability, Role, Tag, TokenPolicy, VpnIp,
    };

    use super::*;

    fn node(id: &str, ip: Ipv4Addr) -> NodeRecord {
        NodeRecord {
            node_id: NodeId::from_string(id),
            cluster_id: ClusterId::from_string("cluster-a"),
            vpn_ip: VpnIp(IpAddr::V4(ip)),
            identity_public_key: format!("identity-{id}"),
            wireguard_public_key: format!("wg-{id}"),
            role: Role::edge(),
            tags: BTreeSet::new(),
            endpoint_candidates: Vec::new(),
            relay_capability: None,
            token_policy: TokenPolicy::default(),
            routes: Vec::new(),
            registered_at: Utc::now(),
        }
    }

    fn claims(cluster_id: ClusterId) -> JoinTokenClaims {
        let mut tags = BTreeSet::new();
        tags.insert(Tag::from_string("edge"));
        JoinTokenClaims {
            cluster_id,
            bootstrap_endpoints: Vec::new(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            not_before: Utc::now() - chrono::Duration::seconds(1),
            role: Role::edge(),
            tags,
            issuer: NodeId::from_string("issuer"),
            key_id: KeyId::from_string("root"),
            policy: TokenPolicy::default(),
            nonce: "nonce-a".to_string(),
        }
    }

    fn candidate(node_id: &str) -> EndpointCandidate {
        EndpointCandidate {
            node_id: NodeId::from_string(node_id),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([203, 0, 113, 10], 51820)),
            observed_at: Utc::now(),
            priority: 100,
            cost: 10,
            source: CandidateSource::StunProbe,
        }
    }

    fn relay_capability() -> RelayCapability {
        RelayCapability {
            enabled_by_policy: true,
            public_endpoint: Some(SocketAddr::from(([203, 0, 113, 30], 51820))),
            admission_url: Some("http://203.0.113.30:9580".to_string()),
            max_sessions: 100,
            active_sessions: 7,
            max_mbps: 1000,
            e2e_only: true,
        }
    }

    fn heartbeat_update(
        local: &NodeRecord,
        remote: &NodeRecord,
        accepted_at: chrono::DateTime<Utc>,
        marker: &str,
        host_octet: u8,
    ) -> Result<HeartbeatStoreUpdate, Box<dyn std::error::Error>> {
        let candidate = EndpointCandidate {
            node_id: local.node_id.clone(),
            kind: EndpointCandidateKind::StunReflexive,
            addr: SocketAddr::from(([203, 0, 113, host_octet], 51820)),
            observed_at: accepted_at,
            priority: u16::from(host_octet),
            cost: 10,
            source: CandidateSource::StunProbe,
        };
        let mut relay = relay_capability();
        relay.active_sessions = u32::from(host_octet);
        let route = Route {
            id: format!("route-{marker}"),
            cidr: format!("10.{host_octet}.0.0/16").parse()?,
            advertised_by: local.node_id.clone(),
            via: Some(local.node_id.clone()),
            metric: u32::from(host_octet),
            tags: BTreeSet::new(),
        };
        let path = PathRecord {
            key: PeerPathKey::new(local.node_id.clone(), remote.node_id.clone()),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: None,
            relay_node: None,
            score: PathScore::calculate(
                PathState::DirectNatTraversal,
                &PathMetrics::default(),
                true,
                u32::from(host_octet),
            ),
            updated_at: accepted_at,
            pinned: false,
        };
        Ok(HeartbeatStoreUpdate {
            node_id: local.node_id.clone(),
            candidates: vec![candidate],
            relay_capability: Some(relay),
            routes: Some(vec![route]),
            health: NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: accepted_at,
                latency_ms: Some(f32::from(host_octet)),
                relay_load: None,
                message: Some(marker.to_string()),
            },
            paths: vec![path],
        })
    }

    fn temp_sqlite_url(name: &str) -> (String, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "ipars-store-{name}-{}-{}.sqlite",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        (format!("sqlite://{}?mode=rwc", path.display()), path)
    }

    #[tokio::test]
    async fn sqlite_store_round_trips_nodes_and_paths() -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let local = node("node-a", Ipv4Addr::new(100, 64, 0, 1));
        let remote = node("node-b", Ipv4Addr::new(100, 64, 0, 2));
        store.insert_node(local.clone()).await?;
        store.insert_node(remote.clone()).await?;
        let duplicate_ip = node("node-c", Ipv4Addr::new(100, 64, 0, 1));
        assert!(matches!(
            store.insert_node(duplicate_ip).await,
            Err(ControlPlaneError::VpnIpAlreadyAllocated(_))
        ));
        let mut duplicate_node_id = local.clone();
        duplicate_node_id.vpn_ip = VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)));
        assert!(matches!(
            store.insert_node(duplicate_node_id).await,
            Err(ControlPlaneError::NodeAlreadyExists(_))
        ));

        let path = PathRecord {
            key: PeerPathKey::new(local.node_id.clone(), remote.node_id.clone()),
            selected_state: PathState::DirectNatTraversal,
            selected_candidate: None,
            relay_node: None,
            score: PathScore::calculate(
                PathState::DirectNatTraversal,
                &PathMetrics::default(),
                true,
                0,
            ),
            updated_at: Utc::now(),
            pinned: false,
        };
        let remote_reported_path = PathRecord {
            key: PeerPathKey::new(remote.node_id.clone(), local.node_id.clone()),
            ..path.clone()
        };
        store.upsert_path(path).await?;
        store.upsert_path(remote_reported_path).await?;

        assert_eq!(store.get_node(&local.node_id).await?, Some(local.clone()));
        assert_eq!(store.list_nodes().await?.len(), 2);
        assert_eq!(store.list_paths_for(&local.node_id).await?.len(), 2);
        store.replace_node_paths(&local.node_id, Vec::new()).await?;
        let remaining_paths = store.list_paths_for(&local.node_id).await?;
        assert_eq!(remaining_paths.len(), 1);
        assert_eq!(remaining_paths[0].key.local, remote.node_id);
        store
            .update_node_candidates(&local.node_id, vec![candidate(local.node_id.as_str())])
            .await?;
        assert_eq!(
            store
                .get_node(&local.node_id)
                .await?
                .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
                .endpoint_candidates
                .len(),
            1
        );
        store
            .update_node_relay_capability(&local.node_id, Some(relay_capability()))
            .await?;
        assert_eq!(
            store
                .get_node(&local.node_id)
                .await?
                .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
                .relay_capability
                .map(|capability| capability.active_sessions),
            Some(7)
        );
        store
            .update_node_relay_capability(&local.node_id, None)
            .await?;
        assert_eq!(
            store
                .get_node(&local.node_id)
                .await?
                .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
                .relay_capability,
            None
        );
        let advertised_route = Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: local.node_id.clone(),
            via: Some(local.node_id.clone()),
            metric: 100,
            tags: Default::default(),
        };
        store
            .update_node_routes(&local.node_id, vec![advertised_route.clone()])
            .await?;
        assert_eq!(
            store
                .get_node(&local.node_id)
                .await?
                .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
                .routes,
            vec![advertised_route.clone()]
        );
        let rotated = store
            .rotate_node_wireguard_public_key(
                &local.node_id,
                &local.wireguard_public_key,
                "wg-node-a-rotated".to_string(),
            )
            .await?;
        assert_eq!(rotated.wireguard_public_key, "wg-node-a-rotated");
        assert_eq!(rotated.endpoint_candidates.len(), 1);
        assert_eq!(rotated.relay_capability, None);
        assert_eq!(rotated.routes, vec![advertised_route]);
        assert!(matches!(
            store
                .rotate_node_wireguard_public_key(
                    &local.node_id,
                    &local.wireguard_public_key,
                    "wg-node-a-stale".to_string()
                )
                .await,
            Err(ControlPlaneError::NodeUpdateRejected { .. })
        ));
        let health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: Utc::now(),
            latency_ms: Some(12.0),
            relay_load: None,
            message: Some("ok".to_string()),
        };
        store
            .upsert_health(local.node_id.clone(), health.clone())
            .await?;
        assert_eq!(store.get_health(&local.node_id).await?, Some(health));

        let removed = store.remove_node(&local.node_id).await?;
        assert_eq!(removed.node.node_id, local.node_id);
        assert_eq!(removed.removed_path_count, 1);
        assert!(removed.removed_health);
        assert_eq!(store.get_node(&local.node_id).await?, None);
        assert_eq!(store.get_health(&local.node_id).await?, None);
        assert!(store.list_paths_for(&remote.node_id).await?.is_empty());
        assert!(matches!(
            store.remove_node(&local.node_id).await,
            Err(ControlPlaneError::NodeNotFound(_))
        ));

        let admission = TokenAdmission::new(std::sync::Arc::new(store.clone()));
        let token_claims = claims(local.cluster_id.clone());
        admission
            .issue_from_claims(&token_claims, Utc::now())
            .await?;
        let accepted = admission.admit_join(&token_claims, Utc::now()).await?;
        assert_eq!(accepted.uses, 1);

        let rejected = admission.admit_join(&token_claims, Utc::now()).await;
        assert!(matches!(
            rejected,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Exhausted,
                ..
            })
        ));
        let token_metrics = store.token_metrics(&local.cluster_id, Utc::now()).await?;
        assert_eq!(token_metrics.issued_count, 1);
        assert_eq!(token_metrics.active_count, 0);
        assert_eq!(token_metrics.exhausted_count, 1);
        assert_eq!(token_metrics.use_count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_heartbeat_commit_is_atomic_and_monotonic(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("heartbeat-monotonic");
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let local = node("node-a", Ipv4Addr::new(100, 64, 0, 1));
        let remote = node("node-b", Ipv4Addr::new(100, 64, 0, 2));
        store.insert_node(local.clone()).await?;
        store.insert_node(remote.clone()).await?;
        let old_at = Utc::now();
        let new_at = old_at + chrono::Duration::seconds(1);
        let old = heartbeat_update(&local, &remote, old_at, "old", 10)?;
        let newest = heartbeat_update(&local, &remote, new_at, "new", 11)?;

        store.apply_heartbeat(old.clone()).await?;
        store.apply_heartbeat(newest.clone()).await?;
        assert!(matches!(
            store.apply_heartbeat(old).await,
            Err(ControlPlaneError::NodeSignatureRejected { .. })
        ));

        let stored_node = store
            .get_node(&local.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?;
        assert_eq!(stored_node.endpoint_candidates, newest.candidates);
        assert_eq!(stored_node.relay_capability, newest.relay_capability);
        assert_eq!(
            stored_node.routes,
            newest.routes.clone().unwrap_or_default()
        );
        assert_eq!(store.get_health(&local.node_id).await?, Some(newest.health));
        assert_eq!(store.list_paths_for(&local.node_id).await?, newest.paths);

        drop(store);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_token_admission_enforces_max_uses_under_concurrency(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("token-concurrency");
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let admission = Arc::new(TokenAdmission::new(Arc::new(store.clone())));
        let cluster_id = ClusterId::new();
        let mut token_claims = claims(cluster_id.clone());
        token_claims.nonce = "concurrent-token".to_string();
        token_claims.policy.max_token_uses = Some(1);
        admission
            .issue_from_claims(&token_claims, Utc::now())
            .await?;

        let task_count = 16;
        let barrier = Arc::new(tokio::sync::Barrier::new(task_count));
        let mut tasks = Vec::new();
        for _ in 0..task_count {
            let admission = Arc::clone(&admission);
            let claims = token_claims.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                admission.admit_join(&claims, Utc::now()).await
            }));
        }

        let mut accepted = 0;
        let mut exhausted = 0;
        for task in tasks {
            match task.await? {
                Ok(record) => {
                    accepted += 1;
                    assert_eq!(record.uses, 1);
                }
                Err(ControlPlaneError::TokenRejected {
                    status: TokenStatus::Exhausted,
                    ..
                }) => exhausted += 1,
                Err(error) => {
                    return Err(format!("unexpected token admission error: {error}").into())
                }
            }
        }

        assert_eq!(accepted, 1);
        assert_eq!(exhausted, task_count - 1);
        let final_record = store
            .get_token(&cluster_id, &token_claims.nonce)
            .await?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(token_claims.nonce.clone()))?;
        assert_eq!(final_record.uses, 1);
        assert_eq!(final_record.status(Utc::now()), TokenStatus::Exhausted);
        let token_metrics = store.token_metrics(&cluster_id, Utc::now()).await?;
        assert_eq!(token_metrics.issued_count, 1);
        assert_eq!(token_metrics.active_count, 0);
        assert_eq!(token_metrics.exhausted_count, 1);
        assert_eq!(token_metrics.use_count, 1);

        let _ = std::fs::remove_file(database_path);
        Ok(())
    }
}
