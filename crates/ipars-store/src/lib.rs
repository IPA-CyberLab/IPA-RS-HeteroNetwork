pub mod customer_resources;

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipars_control_plane::{
    ensure_token_definition_matches, overlay_route_catalog_epoch, ControlPlaneError,
    ControlPlaneStore, HeartbeatStoreUpdate, KeycloakCandidateLease, RejoinNodeStoreUpdate,
    RemovedNode, TokenLedger,
};
use ipars_types::api::ClientGatewaySelection;
use ipars_types::{
    ClusterId, ClusterPolicy, EndpointCandidate, NatClassification, NodeHealth, NodeId, NodeRecord,
    PathRecord, RelayCapability, Route, ServiceInstance, TokenLedgerMetrics, TokenLedgerRecord,
    TokenRevocationOutcome, TokenRevocationRecord, TokenStatus, VpnIp,
};
use sqlx::{Executor, PgPool, Postgres, QueryBuilder, Row, Sqlite, SqlitePool};

const PATH_PAIR_QUERY_CHUNK_SIZE: usize = 200;
const MAX_KEYCLOAK_CANDIDATE_QUERY_LIMIT: usize = 64;

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
                CREATE TABLE IF NOT EXISTS cluster_policies (
                    cluster_id TEXT PRIMARY KEY NOT NULL,
                    record_json TEXT NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS overlay_routing_epochs (
                    cluster_id TEXT PRIMARY KEY NOT NULL,
                    epoch INTEGER NOT NULL CHECK(epoch >= 0)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
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
        let heartbeat_signature_table_existed = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'heartbeat_signatures'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(sql_error)?
            > 0;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS heartbeat_signatures (
                    node_id TEXT PRIMARY KEY NOT NULL,
                    accepted_signature_at TEXT NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        if !heartbeat_signature_table_existed {
            self.pool
                .execute(
                    r#"
                INSERT OR IGNORE INTO heartbeat_signatures (node_id, accepted_signature_at)
                SELECT node_id, json_extract(record_json, '$.last_seen_at')
                FROM health
                WHERE json_extract(record_json, '$.last_seen_at') IS NOT NULL;
                "#,
                )
                .await
                .map_err(sql_error)?;
        }
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS nat_classifications (
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
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS token_revocations (
                    cluster_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (cluster_id, nonce)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS service_instances (
                    cluster_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (cluster_id, instance_id)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                UPDATE service_instances
                SET record_json = json_set(record_json, '$.owner_host_id', 'legacy-unowned')
                WHERE json_type(record_json, '$.owner_host_id') IS NULL;
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                UPDATE service_instances
                SET record_json = json_set(record_json, '$.owner_node_id', NULL)
                WHERE json_type(record_json, '$.owner_node_id') IS NULL;
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS keycloak_candidate_leases (
                    cluster_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    lease_expires_at INTEGER NOT NULL,
                    generation INTEGER NOT NULL DEFAULT 0,
                    eligible INTEGER NOT NULL DEFAULT 1,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY (cluster_id, node_id)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        let keycloak_candidate_columns =
            sqlx::query("PRAGMA table_info(keycloak_candidate_leases)")
                .fetch_all(&self.pool)
                .await
                .map_err(sql_error)?
                .into_iter()
                .filter_map(|row| row.try_get::<String, _>("name").ok())
                .collect::<BTreeSet<_>>();
        if !keycloak_candidate_columns.contains("generation") {
            self.pool
                .execute(
                    "ALTER TABLE keycloak_candidate_leases ADD COLUMN generation INTEGER NOT NULL DEFAULT 0",
                )
                .await
                .map_err(sql_error)?;
        }
        if !keycloak_candidate_columns.contains("eligible") {
            self.pool
                .execute(
                    "ALTER TABLE keycloak_candidate_leases ADD COLUMN eligible INTEGER NOT NULL DEFAULT 1",
                )
                .await
                .map_err(sql_error)?;
        }
        self.pool
            .execute(
                r#"
                CREATE INDEX IF NOT EXISTS keycloak_candidate_leases_expiry_idx
                ON keycloak_candidate_leases(cluster_id, lease_expires_at);
                "#,
            )
            .await
            .map_err(sql_error)?;
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS client_gateway_selections (
                    client_id TEXT PRIMARY KEY NOT NULL,
                    gateway_node_id TEXT NOT NULL,
                    selected_at_millis INTEGER NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        customer_resources::migrate_sqlite_customer_resources(&self.pool).await?;
        Ok(())
    }
}

#[async_trait]
impl ControlPlaneStore for SqliteControlPlaneStore {
    async fn get_cluster_policy(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Option<ClusterPolicy>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM cluster_policies WHERE cluster_id = ?1")
            .bind(cluster_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(row_to_cluster_policy).transpose()
    }

    async fn initialize_cluster_policy_if_absent(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<ClusterPolicy, ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        let insert_result = sqlx::query(
            "INSERT OR IGNORE INTO cluster_policies (cluster_id, record_json) VALUES (?1, ?2)",
        )
        .bind(cluster_id.as_str())
        .bind(serde_json::to_string(&policy).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        if insert_result.rows_affected() > 0 {
            bump_sqlite_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        }
        let stored = sqlite_cluster_policy(&mut transaction, cluster_id)
            .await?
            .ok_or_else(|| {
                ControlPlaneError::Store(format!(
                    "cluster policy initialization did not persist cluster {cluster_id}"
                ))
            })?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(stored)
    }

    async fn get_overlay_routing_epoch(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<u64, ControlPlaneError> {
        let epoch = sqlx::query_scalar::<_, i64>(
            "SELECT epoch FROM overlay_routing_epochs WHERE cluster_id = ?1",
        )
        .bind(cluster_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?
        .unwrap_or(0);
        u64::try_from(epoch)
            .map_err(|_| ControlPlaneError::Store("overlay routing epoch is negative".to_string()))
    }

    async fn upsert_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        if sqlite_cluster_policy(&mut transaction, cluster_id)
            .await?
            .as_ref()
            == Some(&policy)
        {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(());
        }
        sqlx::query(
            r#"
            INSERT INTO cluster_policies (cluster_id, record_json)
            VALUES (?1, ?2)
            ON CONFLICT(cluster_id) DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(serde_json::to_string(&policy).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn upsert_cluster_policy_if_route_catalog_epoch(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
        expected_route_catalog_epoch: u64,
    ) -> Result<bool, ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        let catalog = sqlite_cluster_route_catalog(&mut transaction, cluster_id).await?;
        if overlay_route_catalog_epoch(&catalog)? != expected_route_catalog_epoch {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(false);
        }
        if sqlite_cluster_policy(&mut transaction, cluster_id)
            .await?
            .as_ref()
            == Some(&policy)
        {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(true);
        }
        sqlx::query(
            r#"
            INSERT INTO cluster_policies (cluster_id, record_json)
            VALUES (?1, ?2)
            ON CONFLICT(cluster_id) DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(serde_json::to_string(&policy).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(true)
    }

    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        let node_id = node.node_id.clone();
        let vpn_ip = node.vpn_ip;
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES (?1, ?2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(|error| node_insert_error(error, &node_id, &vpn_ip))?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn insert_node_if_cluster_policy(
        &self,
        node: NodeRecord,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        if sqlite_cluster_policy(&mut transaction, &node.cluster_id).await?
            != expected_cluster_policy
        {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = expected_route_catalog_epoch {
            let catalog = sqlite_cluster_route_catalog(&mut transaction, &node.cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node_id = node.node_id.clone();
        let vpn_ip = node.vpn_ip;
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES (?1, ?2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(|error| node_insert_error(error, &node_id, &vpn_ip))?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
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
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
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
        sqlx::query("DELETE FROM heartbeat_signatures WHERE node_id = ?1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        sqlx::query("DELETE FROM nat_classifications WHERE node_id = ?1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        sqlx::query(
            "DELETE FROM client_gateway_selections WHERE client_id = ?1 OR gateway_node_id = ?1",
        )
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
        bump_sqlite_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
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
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.routes == routes {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(());
        }
        node.routes = routes;
        sqlx::query("UPDATE nodes SET record_json = ?2 WHERE node_id = ?1")
            .bind(node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn update_node_routes_if_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        node_id: &NodeId,
        routes: Vec<Route>,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        if sqlite_cluster_policy(&mut transaction, cluster_id).await? != expected_cluster_policy {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = expected_route_catalog_epoch {
            let catalog = sqlite_cluster_route_catalog(&mut transaction, cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == *cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.routes == routes {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(());
        }
        node.routes = routes;
        sqlx::query("UPDATE nodes SET record_json = ?2 WHERE node_id = ?1")
            .bind(node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn rejoin_node_if_cluster_policy(
        &self,
        update: RejoinNodeStoreUpdate,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        if sqlite_cluster_policy(&mut transaction, &update.cluster_id).await?
            != update.expected_cluster_policy
        {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = update.expected_route_catalog_epoch {
            let catalog =
                sqlite_cluster_route_catalog(&mut transaction, &update.cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node_id = update.expected_node.node_id.clone();
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == update.cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node != update.expected_node {
            return Err(ControlPlaneError::NodeStateChanged(node_id));
        }
        let routes_changed = node.routes != update.routes;
        node.endpoint_candidates = update.candidates;
        node.relay_capability = update.relay_capability;
        node.routes = update.routes;
        sqlx::query("UPDATE nodes SET record_json = ?2 WHERE node_id = ?1")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        if routes_changed {
            bump_sqlite_overlay_routing_epoch(&mut transaction, &update.cluster_id).await?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(node)
    }

    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.wireguard_public_key != expected_current_public_key {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "wireguard public key changed before rotation completed".to_string(),
            });
        }
        if node.wireguard_public_key == next_public_key {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(node);
        }
        node.wireguard_public_key = next_public_key;
        sqlx::query("UPDATE nodes SET record_json = ?2 WHERE node_id = ?1")
            .bind(node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        bump_sqlite_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(node)
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

    async fn get_heartbeat_signature_timestamp(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError> {
        let row = sqlx::query(
            "SELECT accepted_signature_at FROM heartbeat_signatures WHERE node_id = ?1",
        )
        .bind(node_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?;
        row.map(|row| parse_utc_timestamp(&row.get::<String, _>("accepted_signature_at")))
            .transpose()
    }

    async fn list_health(&self) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        let rows = sqlx::query("SELECT node_id, record_json FROM health ORDER BY node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?;
        let mut health_by_node = BTreeMap::new();
        for row in rows {
            let node_id = NodeId::from_string(row.get::<String, _>("node_id"));
            health_by_node.insert(node_id, row_to_health(row)?);
        }
        Ok(health_by_node)
    }

    async fn list_nodes_and_health(
        &self,
    ) -> Result<(Vec<NodeRecord>, BTreeMap<NodeId, NodeHealth>), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let node_rows = sqlx::query("SELECT record_json FROM nodes ORDER BY node_id")
            .fetch_all(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let health_rows = sqlx::query("SELECT node_id, record_json FROM health ORDER BY node_id")
            .fetch_all(&mut *transaction)
            .await
            .map_err(sql_error)?;

        let nodes = node_rows
            .into_iter()
            .map(row_to_node)
            .collect::<Result<Vec<_>, _>>()?;
        let mut health_by_node = BTreeMap::new();
        for row in health_rows {
            let node_id = NodeId::from_string(row.get::<String, _>("node_id"));
            health_by_node.insert(node_id, row_to_health(row)?);
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok((nodes, health_by_node))
    }

    async fn upsert_nat_classification(
        &self,
        node_id: NodeId,
        classification: NatClassification,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO nat_classifications (node_id, record_json)
            VALUES (?1, ?2)
            ON CONFLICT(node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(node_id.as_str())
        .bind(serde_json::to_string(&classification).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn get_nat_classification(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<NatClassification>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM nat_classifications WHERE node_id = ?1")
            .bind(node_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(row_to_nat_classification).transpose()
    }

    async fn list_nat_classifications(
        &self,
    ) -> Result<BTreeMap<NodeId, NatClassification>, ControlPlaneError> {
        let rows =
            sqlx::query("SELECT node_id, record_json FROM nat_classifications ORDER BY node_id")
                .fetch_all(&self.pool)
                .await
                .map_err(sql_error)?;
        let mut classifications = BTreeMap::new();
        for row in rows {
            let node_id = NodeId::from_string(row.get::<String, _>("node_id"));
            classifications.insert(node_id, row_to_nat_classification(row)?);
        }
        Ok(classifications)
    }

    async fn apply_heartbeat(&self, update: HeartbeatStoreUpdate) -> Result<(), ControlPlaneError> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(sql_error)?;
        if sqlite_cluster_policy(&mut transaction, &update.cluster_id)
            .await?
            .as_ref()
            != update.expected_cluster_policy.as_ref()
        {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = update.expected_route_catalog_epoch {
            let catalog =
                sqlite_cluster_route_catalog(&mut transaction, &update.cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = ?1")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(row_to_node)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(update.node_id.clone()))?;
        update.ensure_matches_node_generation(&node)?;
        let routes_changed = update
            .routes
            .as_ref()
            .is_some_and(|routes| node.routes != *routes);
        let previous_health = sqlx::query("SELECT record_json FROM health WHERE node_id = ?1")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?
            .map(row_to_health)
            .transpose()?;
        let previous_signature_at = sqlx::query(
            "SELECT accepted_signature_at FROM heartbeat_signatures WHERE node_id = ?1",
        )
        .bind(update.node_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(|row| parse_utc_timestamp(&row.get::<String, _>("accepted_signature_at")))
        .transpose()?;
        ensure_heartbeat_is_newer(&update, previous_signature_at, previous_health.as_ref())?;

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
        if let Some(accepted_signature_at) = update.accepted_signature_at {
            sqlx::query(
                r#"
                INSERT INTO heartbeat_signatures (node_id, accepted_signature_at)
                VALUES (?1, ?2)
                ON CONFLICT(node_id)
                DO UPDATE SET accepted_signature_at = excluded.accepted_signature_at
                "#,
            )
            .bind(update.node_id.as_str())
            .bind(accepted_signature_at.to_rfc3339())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
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
        if let Some(classification) = update.nat_classification {
            sqlx::query(
                r#"
                INSERT INTO nat_classifications (node_id, record_json)
                VALUES (?1, ?2)
                ON CONFLICT(node_id)
                DO UPDATE SET record_json = excluded.record_json
                "#,
            )
            .bind(update.node_id.as_str())
            .bind(serde_json::to_string(&classification).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
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
        if routes_changed {
            bump_sqlite_overlay_routing_epoch(&mut transaction, &update.cluster_id).await?;
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

    async fn list_all_paths(&self) -> Result<Vec<PathRecord>, ControlPlaneError> {
        sqlx::query("SELECT record_json FROM paths ORDER BY local_node_id, remote_node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .into_iter()
            .map(row_to_path)
            .collect()
    }

    async fn list_paths_for_pairs(
        &self,
        pairs: &BTreeSet<(NodeId, NodeId)>,
    ) -> Result<Vec<PathRecord>, ControlPlaneError> {
        let pairs = pairs.iter().collect::<Vec<_>>();
        let mut paths = Vec::new();
        for chunk in pairs.chunks(PATH_PAIR_QUERY_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Sqlite>::new("SELECT record_json FROM paths WHERE ");
            {
                let mut conditions = query.separated(" OR ");
                for (local, remote) in chunk {
                    conditions
                        .push("(local_node_id = ")
                        .push_bind_unseparated(local.as_str())
                        .push_unseparated(" AND remote_node_id = ")
                        .push_bind_unseparated(remote.as_str())
                        .push_unseparated(")");
                }
            }
            query.push(" ORDER BY local_node_id, remote_node_id");
            paths.extend(
                query
                    .build()
                    .fetch_all(&self.pool)
                    .await
                    .map_err(sql_error)?
                    .into_iter()
                    .map(row_to_path)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        paths.sort_by(|left, right| {
            left.key
                .local
                .cmp(&right.key.local)
                .then_with(|| left.key.remote.cmp(&right.key.remote))
        });
        Ok(paths)
    }

    async fn upsert_service_instance(
        &self,
        instance: ServiceInstance,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO service_instances (cluster_id, instance_id, record_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(cluster_id, instance_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(instance.cluster_id.as_str())
        .bind(instance.instance_id.as_str())
        .bind(serde_json::to_string(&instance).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn remove_service_instance(
        &self,
        cluster_id: &ClusterId,
        instance_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        let result =
            sqlx::query("DELETE FROM service_instances WHERE cluster_id = ?1 AND instance_id = ?2")
                .bind(cluster_id.as_str())
                .bind(instance_id)
                .execute(&self.pool)
                .await
                .map_err(sql_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_service_instances(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<ServiceInstance>, ControlPlaneError> {
        sqlx::query(
            "SELECT record_json FROM service_instances WHERE cluster_id = ?1 ORDER BY instance_id",
        )
        .bind(cluster_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        .into_iter()
        .map(row_to_service_instance)
        .collect()
    }

    async fn upsert_keycloak_candidate(
        &self,
        candidate: KeycloakCandidateLease,
    ) -> Result<bool, ControlPlaneError> {
        let lease_expires_at = keycloak_candidate_expiry_nanos(&candidate.lease_expires_at)?;
        let updated_at = keycloak_candidate_expiry_nanos(&candidate.updated_at)?;
        let record_json = serde_json::to_string(&candidate).map_err(json_error)?;
        let result = sqlx::query(
            r#"
            INSERT INTO keycloak_candidate_leases
                (cluster_id, node_id, lease_expires_at, generation, eligible, record_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(cluster_id, node_id) DO UPDATE SET
                lease_expires_at = excluded.lease_expires_at,
                generation = excluded.generation,
                eligible = excluded.eligible,
                record_json = excluded.record_json
            WHERE keycloak_candidate_leases.lease_expires_at <= ?7
               OR keycloak_candidate_leases.generation < excluded.generation
            "#,
        )
        .bind(candidate.cluster_id.as_str())
        .bind(candidate.node_id.as_str())
        .bind(lease_expires_at)
        .bind(candidate.generation)
        .bind(candidate.eligible)
        .bind(record_json)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_keycloak_candidates(
        &self,
        cluster_id: &ClusterId,
        lease_cutoff: DateTime<Utc>,
        after_node_id: Option<&NodeId>,
        limit: usize,
    ) -> Result<Vec<KeycloakCandidateLease>, ControlPlaneError> {
        let lease_cutoff = keycloak_candidate_expiry_nanos(&lease_cutoff)?;
        let limit = keycloak_candidate_query_limit(limit)?;
        sqlx::query(
            r#"
            SELECT cluster_id, node_id, lease_expires_at, generation, eligible, record_json
            FROM keycloak_candidate_leases
            WHERE cluster_id = ?1
              AND lease_expires_at > ?2
              AND eligible = 1
              AND (?3 IS NULL OR node_id > ?3)
            ORDER BY node_id
            LIMIT ?4
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(lease_cutoff)
        .bind(after_node_id.map(NodeId::as_str))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        .into_iter()
        .map(row_to_keycloak_candidate)
        .collect()
    }

    async fn upsert_client_gateway_selection(
        &self,
        selection: ClientGatewaySelection,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO client_gateway_selections
                (client_id, gateway_node_id, selected_at_millis)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(client_id) DO UPDATE SET
                gateway_node_id = excluded.gateway_node_id,
                selected_at_millis = excluded.selected_at_millis
            "#,
        )
        .bind(selection.client_id.as_str())
        .bind(selection.gateway_node_id.as_str())
        .bind(selection.selected_at.timestamp_millis())
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn remove_client_gateway_selection(
        &self,
        client_id: &NodeId,
    ) -> Result<bool, ControlPlaneError> {
        let result = sqlx::query("DELETE FROM client_gateway_selections WHERE client_id = ?1")
            .bind(client_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_client_gateway_selections(
        &self,
    ) -> Result<BTreeMap<NodeId, ClientGatewaySelection>, ControlPlaneError> {
        let mut selections = BTreeMap::new();
        for row in sqlx::query(
            "SELECT client_id, gateway_node_id, selected_at_millis FROM client_gateway_selections ORDER BY client_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        {
            let selection = row_to_client_gateway_selection(row)?;
            selections.insert(selection.client_id.clone(), selection);
        }
        Ok(selections)
    }

    async fn latest_client_gateway_selection_at(
        &self,
    ) -> Result<Option<DateTime<Utc>>, ControlPlaneError> {
        let row = sqlx::query(
            "SELECT MAX(selected_at_millis) AS selected_at_millis FROM client_gateway_selections",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(sql_error)?;
        row.get::<Option<i64>, _>("selected_at_millis")
            .map(sqlite_selection_timestamp)
            .transpose()
    }
}

#[async_trait]
impl TokenLedger for SqliteControlPlaneStore {
    async fn insert_token_if_absent(
        &self,
        record: TokenLedgerRecord,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query(
            r#"
            INSERT INTO tokens (cluster_id, nonce, record_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(cluster_id, nonce) DO NOTHING
            "#,
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_string(&record).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let row =
            sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = ?1 AND nonce = ?2")
                .bind(record.cluster_id.as_str())
                .bind(record.nonce.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(sql_error)?;
        let mut stored = row
            .map(row_to_token)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(record.nonce.clone()))?;
        ensure_token_definition_matches(&stored, &record)?;
        let revocation = sqlx::query(
            "SELECT record_json FROM token_revocations WHERE cluster_id = ?1 AND nonce = ?2",
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(row_to_revocation)
        .transpose()?;
        if let Some(revocation) = revocation {
            stored.revoked_at = Some(revocation.revoked_at);
            update_sqlite_token(&mut transaction, &stored).await?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(stored)
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

    async fn admit_token(
        &self,
        record: TokenLedgerRecord,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query(
            r#"
            INSERT INTO tokens (cluster_id, nonce, record_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(cluster_id, nonce) DO NOTHING
            "#,
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_string(&record).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let row =
            sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = ?1 AND nonce = ?2")
                .bind(record.cluster_id.as_str())
                .bind(record.nonce.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(sql_error)?;
        let mut stored = row
            .map(row_to_token)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(record.nonce.clone()))?;
        ensure_token_definition_matches(&stored, &record)?;
        let revocation = sqlx::query(
            "SELECT record_json FROM token_revocations WHERE cluster_id = ?1 AND nonce = ?2",
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(row_to_revocation)
        .transpose()?;
        if let Some(revocation) = revocation {
            stored.revoked_at = Some(revocation.revoked_at);
        }
        let status = stored.status(now);
        if status != TokenStatus::Active {
            update_sqlite_token(&mut transaction, &stored).await?;
            transaction.commit().await.map_err(sql_error)?;
            return Err(ControlPlaneError::TokenRejected {
                nonce: record.nonce,
                status,
            });
        }
        stored.uses = stored.uses.saturating_add(1);
        update_sqlite_token(&mut transaction, &stored).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(stored)
    }

    async fn revoke_token(
        &self,
        revocation: TokenRevocationRecord,
    ) -> Result<TokenRevocationOutcome, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query(
            r#"
            INSERT INTO token_revocations (cluster_id, nonce, record_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(cluster_id, nonce) DO NOTHING
            "#,
        )
        .bind(revocation.cluster_id.as_str())
        .bind(revocation.nonce.as_str())
        .bind(serde_json::to_string(&revocation).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let stored_revocation = sqlx::query(
            "SELECT record_json FROM token_revocations WHERE cluster_id = ?1 AND nonce = ?2",
        )
        .bind(revocation.cluster_id.as_str())
        .bind(revocation.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(row_to_revocation)
        .transpose()?
        .ok_or_else(|| ControlPlaneError::TokenNotFound(revocation.nonce.clone()))?;
        let row =
            sqlx::query("SELECT record_json FROM tokens WHERE cluster_id = ?1 AND nonce = ?2")
                .bind(revocation.cluster_id.as_str())
                .bind(revocation.nonce.as_str())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(sql_error)?;
        let record = row.map(row_to_token).transpose()?.map(|mut record| {
            record.revoked_at = Some(stored_revocation.revoked_at);
            record
        });
        if let Some(record) = &record {
            update_sqlite_token(&mut transaction, record).await?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(TokenRevocationOutcome {
            revocation: stored_revocation,
            record,
        })
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
        let revocations =
            sqlx::query("SELECT record_json FROM token_revocations WHERE cluster_id = ?1")
                .bind(cluster_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(sql_error)?;
        let mut metrics = TokenLedgerMetrics::default();
        let mut token_nonces = BTreeSet::new();
        for record in records.into_iter().map(row_to_token) {
            let record = record?;
            token_nonces.insert(record.nonce.clone());
            metrics.observe_record(&record, now);
        }
        for revocation in revocations.into_iter().map(row_to_revocation) {
            let revocation = revocation?;
            if !token_nonces.contains(&revocation.nonce) {
                metrics.observe_revocation_tombstone();
            }
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
                CREATE TABLE IF NOT EXISTS cluster_policies (
                    cluster_id TEXT PRIMARY KEY NOT NULL,
                    record_json JSONB NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS overlay_routing_epochs (
                    cluster_id TEXT PRIMARY KEY NOT NULL,
                    epoch BIGINT NOT NULL CHECK(epoch >= 0)
                );
                "#,
            )
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
        let heartbeat_signature_table_existed =
            sqlx::query_scalar::<_, bool>("SELECT to_regclass('heartbeat_signatures') IS NOT NULL")
                .fetch_one(&mut *transaction)
                .await
                .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS heartbeat_signatures (
                    node_id TEXT PRIMARY KEY NOT NULL,
                    accepted_signature_at TEXT NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        if !heartbeat_signature_table_existed {
            transaction
                .execute(
                    r#"
                INSERT INTO heartbeat_signatures (node_id, accepted_signature_at)
                SELECT node_id, record_json->>'last_seen_at'
                FROM health
                WHERE record_json ? 'last_seen_at'
                ON CONFLICT (node_id) DO NOTHING;
                "#,
                )
                .await
                .map_err(sql_error)?;
        }
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS nat_classifications (
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
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS token_revocations (
                    cluster_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    record_json JSONB NOT NULL,
                    PRIMARY KEY (cluster_id, nonce)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS service_instances (
                    cluster_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    record_json JSONB NOT NULL,
                    PRIMARY KEY (cluster_id, instance_id)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                UPDATE service_instances
                SET record_json = record_json || jsonb_build_object('owner_host_id', 'legacy-unowned')
                WHERE NOT (record_json ? 'owner_host_id');
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                UPDATE service_instances
                SET record_json = record_json || '{"owner_node_id": null}'::jsonb
                WHERE NOT (record_json ? 'owner_node_id');
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS keycloak_candidate_leases (
                    cluster_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    lease_expires_at BIGINT NOT NULL,
                    generation BIGINT NOT NULL DEFAULT 0,
                    eligible BOOLEAN NOT NULL DEFAULT TRUE,
                    record_json JSONB NOT NULL,
                    PRIMARY KEY (cluster_id, node_id)
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                "ALTER TABLE keycloak_candidate_leases ADD COLUMN IF NOT EXISTS generation BIGINT NOT NULL DEFAULT 0",
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                "ALTER TABLE keycloak_candidate_leases ADD COLUMN IF NOT EXISTS eligible BOOLEAN NOT NULL DEFAULT TRUE",
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE INDEX IF NOT EXISTS keycloak_candidate_leases_expiry_idx
                ON keycloak_candidate_leases(cluster_id, lease_expires_at);
                "#,
            )
            .await
            .map_err(sql_error)?;
        transaction
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS client_gateway_selections (
                    client_id TEXT PRIMARY KEY NOT NULL,
                    gateway_node_id TEXT NOT NULL,
                    selected_at TIMESTAMPTZ NOT NULL
                );
                "#,
            )
            .await
            .map_err(sql_error)?;
        customer_resources::migrate_postgres_customer_resources(&mut transaction).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }
}

#[async_trait]
impl ControlPlaneStore for PostgresControlPlaneStore {
    async fn get_cluster_policy(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Option<ClusterPolicy>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM cluster_policies WHERE cluster_id = $1")
            .bind(cluster_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(pg_row_to_cluster_policy).transpose()
    }

    async fn initialize_cluster_policy_if_absent(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<ClusterPolicy, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, cluster_id).await?;
        let insert_result = sqlx::query(
            r#"
            INSERT INTO cluster_policies (cluster_id, record_json)
            VALUES ($1, $2)
            ON CONFLICT(cluster_id) DO NOTHING
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(serde_json::to_value(&policy).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        if insert_result.rows_affected() > 0 {
            bump_postgres_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        }
        let stored = postgres_cluster_policy(&mut transaction, cluster_id)
            .await?
            .ok_or_else(|| {
                ControlPlaneError::Store(format!(
                    "cluster policy initialization did not persist cluster {cluster_id}"
                ))
            })?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(stored)
    }

    async fn get_overlay_routing_epoch(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<u64, ControlPlaneError> {
        let epoch = sqlx::query_scalar::<_, i64>(
            "SELECT epoch FROM overlay_routing_epochs WHERE cluster_id = $1",
        )
        .bind(cluster_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?
        .unwrap_or(0);
        u64::try_from(epoch)
            .map_err(|_| ControlPlaneError::Store("overlay routing epoch is negative".to_string()))
    }

    async fn upsert_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, cluster_id).await?;
        if postgres_cluster_policy(&mut transaction, cluster_id)
            .await?
            .as_ref()
            == Some(&policy)
        {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(());
        }
        sqlx::query(
            r#"
            INSERT INTO cluster_policies (cluster_id, record_json)
            VALUES ($1, $2)
            ON CONFLICT(cluster_id) DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(serde_json::to_value(&policy).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        bump_postgres_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn upsert_cluster_policy_if_route_catalog_epoch(
        &self,
        cluster_id: &ClusterId,
        policy: ClusterPolicy,
        expected_route_catalog_epoch: u64,
    ) -> Result<bool, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, cluster_id).await?;
        let catalog = postgres_cluster_route_catalog(&mut transaction, cluster_id).await?;
        if overlay_route_catalog_epoch(&catalog)? != expected_route_catalog_epoch {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(false);
        }
        if postgres_cluster_policy(&mut transaction, cluster_id)
            .await?
            .as_ref()
            == Some(&policy)
        {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(true);
        }
        sqlx::query(
            r#"
            INSERT INTO cluster_policies (cluster_id, record_json)
            VALUES ($1, $2)
            ON CONFLICT(cluster_id) DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(serde_json::to_value(&policy).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        bump_postgres_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(true)
    }

    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        let node_id = node.node_id.clone();
        let vpn_ip = node.vpn_ip;
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, &node.cluster_id).await?;
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES ($1, $2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(|error| node_insert_error(error, &node_id, &vpn_ip))?;
        bump_postgres_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn insert_node_if_cluster_policy(
        &self,
        node: NodeRecord,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, &node.cluster_id).await?;
        if postgres_cluster_policy(&mut transaction, &node.cluster_id).await?
            != expected_cluster_policy
        {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = expected_route_catalog_epoch {
            let catalog =
                postgres_cluster_route_catalog(&mut transaction, &node.cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node_id = node.node_id.clone();
        let vpn_ip = node.vpn_ip;
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES ($1, $2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(|error| node_insert_error(error, &node_id, &vpn_ip))?;
        bump_postgres_overlay_routing_epoch(&mut transaction, &node.cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
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
        let cluster_id = postgres_node_cluster_id(&mut transaction, node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        lock_postgres_cluster(&mut transaction, &cluster_id).await?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let node = row
            .map(pg_row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        sqlx::query("DELETE FROM heartbeat_signatures WHERE node_id = $1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let health_result = sqlx::query("DELETE FROM health WHERE node_id = $1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        sqlx::query("DELETE FROM nat_classifications WHERE node_id = $1")
            .bind(node_id.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        sqlx::query(
            "DELETE FROM client_gateway_selections WHERE client_id = $1 OR gateway_node_id = $1",
        )
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
        bump_postgres_overlay_routing_epoch(&mut transaction, &cluster_id).await?;
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
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let cluster_id = postgres_node_cluster_id(&mut transaction, node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        lock_postgres_cluster(&mut transaction, &cluster_id).await?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(pg_row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.routes == routes {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(());
        }
        node.routes = routes;
        sqlx::query("UPDATE nodes SET record_json = $2 WHERE node_id = $1")
            .bind(node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        bump_postgres_overlay_routing_epoch(&mut transaction, &cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn update_node_routes_if_cluster_policy(
        &self,
        cluster_id: &ClusterId,
        node_id: &NodeId,
        routes: Vec<Route>,
        expected_cluster_policy: Option<ClusterPolicy>,
        expected_route_catalog_epoch: Option<u64>,
    ) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, cluster_id).await?;
        if postgres_cluster_policy(&mut transaction, cluster_id).await? != expected_cluster_policy {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = expected_route_catalog_epoch {
            let catalog = postgres_cluster_route_catalog(&mut transaction, cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(pg_row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == *cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.routes == routes {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(());
        }
        node.routes = routes;
        sqlx::query("UPDATE nodes SET record_json = $2 WHERE node_id = $1")
            .bind(node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        bump_postgres_overlay_routing_epoch(&mut transaction, cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(())
    }

    async fn rejoin_node_if_cluster_policy(
        &self,
        update: RejoinNodeStoreUpdate,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_cluster(&mut transaction, &update.cluster_id).await?;
        if postgres_cluster_policy(&mut transaction, &update.cluster_id).await?
            != update.expected_cluster_policy
        {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if let Some(expected) = update.expected_route_catalog_epoch {
            let catalog =
                postgres_cluster_route_catalog(&mut transaction, &update.cluster_id).await?;
            if overlay_route_catalog_epoch(&catalog)? != expected {
                return Err(ControlPlaneError::OverlayRouteCatalogChanged);
            }
        }
        let node_id = update.expected_node.node_id.clone();
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(pg_row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == update.cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node != update.expected_node {
            return Err(ControlPlaneError::NodeStateChanged(node_id));
        }
        let routes_changed = node.routes != update.routes;
        node.endpoint_candidates = update.candidates;
        node.relay_capability = update.relay_capability;
        node.routes = update.routes;
        sqlx::query("UPDATE nodes SET record_json = $2 WHERE node_id = $1")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        if routes_changed {
            bump_postgres_overlay_routing_epoch(&mut transaction, &update.cluster_id).await?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(node)
    }

    async fn rotate_node_wireguard_public_key(
        &self,
        node_id: &NodeId,
        expected_current_public_key: &str,
        next_public_key: String,
    ) -> Result<NodeRecord, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let cluster_id = postgres_node_cluster_id(&mut transaction, node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        lock_postgres_cluster(&mut transaction, &cluster_id).await?;
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(pg_row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(node_id.clone()))?;
        if node.wireguard_public_key != expected_current_public_key {
            return Err(ControlPlaneError::NodeUpdateRejected {
                node_id: node_id.clone(),
                reason: "wireguard public key changed before rotation completed".to_string(),
            });
        }
        if node.wireguard_public_key == next_public_key {
            transaction.commit().await.map_err(sql_error)?;
            return Ok(node);
        }
        node.wireguard_public_key = next_public_key;
        sqlx::query("UPDATE nodes SET record_json = $2 WHERE node_id = $1")
            .bind(node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        bump_postgres_overlay_routing_epoch(&mut transaction, &cluster_id).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(node)
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

    async fn get_heartbeat_signature_timestamp(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<chrono::DateTime<Utc>>, ControlPlaneError> {
        let row = sqlx::query(
            "SELECT accepted_signature_at FROM heartbeat_signatures WHERE node_id = $1",
        )
        .bind(node_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(sql_error)?;
        row.map(|row| parse_utc_timestamp(&row.get::<String, _>("accepted_signature_at")))
            .transpose()
    }

    async fn list_health(&self) -> Result<BTreeMap<NodeId, NodeHealth>, ControlPlaneError> {
        let rows = sqlx::query("SELECT node_id, record_json FROM health ORDER BY node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?;
        let mut health_by_node = BTreeMap::new();
        for row in rows {
            let node_id = NodeId::from_string(row.get::<String, _>("node_id"));
            health_by_node.insert(node_id, pg_row_to_health(row)?);
        }
        Ok(health_by_node)
    }

    async fn list_nodes_and_health(
        &self,
    ) -> Result<(Vec<NodeRecord>, BTreeMap<NodeId, NodeHealth>), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let node_rows = sqlx::query("SELECT record_json FROM nodes ORDER BY node_id")
            .fetch_all(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let health_rows = sqlx::query("SELECT node_id, record_json FROM health ORDER BY node_id")
            .fetch_all(&mut *transaction)
            .await
            .map_err(sql_error)?;

        let nodes = node_rows
            .into_iter()
            .map(pg_row_to_node)
            .collect::<Result<Vec<_>, _>>()?;
        let mut health_by_node = BTreeMap::new();
        for row in health_rows {
            let node_id = NodeId::from_string(row.get::<String, _>("node_id"));
            health_by_node.insert(node_id, pg_row_to_health(row)?);
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok((nodes, health_by_node))
    }

    async fn upsert_nat_classification(
        &self,
        node_id: NodeId,
        classification: NatClassification,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO nat_classifications (node_id, record_json)
            VALUES ($1, $2)
            ON CONFLICT(node_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(node_id.as_str())
        .bind(serde_json::to_value(&classification).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn get_nat_classification(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<NatClassification>, ControlPlaneError> {
        let row = sqlx::query("SELECT record_json FROM nat_classifications WHERE node_id = $1")
            .bind(node_id.as_str())
            .fetch_optional(&self.pool)
            .await
            .map_err(sql_error)?;
        row.map(pg_row_to_nat_classification).transpose()
    }

    async fn list_nat_classifications(
        &self,
    ) -> Result<BTreeMap<NodeId, NatClassification>, ControlPlaneError> {
        let rows =
            sqlx::query("SELECT node_id, record_json FROM nat_classifications ORDER BY node_id")
                .fetch_all(&self.pool)
                .await
                .map_err(sql_error)?;
        let mut classifications = BTreeMap::new();
        for row in rows {
            let node_id = NodeId::from_string(row.get::<String, _>("node_id"));
            classifications.insert(node_id, pg_row_to_nat_classification(row)?);
        }
        Ok(classifications)
    }

    async fn apply_heartbeat(&self, update: HeartbeatStoreUpdate) -> Result<(), ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        let updates_routes = update.routes.is_some();
        if updates_routes {
            lock_postgres_cluster(&mut transaction, &update.cluster_id).await?;
        } else {
            lock_postgres_cluster_shared(&mut transaction, &update.cluster_id).await?;
        }
        if postgres_cluster_policy(&mut transaction, &update.cluster_id)
            .await?
            .as_ref()
            != update.expected_cluster_policy.as_ref()
        {
            return Err(ControlPlaneError::ClusterPolicyChanged);
        }
        if updates_routes {
            if let Some(expected) = update.expected_route_catalog_epoch {
                let catalog =
                    postgres_cluster_route_catalog(&mut transaction, &update.cluster_id).await?;
                if overlay_route_catalog_epoch(&catalog)? != expected {
                    return Err(ControlPlaneError::OverlayRouteCatalogChanged);
                }
            }
        }
        let row = sqlx::query("SELECT record_json FROM nodes WHERE node_id = $1 FOR UPDATE")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?;
        let mut node = row
            .map(pg_row_to_node)
            .transpose()?
            .filter(|node| node.cluster_id == update.cluster_id)
            .ok_or_else(|| ControlPlaneError::NodeNotFound(update.node_id.clone()))?;
        update.ensure_matches_node_generation(&node)?;
        let routes_changed = update
            .routes
            .as_ref()
            .is_some_and(|routes| node.routes != *routes);
        let previous_signature_at = sqlx::query(
            "SELECT accepted_signature_at FROM heartbeat_signatures WHERE node_id = $1",
        )
        .bind(update.node_id.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(|row| parse_utc_timestamp(&row.get::<String, _>("accepted_signature_at")))
        .transpose()?;
        let previous_health = sqlx::query("SELECT record_json FROM health WHERE node_id = $1")
            .bind(update.node_id.as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(sql_error)?
            .map(pg_row_to_health)
            .transpose()?;
        ensure_heartbeat_is_newer(&update, previous_signature_at, previous_health.as_ref())?;

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
        if let Some(accepted_signature_at) = update.accepted_signature_at {
            sqlx::query(
                r#"
                INSERT INTO heartbeat_signatures (node_id, accepted_signature_at)
                VALUES ($1, $2)
                ON CONFLICT(node_id)
                DO UPDATE SET accepted_signature_at = excluded.accepted_signature_at
                "#,
            )
            .bind(update.node_id.as_str())
            .bind(accepted_signature_at.to_rfc3339())
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
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
        if let Some(classification) = update.nat_classification {
            sqlx::query(
                r#"
                INSERT INTO nat_classifications (node_id, record_json)
                VALUES ($1, $2)
                ON CONFLICT(node_id)
                DO UPDATE SET record_json = excluded.record_json
                "#,
            )
            .bind(update.node_id.as_str())
            .bind(serde_json::to_value(&classification).map_err(json_error)?)
            .execute(&mut *transaction)
            .await
            .map_err(sql_error)?;
        }
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
        if routes_changed {
            bump_postgres_overlay_routing_epoch(&mut transaction, &update.cluster_id).await?;
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

    async fn list_all_paths(&self) -> Result<Vec<PathRecord>, ControlPlaneError> {
        sqlx::query("SELECT record_json FROM paths ORDER BY local_node_id, remote_node_id")
            .fetch_all(&self.pool)
            .await
            .map_err(sql_error)?
            .into_iter()
            .map(pg_row_to_path)
            .collect()
    }

    async fn list_paths_for_pairs(
        &self,
        pairs: &BTreeSet<(NodeId, NodeId)>,
    ) -> Result<Vec<PathRecord>, ControlPlaneError> {
        let pairs = pairs.iter().collect::<Vec<_>>();
        let mut paths = Vec::new();
        for chunk in pairs.chunks(PATH_PAIR_QUERY_CHUNK_SIZE) {
            let mut query = QueryBuilder::<Postgres>::new("SELECT record_json FROM paths WHERE ");
            {
                let mut conditions = query.separated(" OR ");
                for (local, remote) in chunk {
                    conditions
                        .push("(local_node_id = ")
                        .push_bind_unseparated(local.as_str())
                        .push_unseparated(" AND remote_node_id = ")
                        .push_bind_unseparated(remote.as_str())
                        .push_unseparated(")");
                }
            }
            query.push(" ORDER BY local_node_id, remote_node_id");
            paths.extend(
                query
                    .build()
                    .fetch_all(&self.pool)
                    .await
                    .map_err(sql_error)?
                    .into_iter()
                    .map(pg_row_to_path)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        paths.sort_by(|left, right| {
            left.key
                .local
                .cmp(&right.key.local)
                .then_with(|| left.key.remote.cmp(&right.key.remote))
        });
        Ok(paths)
    }

    async fn upsert_service_instance(
        &self,
        instance: ServiceInstance,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO service_instances (cluster_id, instance_id, record_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(cluster_id, instance_id)
            DO UPDATE SET record_json = excluded.record_json
            "#,
        )
        .bind(instance.cluster_id.as_str())
        .bind(instance.instance_id.as_str())
        .bind(serde_json::to_value(&instance).map_err(json_error)?)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn remove_service_instance(
        &self,
        cluster_id: &ClusterId,
        instance_id: &str,
    ) -> Result<bool, ControlPlaneError> {
        let result =
            sqlx::query("DELETE FROM service_instances WHERE cluster_id = $1 AND instance_id = $2")
                .bind(cluster_id.as_str())
                .bind(instance_id)
                .execute(&self.pool)
                .await
                .map_err(sql_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_service_instances(
        &self,
        cluster_id: &ClusterId,
    ) -> Result<Vec<ServiceInstance>, ControlPlaneError> {
        sqlx::query(
            "SELECT record_json FROM service_instances WHERE cluster_id = $1 ORDER BY instance_id",
        )
        .bind(cluster_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        .into_iter()
        .map(pg_row_to_service_instance)
        .collect()
    }

    async fn upsert_keycloak_candidate(
        &self,
        candidate: KeycloakCandidateLease,
    ) -> Result<bool, ControlPlaneError> {
        let lease_expires_at = keycloak_candidate_expiry_nanos(&candidate.lease_expires_at)?;
        let updated_at = keycloak_candidate_expiry_nanos(&candidate.updated_at)?;
        let record_json = serde_json::to_value(&candidate).map_err(json_error)?;
        let result = sqlx::query(
            r#"
            INSERT INTO keycloak_candidate_leases
                (cluster_id, node_id, lease_expires_at, generation, eligible, record_json)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT(cluster_id, node_id) DO UPDATE SET
                lease_expires_at = excluded.lease_expires_at,
                generation = excluded.generation,
                eligible = excluded.eligible,
                record_json = excluded.record_json
            WHERE keycloak_candidate_leases.lease_expires_at <= $7
               OR keycloak_candidate_leases.generation < excluded.generation
            "#,
        )
        .bind(candidate.cluster_id.as_str())
        .bind(candidate.node_id.as_str())
        .bind(lease_expires_at)
        .bind(candidate.generation)
        .bind(candidate.eligible)
        .bind(record_json)
        .bind(updated_at)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_keycloak_candidates(
        &self,
        cluster_id: &ClusterId,
        lease_cutoff: DateTime<Utc>,
        after_node_id: Option<&NodeId>,
        limit: usize,
    ) -> Result<Vec<KeycloakCandidateLease>, ControlPlaneError> {
        let lease_cutoff = keycloak_candidate_expiry_nanos(&lease_cutoff)?;
        let limit = keycloak_candidate_query_limit(limit)?;
        sqlx::query(
            r#"
            SELECT cluster_id, node_id, lease_expires_at, generation, eligible, record_json
            FROM keycloak_candidate_leases
            WHERE cluster_id = $1
              AND lease_expires_at > $2
              AND eligible
              AND ($3::TEXT IS NULL OR node_id > $3)
            ORDER BY node_id
            LIMIT $4
            "#,
        )
        .bind(cluster_id.as_str())
        .bind(lease_cutoff)
        .bind(after_node_id.map(NodeId::as_str))
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        .into_iter()
        .map(pg_row_to_keycloak_candidate)
        .collect()
    }

    async fn upsert_client_gateway_selection(
        &self,
        selection: ClientGatewaySelection,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query(
            r#"
            INSERT INTO client_gateway_selections (client_id, gateway_node_id, selected_at)
            VALUES ($1, $2, $3)
            ON CONFLICT(client_id) DO UPDATE SET
                gateway_node_id = excluded.gateway_node_id,
                selected_at = excluded.selected_at
            "#,
        )
        .bind(selection.client_id.as_str())
        .bind(selection.gateway_node_id.as_str())
        .bind(selection.selected_at)
        .execute(&self.pool)
        .await
        .map_err(sql_error)?;
        Ok(())
    }

    async fn remove_client_gateway_selection(
        &self,
        client_id: &NodeId,
    ) -> Result<bool, ControlPlaneError> {
        let result = sqlx::query("DELETE FROM client_gateway_selections WHERE client_id = $1")
            .bind(client_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_client_gateway_selections(
        &self,
    ) -> Result<BTreeMap<NodeId, ClientGatewaySelection>, ControlPlaneError> {
        let mut selections = BTreeMap::new();
        for row in sqlx::query(
            "SELECT client_id, gateway_node_id, selected_at FROM client_gateway_selections ORDER BY client_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(sql_error)?
        {
            let selection = pg_row_to_client_gateway_selection(row);
            selections.insert(selection.client_id.clone(), selection);
        }
        Ok(selections)
    }

    async fn latest_client_gateway_selection_at(
        &self,
    ) -> Result<Option<DateTime<Utc>>, ControlPlaneError> {
        let row =
            sqlx::query("SELECT MAX(selected_at) AS selected_at FROM client_gateway_selections")
                .fetch_one(&self.pool)
                .await
                .map_err(sql_error)?;
        Ok(row.get("selected_at"))
    }
}

#[async_trait]
impl TokenLedger for PostgresControlPlaneStore {
    async fn insert_token_if_absent(
        &self,
        record: TokenLedgerRecord,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_token(&mut transaction, &record.cluster_id, &record.nonce).await?;
        sqlx::query(
            r#"
            INSERT INTO tokens (cluster_id, nonce, record_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(cluster_id, nonce) DO NOTHING
            "#,
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_value(&record).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let row = sqlx::query(
            "SELECT record_json FROM tokens WHERE cluster_id = $1 AND nonce = $2 FOR UPDATE",
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let mut stored = row
            .map(pg_row_to_token)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(record.nonce.clone()))?;
        ensure_token_definition_matches(&stored, &record)?;
        let revocation = sqlx::query(
            "SELECT record_json FROM token_revocations WHERE cluster_id = $1 AND nonce = $2",
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(pg_row_to_revocation)
        .transpose()?;
        if let Some(revocation) = revocation {
            stored.revoked_at = Some(revocation.revoked_at);
            update_postgres_token(&mut transaction, &stored).await?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(stored)
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

    async fn admit_token(
        &self,
        record: TokenLedgerRecord,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TokenLedgerRecord, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_token(&mut transaction, &record.cluster_id, &record.nonce).await?;
        sqlx::query(
            r#"
            INSERT INTO tokens (cluster_id, nonce, record_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(cluster_id, nonce) DO NOTHING
            "#,
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_value(&record).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let row = sqlx::query(
            "SELECT record_json FROM tokens WHERE cluster_id = $1 AND nonce = $2 FOR UPDATE",
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let mut stored = row
            .map(pg_row_to_token)
            .transpose()?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(record.nonce.clone()))?;
        ensure_token_definition_matches(&stored, &record)?;
        let revocation = sqlx::query(
            "SELECT record_json FROM token_revocations WHERE cluster_id = $1 AND nonce = $2",
        )
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(pg_row_to_revocation)
        .transpose()?;
        if let Some(revocation) = revocation {
            stored.revoked_at = Some(revocation.revoked_at);
        }
        let status = stored.status(now);
        if status != TokenStatus::Active {
            update_postgres_token(&mut transaction, &stored).await?;
            transaction.commit().await.map_err(sql_error)?;
            return Err(ControlPlaneError::TokenRejected {
                nonce: record.nonce,
                status,
            });
        }
        stored.uses = stored.uses.saturating_add(1);
        update_postgres_token(&mut transaction, &stored).await?;
        transaction.commit().await.map_err(sql_error)?;
        Ok(stored)
    }

    async fn revoke_token(
        &self,
        revocation: TokenRevocationRecord,
    ) -> Result<TokenRevocationOutcome, ControlPlaneError> {
        let mut transaction = self.pool.begin().await.map_err(sql_error)?;
        lock_postgres_token(&mut transaction, &revocation.cluster_id, &revocation.nonce).await?;
        sqlx::query(
            r#"
            INSERT INTO token_revocations (cluster_id, nonce, record_json)
            VALUES ($1, $2, $3)
            ON CONFLICT(cluster_id, nonce) DO NOTHING
            "#,
        )
        .bind(revocation.cluster_id.as_str())
        .bind(revocation.nonce.as_str())
        .bind(serde_json::to_value(&revocation).map_err(json_error)?)
        .execute(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let stored_revocation = sqlx::query(
            "SELECT record_json FROM token_revocations WHERE cluster_id = $1 AND nonce = $2",
        )
        .bind(revocation.cluster_id.as_str())
        .bind(revocation.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?
        .map(pg_row_to_revocation)
        .transpose()?
        .ok_or_else(|| ControlPlaneError::TokenNotFound(revocation.nonce.clone()))?;
        let row = sqlx::query(
            "SELECT record_json FROM tokens WHERE cluster_id = $1 AND nonce = $2 FOR UPDATE",
        )
        .bind(revocation.cluster_id.as_str())
        .bind(revocation.nonce.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(sql_error)?;
        let record = row.map(pg_row_to_token).transpose()?.map(|mut record| {
            record.revoked_at = Some(stored_revocation.revoked_at);
            record
        });
        if let Some(record) = &record {
            update_postgres_token(&mut transaction, record).await?;
        }
        transaction.commit().await.map_err(sql_error)?;
        Ok(TokenRevocationOutcome {
            revocation: stored_revocation,
            record,
        })
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
        let revocations =
            sqlx::query("SELECT record_json FROM token_revocations WHERE cluster_id = $1")
                .bind(cluster_id.as_str())
                .fetch_all(&self.pool)
                .await
                .map_err(sql_error)?;
        let mut metrics = TokenLedgerMetrics::default();
        let mut token_nonces = BTreeSet::new();
        for record in records.into_iter().map(pg_row_to_token) {
            let record = record?;
            token_nonces.insert(record.nonce.clone());
            metrics.observe_record(&record, now);
        }
        for revocation in revocations.into_iter().map(pg_row_to_revocation) {
            let revocation = revocation?;
            if !token_nonces.contains(&revocation.nonce) {
                metrics.observe_revocation_tombstone();
            }
        }
        Ok(metrics)
    }
}

async fn sqlite_cluster_policy(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    cluster_id: &ClusterId,
) -> Result<Option<ClusterPolicy>, ControlPlaneError> {
    sqlx::query("SELECT record_json FROM cluster_policies WHERE cluster_id = ?1")
        .bind(cluster_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(sql_error)?
        .map(row_to_cluster_policy)
        .transpose()
}

async fn bump_sqlite_overlay_routing_epoch(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    cluster_id: &ClusterId,
) -> Result<(), ControlPlaneError> {
    let result = sqlx::query(
        r#"
        INSERT INTO overlay_routing_epochs (cluster_id, epoch)
        VALUES (?1, 1)
        ON CONFLICT(cluster_id) DO UPDATE
        SET epoch = overlay_routing_epochs.epoch + 1
        WHERE overlay_routing_epochs.epoch < 9223372036854775807
        "#,
    )
    .bind(cluster_id.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(sql_error)?;
    if result.rows_affected() != 1 {
        return Err(ControlPlaneError::Store(format!(
            "overlay routing epoch exhausted for cluster {cluster_id}"
        )));
    }
    Ok(())
}

async fn sqlite_cluster_route_catalog(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    cluster_id: &ClusterId,
) -> Result<Vec<NodeRecord>, ControlPlaneError> {
    Ok(sqlx::query(
        r#"
        SELECT record_json
        FROM nodes
        WHERE json_extract(record_json, '$.cluster_id') = ?1
        ORDER BY node_id
        "#,
    )
    .bind(cluster_id.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(sql_error)?
    .into_iter()
    .map(row_to_node)
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .filter(|node| !node.role.is_client())
    .collect())
}

async fn lock_postgres_cluster(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
) -> Result<(), ControlPlaneError> {
    let lock_key = postgres_cluster_lock_key(cluster_id);
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(sql_error)?;
    Ok(())
}

async fn lock_postgres_cluster_shared(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
) -> Result<(), ControlPlaneError> {
    let lock_key = postgres_cluster_lock_key(cluster_id);
    sqlx::query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(sql_error)?;
    Ok(())
}

fn postgres_cluster_lock_key(cluster_id: &ClusterId) -> String {
    format!(
        "ipars-control-plane:{}:{}",
        cluster_id.as_str().len(),
        cluster_id.as_str()
    )
}

async fn postgres_node_cluster_id(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    node_id: &NodeId,
) -> Result<Option<ClusterId>, ControlPlaneError> {
    Ok(
        sqlx::query(
            "SELECT record_json->>'cluster_id' AS cluster_id FROM nodes WHERE node_id = $1",
        )
        .bind(node_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(sql_error)?
        .map(|row| ClusterId::from_string(row.get::<String, _>("cluster_id"))),
    )
}

async fn postgres_cluster_policy(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
) -> Result<Option<ClusterPolicy>, ControlPlaneError> {
    sqlx::query("SELECT record_json FROM cluster_policies WHERE cluster_id = $1")
        .bind(cluster_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(sql_error)?
        .map(pg_row_to_cluster_policy)
        .transpose()
}

async fn bump_postgres_overlay_routing_epoch(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
) -> Result<(), ControlPlaneError> {
    let result = sqlx::query(
        r#"
        INSERT INTO overlay_routing_epochs (cluster_id, epoch)
        VALUES ($1, 1)
        ON CONFLICT(cluster_id) DO UPDATE
        SET epoch = overlay_routing_epochs.epoch + 1
        WHERE overlay_routing_epochs.epoch < 9223372036854775807
        "#,
    )
    .bind(cluster_id.as_str())
    .execute(&mut **transaction)
    .await
    .map_err(sql_error)?;
    if result.rows_affected() != 1 {
        return Err(ControlPlaneError::Store(format!(
            "overlay routing epoch exhausted for cluster {cluster_id}"
        )));
    }
    Ok(())
}

async fn postgres_cluster_route_catalog(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    cluster_id: &ClusterId,
) -> Result<Vec<NodeRecord>, ControlPlaneError> {
    Ok(sqlx::query(
        r#"
        SELECT record_json
        FROM nodes
        WHERE record_json->>'cluster_id' = $1
        ORDER BY node_id
        "#,
    )
    .bind(cluster_id.as_str())
    .fetch_all(&mut **transaction)
    .await
    .map_err(sql_error)?
    .into_iter()
    .map(pg_row_to_node)
    .collect::<Result<Vec<_>, _>>()?
    .into_iter()
    .filter(|node| !node.role.is_client())
    .collect())
}

fn row_to_cluster_policy(row: sqlx::sqlite::SqliteRow) -> Result<ClusterPolicy, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
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

fn row_to_nat_classification(
    row: sqlx::sqlite::SqliteRow,
) -> Result<NatClassification, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_token(row: sqlx::sqlite::SqliteRow) -> Result<TokenLedgerRecord, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_revocation(
    row: sqlx::sqlite::SqliteRow,
) -> Result<TokenRevocationRecord, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_service_instance(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ServiceInstance, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_keycloak_candidate(
    row: sqlx::sqlite::SqliteRow,
) -> Result<KeycloakCandidateLease, ControlPlaneError> {
    let cluster_id: String = row.get("cluster_id");
    let node_id: String = row.get("node_id");
    let lease_expires_at: i64 = row.get("lease_expires_at");
    let generation: i64 = row.get("generation");
    let eligible: bool = row.get("eligible");
    let record_json: String = row.get("record_json");
    let candidate = serde_json::from_str(&record_json).map_err(json_error)?;
    validate_keycloak_candidate_row(
        candidate,
        &cluster_id,
        &node_id,
        lease_expires_at,
        generation,
        eligible,
    )
}

fn row_to_client_gateway_selection(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ClientGatewaySelection, ControlPlaneError> {
    Ok(ClientGatewaySelection {
        client_id: NodeId::from_string(row.get::<String, _>("client_id")),
        gateway_node_id: NodeId::from_string(row.get::<String, _>("gateway_node_id")),
        selected_at: sqlite_selection_timestamp(row.get("selected_at_millis"))?,
    })
}

fn sqlite_selection_timestamp(millis: i64) -> Result<DateTime<Utc>, ControlPlaneError> {
    DateTime::from_timestamp_millis(millis).ok_or_else(|| {
        ControlPlaneError::Store("stored client gateway selection timestamp is invalid".to_string())
    })
}

fn pg_row_to_cluster_policy(
    row: sqlx::postgres::PgRow,
) -> Result<ClusterPolicy, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
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

fn pg_row_to_nat_classification(
    row: sqlx::postgres::PgRow,
) -> Result<NatClassification, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_token(row: sqlx::postgres::PgRow) -> Result<TokenLedgerRecord, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_revocation(
    row: sqlx::postgres::PgRow,
) -> Result<TokenRevocationRecord, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_service_instance(
    row: sqlx::postgres::PgRow,
) -> Result<ServiceInstance, ControlPlaneError> {
    let record_json: serde_json::Value = row.get("record_json");
    serde_json::from_value(record_json).map_err(json_error)
}

fn pg_row_to_keycloak_candidate(
    row: sqlx::postgres::PgRow,
) -> Result<KeycloakCandidateLease, ControlPlaneError> {
    let cluster_id: String = row.get("cluster_id");
    let node_id: String = row.get("node_id");
    let lease_expires_at: i64 = row.get("lease_expires_at");
    let generation: i64 = row.get("generation");
    let eligible: bool = row.get("eligible");
    let record_json: serde_json::Value = row.get("record_json");
    let candidate = serde_json::from_value(record_json).map_err(json_error)?;
    validate_keycloak_candidate_row(
        candidate,
        &cluster_id,
        &node_id,
        lease_expires_at,
        generation,
        eligible,
    )
}

fn pg_row_to_client_gateway_selection(row: sqlx::postgres::PgRow) -> ClientGatewaySelection {
    ClientGatewaySelection {
        client_id: NodeId::from_string(row.get::<String, _>("client_id")),
        gateway_node_id: NodeId::from_string(row.get::<String, _>("gateway_node_id")),
        selected_at: row.get("selected_at"),
    }
}

async fn update_sqlite_token(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &TokenLedgerRecord,
) -> Result<(), ControlPlaneError> {
    sqlx::query("UPDATE tokens SET record_json = ?3 WHERE cluster_id = ?1 AND nonce = ?2")
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_string(record).map_err(json_error)?)
        .execute(&mut **transaction)
        .await
        .map_err(sql_error)?;
    Ok(())
}

async fn lock_postgres_token(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    cluster_id: &ClusterId,
    nonce: &str,
) -> Result<(), ControlPlaneError> {
    let lock_key = format!(
        "{}:{}{}",
        cluster_id.as_str().len(),
        cluster_id.as_str(),
        nonce
    );
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(sql_error)?;
    Ok(())
}

async fn update_postgres_token(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    record: &TokenLedgerRecord,
) -> Result<(), ControlPlaneError> {
    sqlx::query("UPDATE tokens SET record_json = $3 WHERE cluster_id = $1 AND nonce = $2")
        .bind(record.cluster_id.as_str())
        .bind(record.nonce.as_str())
        .bind(serde_json::to_value(record).map_err(json_error)?)
        .execute(&mut **transaction)
        .await
        .map_err(sql_error)?;
    Ok(())
}

fn ensure_heartbeat_is_newer(
    update: &HeartbeatStoreUpdate,
    previous_signature_at: Option<DateTime<Utc>>,
    previous_health: Option<&NodeHealth>,
) -> Result<(), ControlPlaneError> {
    if let Some(accepted_signature_at) = update.accepted_signature_at {
        if let Some(previous_signature_at) = previous_signature_at {
            if accepted_signature_at <= previous_signature_at {
                return Err(ControlPlaneError::NodeSignatureRejected {
                    node_id: update.node_id.clone(),
                    reason: format!(
                        "signed_at {accepted_signature_at} is not newer than last accepted heartbeat {previous_signature_at}"
                    ),
                });
            }
        }
    } else if let Some(previous_health) = previous_health {
        if update.health.last_seen_at <= previous_health.last_seen_at {
            return Err(ControlPlaneError::NodeSignatureRejected {
                node_id: update.node_id.clone(),
                reason: "unsigned heartbeat was received before the current health snapshot"
                    .to_string(),
            });
        }
    }
    Ok(())
}

fn parse_utc_timestamp(value: &str) -> Result<DateTime<Utc>, ControlPlaneError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| ControlPlaneError::Store(error.to_string()))
}

fn keycloak_candidate_expiry_nanos(timestamp: &DateTime<Utc>) -> Result<i64, ControlPlaneError> {
    timestamp.timestamp_nanos_opt().ok_or_else(|| {
        ControlPlaneError::Store(
            "Keycloak candidate lease expiration is outside the supported timestamp range"
                .to_string(),
        )
    })
}

fn keycloak_candidate_query_limit(limit: usize) -> Result<i64, ControlPlaneError> {
    if !(1..=MAX_KEYCLOAK_CANDIDATE_QUERY_LIMIT).contains(&limit) {
        return Err(ControlPlaneError::Store(format!(
            "Keycloak candidate query limit must be between 1 and {MAX_KEYCLOAK_CANDIDATE_QUERY_LIMIT}"
        )));
    }
    Ok(limit as i64)
}

fn validate_keycloak_candidate_row(
    candidate: KeycloakCandidateLease,
    cluster_id: &str,
    node_id: &str,
    lease_expires_at: i64,
    generation: i64,
    eligible: bool,
) -> Result<KeycloakCandidateLease, ControlPlaneError> {
    if candidate.cluster_id.as_str() != cluster_id {
        return Err(ControlPlaneError::Store(
            "stored Keycloak candidate cluster ID does not match its record".to_string(),
        ));
    }
    if candidate.node_id.as_str() != node_id {
        return Err(ControlPlaneError::Store(
            "stored Keycloak candidate node ID does not match its record".to_string(),
        ));
    }
    if keycloak_candidate_expiry_nanos(&candidate.lease_expires_at)? != lease_expires_at {
        return Err(ControlPlaneError::Store(
            "stored Keycloak candidate lease expiration does not match its record".to_string(),
        ));
    }
    if candidate.generation != generation {
        return Err(ControlPlaneError::Store(
            "stored Keycloak candidate generation does not match its record".to_string(),
        ));
    }
    if candidate.eligible != eligible {
        return Err(ControlPlaneError::Store(
            "stored Keycloak candidate eligibility does not match its record".to_string(),
        ));
    }
    Ok(candidate)
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

    use chrono::{Duration, Utc};
    use ipars_control_plane::{ControlPlaneStore, TokenAdmission};
    use ipars_types::{
        BootstrapEndpoint, BootstrapEndpointKind, CandidateSource, ClusterId, EndpointCandidate,
        EndpointCandidateKind, HealthState, JoinTokenClaims, KeyId, NatClassification,
        NatProbeObservation, NodeHealth, NodeRecord, PathMetrics, PathRecord, PathScore, PathState,
        PeerPathKey, RelayCapability, Role, ServiceInstance, Tag, TokenPolicy, VpnIp,
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

    fn keycloak_candidate(
        cluster_id: &ClusterId,
        node_id: &str,
        host_octet: u8,
        ready: bool,
        lease_expires_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> KeycloakCandidateLease {
        KeycloakCandidateLease {
            cluster_id: cluster_id.clone(),
            node_id: NodeId::from_string(node_id),
            vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, host_octet))),
            version: "26.6.4".to_string(),
            ready,
            eligible: true,
            generation: 1,
            lease_expires_at,
            updated_at,
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
            cluster_id: local.cluster_id.clone(),
            expected_cluster_policy: None,
            expected_route_catalog_epoch: None,
            node_id: local.node_id.clone(),
            expected_identity_public_key: local.identity_public_key.clone(),
            expected_registered_at: local.registered_at,
            accepted_signature_at: Some(accepted_at),
            candidates: vec![candidate],
            nat_classification: None,
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
        assert_eq!(store.list_all_paths().await?.len(), 2);
        let requested_pairs = BTreeSet::from([(local.node_id.clone(), remote.node_id.clone())]);
        let requested_paths = store.list_paths_for_pairs(&requested_pairs).await?;
        assert_eq!(requested_paths.len(), 1);
        assert_eq!(requested_paths[0].key.local, local.node_id);
        assert_eq!(
            store.list_paths_for_pairs(&BTreeSet::new()).await?,
            Vec::new()
        );
        store.replace_node_paths(&local.node_id, Vec::new()).await?;
        let remaining_paths = store.list_paths_for(&local.node_id).await?;
        assert_eq!(remaining_paths.len(), 1);
        assert_eq!(remaining_paths[0].key.local, remote.node_id);
        assert_eq!(store.list_all_paths().await?, remaining_paths);
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
        assert_eq!(
            store.get_health(&local.node_id).await?,
            Some(health.clone())
        );
        assert_eq!(
            store.list_health().await?,
            BTreeMap::from([(local.node_id.clone(), health)])
        );
        let assessed_at = Utc::now();
        let nat_classification = NatClassification::from_observations(
            SocketAddr::from(([10, 0, 0, 10], 51820)),
            vec![NatProbeObservation {
                local_addr: SocketAddr::from(([10, 0, 0, 10], 51820)),
                stun_server: SocketAddr::from(([198, 51, 100, 1], 3478)),
                reflexive_addr: SocketAddr::from(([203, 0, 113, 10], 40000)),
                observed_at: assessed_at,
            }],
            assessed_at,
        );
        store
            .upsert_nat_classification(local.node_id.clone(), nat_classification.clone())
            .await?;
        assert_eq!(
            store.get_nat_classification(&local.node_id).await?,
            Some(nat_classification.clone())
        );
        assert_eq!(store.list_nat_classifications().await?.len(), 1);

        let selection_time =
            DateTime::parse_from_rfc3339("2026-07-22T12:00:00Z")?.with_timezone(&Utc);
        let selection = ClientGatewaySelection {
            client_id: local.node_id.clone(),
            gateway_node_id: remote.node_id.clone(),
            selected_at: selection_time,
        };
        store
            .upsert_client_gateway_selection(selection.clone())
            .await?;
        assert_eq!(
            store
                .list_client_gateway_selections()
                .await?
                .get(&local.node_id),
            Some(&selection)
        );
        assert_eq!(
            store.latest_client_gateway_selection_at().await?,
            Some(selection_time)
        );

        let removed = store.remove_node(&local.node_id).await?;
        assert_eq!(removed.node.node_id, local.node_id);
        assert_eq!(removed.removed_path_count, 1);
        assert!(removed.removed_health);
        assert_eq!(store.get_node(&local.node_id).await?, None);
        assert_eq!(store.get_health(&local.node_id).await?, None);
        assert_eq!(store.get_nat_classification(&local.node_id).await?, None);
        assert!(store.list_client_gateway_selections().await?.is_empty());
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
    async fn sqlite_list_nodes_and_health_preserves_cluster_independent_results(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let cluster_a_node = node("node-a", Ipv4Addr::new(100, 64, 0, 1));
        let mut cluster_b_node = node("node-b", Ipv4Addr::new(100, 64, 0, 2));
        cluster_b_node.cluster_id = ClusterId::from_string("cluster-b");
        store.insert_node(cluster_a_node.clone()).await?;
        store.insert_node(cluster_b_node.clone()).await?;

        let observed_at = Utc::now();
        let cluster_a_health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: observed_at,
            latency_ms: Some(11.0),
            relay_load: None,
            message: Some("cluster-a".to_string()),
        };
        let cluster_b_health = NodeHealth {
            state: HealthState::Degraded,
            last_seen_at: observed_at,
            latency_ms: Some(22.0),
            relay_load: None,
            message: Some("cluster-b".to_string()),
        };
        let orphan_node_id = NodeId::from_string("orphan-node");
        let orphan_health = NodeHealth {
            state: HealthState::Unhealthy,
            last_seen_at: observed_at,
            latency_ms: None,
            relay_load: None,
            message: Some("orphan".to_string()),
        };
        store
            .upsert_health(cluster_a_node.node_id.clone(), cluster_a_health.clone())
            .await?;
        store
            .upsert_health(cluster_b_node.node_id.clone(), cluster_b_health.clone())
            .await?;
        store
            .upsert_health(orphan_node_id.clone(), orphan_health.clone())
            .await?;

        let (nodes, health_by_node) = store.list_nodes_and_health().await?;

        assert_eq!(nodes, vec![cluster_a_node.clone(), cluster_b_node.clone()]);
        assert_eq!(
            health_by_node,
            BTreeMap::from([
                (cluster_a_node.node_id, cluster_a_health),
                (cluster_b_node.node_id, cluster_b_health),
                (orphan_node_id, orphan_health),
            ])
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_cluster_policy_is_shared_across_store_instances(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("cluster-policy");
        let cluster_id = ClusterId::from_string("cluster-ha");
        let store_a = SqliteControlPlaneStore::connect(&database_url).await?;
        let store_b = SqliteControlPlaneStore::connect(&database_url).await?;
        assert_eq!(store_a.get_cluster_policy(&cluster_id).await?, None);

        let policy = ClusterPolicy {
            overlay_block_size: 12,
            overlay_max_degree: 6,
            ..ClusterPolicy::default()
        };
        store_a
            .upsert_cluster_policy(&cluster_id, policy.clone())
            .await?;
        assert_eq!(
            store_b.get_cluster_policy(&cluster_id).await?,
            Some(policy.clone())
        );

        let reopened = SqliteControlPlaneStore::connect(&database_url).await?;
        assert_eq!(
            reopened.get_cluster_policy(&cluster_id).await?,
            Some(policy)
        );
        assert_eq!(
            reopened
                .get_cluster_policy(&ClusterId::from_string("other-cluster"))
                .await?,
            None
        );

        drop(store_a);
        drop(store_b);
        drop(reopened);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_cluster_policy_initialization_is_first_writer_wins(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("cluster-policy-init");
        let cluster_id = ClusterId::from_string("cluster-ha-init");
        let store_a = SqliteControlPlaneStore::connect(&database_url).await?;
        let store_b = SqliteControlPlaneStore::connect(&database_url).await?;
        let policy_a = ClusterPolicy {
            overlay_block_size: 8,
            ..ClusterPolicy::default()
        };
        let policy_b = ClusterPolicy {
            overlay_block_size: 12,
            ..ClusterPolicy::default()
        };

        let (result_a, result_b) = tokio::join!(
            store_a.initialize_cluster_policy_if_absent(&cluster_id, policy_a),
            store_b.initialize_cluster_policy_if_absent(&cluster_id, policy_b),
        );
        let result_a = result_a?;
        let result_b = result_b?;

        assert_eq!(result_a, result_b);
        assert_eq!(
            store_a.get_cluster_policy(&cluster_id).await?,
            Some(result_a)
        );

        drop(store_a);
        drop(store_b);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_overlay_routing_epoch_tracks_only_committed_routing_changes(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let cluster_id = ClusterId::from_string("cluster-a");
        let initial_policy = ClusterPolicy::default();
        let current_policy = ClusterPolicy {
            overlay_block_size: 12,
            ..initial_policy.clone()
        };

        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 0);
        assert_eq!(
            store
                .initialize_cluster_policy_if_absent(&cluster_id, initial_policy.clone())
                .await?,
            initial_policy
        );
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 1);

        assert_eq!(
            store
                .initialize_cluster_policy_if_absent(&cluster_id, current_policy.clone())
                .await?,
            initial_policy
        );
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 1);
        store
            .upsert_cluster_policy(&cluster_id, initial_policy.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 1);
        store
            .upsert_cluster_policy(&cluster_id, current_policy.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 2);
        store
            .upsert_cluster_policy(&cluster_id, current_policy.clone())
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 2);

        let empty_catalog_epoch = overlay_route_catalog_epoch(&[])?;
        assert!(
            !store
                .upsert_cluster_policy_if_route_catalog_epoch(
                    &cluster_id,
                    initial_policy.clone(),
                    empty_catalog_epoch ^ 1,
                )
                .await?
        );
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 2);
        assert!(
            store
                .upsert_cluster_policy_if_route_catalog_epoch(
                    &cluster_id,
                    current_policy.clone(),
                    empty_catalog_epoch,
                )
                .await?
        );
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 2);

        let local = node("epoch-node", Ipv4Addr::new(100, 64, 0, 1));
        store.insert_node(local.clone()).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 3);
        assert!(store.insert_node(local.clone()).await.is_err());
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 3);

        store
            .update_node_candidates(&local.node_id, vec![candidate(local.node_id.as_str())])
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 3);

        let route = Route {
            id: "epoch-route".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: local.node_id.clone(),
            via: Some(local.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        store
            .update_node_routes(&local.node_id, vec![route.clone()])
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);
        store
            .update_node_routes(&local.node_id, vec![route.clone()])
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);

        assert!(matches!(
            store
                .update_node_routes_if_cluster_policy(
                    &cluster_id,
                    &local.node_id,
                    Vec::new(),
                    Some(initial_policy),
                    None,
                )
                .await,
            Err(ControlPlaneError::ClusterPolicyChanged)
        ));
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);

        store
            .rotate_node_wireguard_public_key(
                &local.node_id,
                &local.wireguard_public_key,
                local.wireguard_public_key.clone(),
            )
            .await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);

        let remote = node("heartbeat-peer", Ipv4Addr::new(100, 64, 0, 2));
        let heartbeat_at = Utc::now() + Duration::seconds(1);
        let mut candidate_only =
            heartbeat_update(&local, &remote, heartbeat_at, "candidate-only", 43)?;
        candidate_only.expected_cluster_policy = Some(current_policy.clone());
        candidate_only.routes = None;
        store.apply_heartbeat(candidate_only).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);

        let mut same_route = heartbeat_update(
            &local,
            &remote,
            heartbeat_at + Duration::seconds(1),
            "same",
            44,
        )?;
        same_route.expected_cluster_policy = Some(current_policy.clone());
        same_route.routes = Some(vec![route]);
        store.apply_heartbeat(same_route.clone()).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 4);

        let mut changed_route = heartbeat_update(
            &local,
            &remote,
            heartbeat_at + Duration::seconds(2),
            "changed",
            45,
        )?;
        changed_route.expected_cluster_policy = Some(current_policy);
        store.apply_heartbeat(changed_route).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 5);
        assert!(store.apply_heartbeat(same_route).await.is_err());
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 5);

        store.remove_node(&local.node_id).await?;
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 6);
        assert!(matches!(
            store.remove_node(&local.node_id).await,
            Err(ControlPlaneError::NodeNotFound(_))
        ));
        assert_eq!(store.get_overlay_routing_epoch(&cluster_id).await?, 6);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_epoch_exhaustion_rolls_back_routing_change(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool.clone()).await?;
        let local = node("epoch-overflow", Ipv4Addr::new(100, 64, 0, 1));
        let cluster_id = local.cluster_id.clone();
        store.insert_node(local.clone()).await?;
        sqlx::query("UPDATE overlay_routing_epochs SET epoch = ?2 WHERE cluster_id = ?1")
            .bind(cluster_id.as_str())
            .bind(i64::MAX)
            .execute(&pool)
            .await?;

        let route = Route {
            id: "overflow-route".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: local.node_id.clone(),
            via: Some(local.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        assert!(matches!(
            store.update_node_routes(&local.node_id, vec![route]).await,
            Err(ControlPlaneError::Store(message))
                if message.contains("overlay routing epoch exhausted")
        ));
        assert_eq!(
            store.get_overlay_routing_epoch(&cluster_id).await?,
            i64::MAX as u64
        );
        assert!(store
            .get_node(&local.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
            .routes
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_guarded_node_mutations_reject_stale_cluster_policy(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let cluster_id = ClusterId::from_string("cluster-a");
        let current_policy = ClusterPolicy {
            overlay_block_size: 12,
            ..ClusterPolicy::default()
        };
        let stale_policy = ClusterPolicy::default();
        store
            .upsert_cluster_policy(&cluster_id, current_policy.clone())
            .await?;

        let local = node("node-a", Ipv4Addr::new(100, 64, 0, 1));
        assert!(matches!(
            store
                .insert_node_if_cluster_policy(local.clone(), Some(stale_policy.clone()), None)
                .await,
            Err(ControlPlaneError::ClusterPolicyChanged)
        ));
        assert_eq!(store.get_node(&local.node_id).await?, None);
        store
            .insert_node_if_cluster_policy(local.clone(), Some(current_policy.clone()), None)
            .await?;
        let remote = node("node-b", Ipv4Addr::new(100, 64, 0, 2));
        store
            .insert_node_if_cluster_policy(remote.clone(), Some(current_policy.clone()), None)
            .await?;

        let route = Route {
            id: "route-stale".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: local.node_id.clone(),
            via: Some(local.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        assert!(matches!(
            store
                .update_node_routes_if_cluster_policy(
                    &cluster_id,
                    &local.node_id,
                    vec![route],
                    Some(stale_policy.clone()),
                    None,
                )
                .await,
            Err(ControlPlaneError::ClusterPolicyChanged)
        ));
        assert!(store
            .get_node(&local.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
            .routes
            .is_empty());

        let accepted_at = Utc::now();
        let mut heartbeat = heartbeat_update(&local, &remote, accepted_at, "stale-policy", 42)?;
        heartbeat.expected_cluster_policy = Some(stale_policy);
        assert!(matches!(
            store.apply_heartbeat(heartbeat).await,
            Err(ControlPlaneError::ClusterPolicyChanged)
        ));
        assert_eq!(store.get_health(&local.node_id).await?, None);
        assert!(store.list_paths_for(&local.node_id).await?.is_empty());
        assert!(store
            .get_node(&local.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(local.node_id.clone()))?
            .routes
            .is_empty());

        let mut accepted = heartbeat_update(&local, &remote, accepted_at, "current-policy", 43)?;
        accepted.expected_cluster_policy = Some(current_policy);
        store.apply_heartbeat(accepted.clone()).await?;
        assert_eq!(
            store.get_health(&local.node_id).await?,
            Some(accepted.health)
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_rejoin_rejects_concurrent_node_state_change_atomically(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let cluster_id = ClusterId::from_string("cluster-a");
        let policy = ClusterPolicy::default();
        store
            .upsert_cluster_policy(&cluster_id, policy.clone())
            .await?;
        let original = node("rejoin-node", Ipv4Addr::new(100, 64, 0, 1));
        store.insert_node(original.clone()).await?;

        let mut concurrent_candidate = candidate("rejoin-node");
        concurrent_candidate.addr = SocketAddr::from(([203, 0, 113, 99], 51820));
        store
            .update_node_candidates(&original.node_id, vec![concurrent_candidate.clone()])
            .await?;

        assert!(matches!(
            store
                .rejoin_node_if_cluster_policy(RejoinNodeStoreUpdate {
                    cluster_id,
                    expected_cluster_policy: Some(policy),
                    expected_route_catalog_epoch: None,
                    expected_node: original.clone(),
                    candidates: vec![candidate("rejoin-node")],
                    relay_capability: Some(relay_capability()),
                    routes: Vec::new(),
                })
                .await,
            Err(ControlPlaneError::NodeStateChanged(node_id))
                if node_id == original.node_id
        ));

        let stored = store
            .get_node(&original.node_id)
            .await?
            .ok_or_else(|| ControlPlaneError::NodeNotFound(original.node_id.clone()))?;
        assert_eq!(stored.endpoint_candidates, vec![concurrent_candidate]);
        assert_eq!(stored.relay_capability, None);
        assert!(stored.routes.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_guarded_route_mutations_reject_stale_catalog_epoch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let cluster_id = ClusterId::from_string("cluster-a");
        let local = node("route-node-a", Ipv4Addr::new(100, 64, 0, 1));
        let remote = node("route-node-b", Ipv4Addr::new(100, 64, 0, 2));
        store.insert_node(local.clone()).await?;
        store.insert_node(remote.clone()).await?;
        let initial_epoch = overlay_route_catalog_epoch(&[local.clone(), remote.clone()])?;

        let local_route = Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: local.node_id.clone(),
            via: Some(local.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        store
            .update_node_routes_if_cluster_policy(
                &cluster_id,
                &local.node_id,
                vec![local_route.clone()],
                None,
                Some(initial_epoch),
            )
            .await?;

        let remote_route = Route {
            id: "route-b".to_string(),
            cidr: "10.43.0.0/16".parse()?,
            advertised_by: remote.node_id.clone(),
            via: Some(remote.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        assert!(matches!(
            store
                .update_node_routes_if_cluster_policy(
                    &cluster_id,
                    &remote.node_id,
                    vec![remote_route],
                    None,
                    Some(initial_epoch),
                )
                .await,
            Err(ControlPlaneError::OverlayRouteCatalogChanged)
        ));
        assert_eq!(
            store
                .get_node(&local.node_id)
                .await?
                .ok_or(ControlPlaneError::NodeNotFound(local.node_id))?
                .routes,
            vec![local_route]
        );
        assert!(store
            .get_node(&remote.node_id)
            .await?
            .ok_or(ControlPlaneError::NodeNotFound(remote.node_id))?
            .routes
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_cluster_policy_catalog_cas_rejects_stale_epoch(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let cluster_id = ClusterId::from_string("cluster-a");
        let mut provider = node("provider", Ipv4Addr::new(100, 64, 0, 1));
        provider.routes = vec![Route {
            id: "route-a".to_string(),
            cidr: "10.42.0.0/16".parse()?,
            advertised_by: provider.node_id.clone(),
            via: Some(provider.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        }];
        store.insert_node(provider.clone()).await?;
        let stale_epoch = overlay_route_catalog_epoch(&[provider.clone()])?;

        let replacement_route = Route {
            id: "route-b".to_string(),
            cidr: "10.43.0.0/16".parse()?,
            advertised_by: provider.node_id.clone(),
            via: Some(provider.node_id.clone()),
            metric: 50,
            tags: BTreeSet::new(),
        };
        store
            .update_node_routes(&provider.node_id, vec![replacement_route])
            .await?;
        let next_policy = ClusterPolicy {
            overlay_block_size: 16,
            ..ClusterPolicy::default()
        };
        assert!(
            !store
                .upsert_cluster_policy_if_route_catalog_epoch(
                    &cluster_id,
                    next_policy.clone(),
                    stale_epoch,
                )
                .await?
        );
        assert_eq!(store.get_cluster_policy(&cluster_id).await?, None);

        let current_catalog = store
            .list_nodes()
            .await?
            .into_iter()
            .filter(|node| node.cluster_id == cluster_id && !node.role.is_client())
            .collect::<Vec<_>>();
        let current_epoch = overlay_route_catalog_epoch(&current_catalog)?;
        assert!(
            store
                .upsert_cluster_policy_if_route_catalog_epoch(
                    &cluster_id,
                    next_policy.clone(),
                    current_epoch,
                )
                .await?
        );
        assert_eq!(
            store.get_cluster_policy(&cluster_id).await?,
            Some(next_policy)
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_service_directory_is_shared_across_store_instances(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("service-directory");
        let cluster_id = ClusterId::from_string("cluster-ha");
        let now = Utc::now();
        let first = ServiceInstance {
            cluster_id: cluster_id.clone(),
            instance_id: "public-a".to_string(),
            owner_host_id: "host-public-a".to_string(),
            owner_node_id: None,
            enrollment_signer: true,
            endpoints: vec![BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://public-a.example:8443".to_string(),
            }],
            lease_expires_at: now + Duration::seconds(30),
            updated_at: now,
        };
        let store_a = SqliteControlPlaneStore::connect(&database_url).await?;
        let store_b = SqliteControlPlaneStore::connect(&database_url).await?;

        store_a.upsert_service_instance(first.clone()).await?;
        assert_eq!(
            store_b.list_service_instances(&cluster_id).await?,
            vec![first.clone()]
        );

        let renewed = ServiceInstance {
            endpoints: vec![BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://public-a.example:9443".to_string(),
            }],
            updated_at: now + Duration::seconds(1),
            lease_expires_at: now + Duration::seconds(31),
            ..first
        };
        store_b.upsert_service_instance(renewed.clone()).await?;
        assert_eq!(
            store_a.list_service_instances(&cluster_id).await?,
            vec![renewed]
        );
        assert!(store_a
            .list_service_instances(&ClusterId::from_string("other-cluster"))
            .await?
            .is_empty());
        assert!(
            store_a
                .remove_service_instance(&cluster_id, "public-a")
                .await?
        );
        assert!(
            !store_a
                .remove_service_instance(&cluster_id, "public-a")
                .await?
        );
        assert!(store_b
            .list_service_instances(&cluster_id)
            .await?
            .is_empty());

        drop(store_a);
        drop(store_b);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_keycloak_candidate_leases_are_shared_filtered_and_mutable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("keycloak-candidates");
        let cluster_id = ClusterId::from_string("cluster-ha");
        let other_cluster_id = ClusterId::from_string("cluster-other");
        let now = Utc::now();
        let node_a = keycloak_candidate(
            &cluster_id,
            "node-a",
            1,
            true,
            now + Duration::seconds(30),
            now,
        );
        let node_b = keycloak_candidate(
            &cluster_id,
            "node-b",
            2,
            false,
            now + Duration::seconds(40),
            now,
        );
        let expired = keycloak_candidate(
            &cluster_id,
            "node-expired",
            3,
            true,
            now - Duration::seconds(1),
            now,
        );
        let cutoff_boundary = keycloak_candidate(&cluster_id, "node-cutoff", 4, true, now, now);
        let other_cluster = keycloak_candidate(
            &other_cluster_id,
            "node-a",
            5,
            true,
            now + Duration::seconds(30),
            now,
        );
        let store_a = SqliteControlPlaneStore::connect(&database_url).await?;
        let store_b = SqliteControlPlaneStore::connect(&database_url).await?;

        store_a.upsert_keycloak_candidate(node_b.clone()).await?;
        store_a.upsert_keycloak_candidate(expired).await?;
        store_b.upsert_keycloak_candidate(node_a.clone()).await?;
        store_b.upsert_keycloak_candidate(cutoff_boundary).await?;
        store_b
            .upsert_keycloak_candidate(other_cluster.clone())
            .await?;

        assert_eq!(
            store_b
                .list_keycloak_candidates(&cluster_id, now, None, 64)
                .await?,
            vec![node_a.clone(), node_b.clone()]
        );
        assert_eq!(
            store_a
                .list_keycloak_candidates(&cluster_id, now, None, 1)
                .await?,
            vec![node_a.clone()]
        );
        assert_eq!(
            store_a
                .list_keycloak_candidates(&other_cluster_id, now, None, 64)
                .await?,
            vec![other_cluster]
        );
        for invalid_limit in [0, 65] {
            let Err(error) = store_a
                .list_keycloak_candidates(&cluster_id, now, None, invalid_limit)
                .await
            else {
                return Err("invalid candidate query limit unexpectedly succeeded".into());
            };
            assert!(
                matches!(error, ControlPlaneError::Store(message) if message.contains("between 1 and 64"))
            );
        }

        let renewed = KeycloakCandidateLease {
            ready: true,
            generation: 2,
            lease_expires_at: now + Duration::seconds(60),
            updated_at: now + Duration::seconds(1),
            ..node_b
        };
        store_b.upsert_keycloak_candidate(renewed.clone()).await?;
        assert_eq!(
            store_a
                .list_keycloak_candidates(&cluster_id, now, None, 64)
                .await?,
            vec![node_a.clone(), renewed.clone()]
        );
        let structured_expiry = sqlx::query_scalar::<_, i64>(
            "SELECT lease_expires_at FROM keycloak_candidate_leases WHERE cluster_id = ?1 AND node_id = ?2",
        )
        .bind(cluster_id.as_str())
        .bind(renewed.node_id.as_str())
        .fetch_one(&store_a.pool)
        .await?;
        assert_eq!(
            structured_expiry,
            keycloak_candidate_expiry_nanos(&renewed.lease_expires_at)?
        );

        sqlx::query(
            "UPDATE keycloak_candidate_leases SET lease_expires_at = lease_expires_at + 1 WHERE cluster_id = ?1 AND node_id = ?2",
        )
        .bind(cluster_id.as_str())
        .bind(renewed.node_id.as_str())
        .execute(&store_a.pool)
        .await?;
        assert!(matches!(
            store_a
                .list_keycloak_candidates(&cluster_id, now, None, 64)
                .await,
            Err(ControlPlaneError::Store(message))
                if message.contains("lease expiration does not match")
        ));
        let repaired = KeycloakCandidateLease {
            generation: 3,
            updated_at: now + Duration::seconds(2),
            ..renewed.clone()
        };
        assert!(store_b.upsert_keycloak_candidate(repaired.clone()).await?);

        let withdrawn = KeycloakCandidateLease {
            eligible: false,
            ready: false,
            generation: 2,
            lease_expires_at: now + Duration::seconds(45),
            updated_at: now + Duration::seconds(1),
            ..node_a.clone()
        };
        assert!(store_a.upsert_keycloak_candidate(withdrawn.clone()).await?);
        assert!(!store_b.upsert_keycloak_candidate(node_a).await?);
        assert_eq!(
            store_b
                .list_keycloak_candidates(&cluster_id, now, None, 64)
                .await?,
            vec![repaired.clone()]
        );
        let reset = KeycloakCandidateLease {
            eligible: true,
            ready: true,
            generation: 1,
            lease_expires_at: now + Duration::seconds(90),
            updated_at: now + Duration::seconds(46),
            ..withdrawn
        };
        assert!(store_b.upsert_keycloak_candidate(reset.clone()).await?);
        assert_eq!(
            store_a
                .list_keycloak_candidates(
                    &cluster_id,
                    now + Duration::seconds(46),
                    Some(&reset.node_id),
                    64,
                )
                .await?,
            vec![repaired.clone()]
        );
        assert_eq!(
            store_a
                .list_keycloak_candidates(&cluster_id, now + Duration::seconds(46), None, 64)
                .await?,
            vec![reset, repaired]
        );

        drop(store_a);
        drop(store_b);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_migrates_legacy_keycloak_candidate_rows(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("keycloak-generation-migration");
        let cluster_id = ClusterId::from_string("cluster-keycloak-legacy");
        let now = Utc::now();
        let mut expected = keycloak_candidate(
            &cluster_id,
            "legacy-node",
            9,
            true,
            now + Duration::seconds(45),
            now,
        );
        expected.generation = 0;
        let mut legacy_record = serde_json::to_value(&expected)?;
        let legacy_record = legacy_record
            .as_object_mut()
            .ok_or("Keycloak candidate must serialize as an object")?;
        legacy_record.remove("generation");
        legacy_record.remove("eligible");

        let pool = SqlitePool::connect(&database_url).await?;
        sqlx::query(
            r#"
            CREATE TABLE keycloak_candidate_leases (
                cluster_id TEXT NOT NULL,
                node_id TEXT NOT NULL,
                lease_expires_at INTEGER NOT NULL,
                record_json TEXT NOT NULL,
                PRIMARY KEY (cluster_id, node_id)
            )
            "#,
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "INSERT INTO keycloak_candidate_leases (cluster_id, node_id, lease_expires_at, record_json) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(cluster_id.as_str())
        .bind(expected.node_id.as_str())
        .bind(keycloak_candidate_expiry_nanos(&expected.lease_expires_at)?)
        .bind(serde_json::to_string(legacy_record)?)
        .execute(&pool)
        .await?;
        pool.close().await;

        let migrated = SqliteControlPlaneStore::connect(&database_url).await?;
        assert_eq!(
            migrated
                .list_keycloak_candidates(&cluster_id, now, None, 64)
                .await?,
            vec![expected.clone()]
        );
        let columns = sqlx::query("PRAGMA table_info(keycloak_candidate_leases)")
            .fetch_all(&migrated.pool)
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<BTreeSet<_>>();
        assert!(columns.contains("generation"));
        assert!(columns.contains("eligible"));

        let upgraded = KeycloakCandidateLease {
            generation: 1,
            updated_at: now + Duration::seconds(1),
            lease_expires_at: now + Duration::seconds(60),
            ..expected
        };
        assert!(migrated.upsert_keycloak_candidate(upgraded).await?);

        drop(migrated);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_service_directory_migrates_legacy_ownerless_records(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("service-owner-migration");
        let cluster_id = ClusterId::from_string("cluster-legacy");
        let now = Utc::now();
        let expected = ServiceInstance {
            cluster_id: cluster_id.clone(),
            instance_id: "legacy-public".to_string(),
            owner_host_id: ipars_types::LEGACY_UNOWNED_SERVICE_HOST_ID.to_string(),
            owner_node_id: None,
            enrollment_signer: false,
            endpoints: vec![BootstrapEndpoint {
                kind: BootstrapEndpointKind::ControlPlane,
                url: "https://legacy.example:8443".to_string(),
            }],
            lease_expires_at: now + Duration::seconds(30),
            updated_at: now,
        };
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let mut legacy = serde_json::to_value(&expected)?;
        let Some(legacy) = legacy.as_object_mut() else {
            return Err("service instance must serialize as an object".into());
        };
        legacy.remove("owner_host_id");
        legacy.remove("owner_node_id");
        legacy.remove("enrollment_signer");
        sqlx::query(
            "INSERT INTO service_instances (cluster_id, instance_id, record_json) VALUES (?1, ?2, ?3)",
        )
        .bind(cluster_id.as_str())
        .bind(expected.instance_id.as_str())
        .bind(serde_json::to_string(legacy)?)
        .execute(&store.pool)
        .await?;
        drop(store);

        let migrated = SqliteControlPlaneStore::connect(&database_url).await?;
        assert_eq!(
            migrated.list_service_instances(&cluster_id).await?,
            vec![expected.clone()]
        );

        sqlx::query(
            "UPDATE service_instances SET record_json = ?1 WHERE cluster_id = ?2 AND instance_id = ?3",
        )
        .bind(serde_json::to_string(legacy)?)
        .bind(cluster_id.as_str())
        .bind(expected.instance_id.as_str())
        .execute(&migrated.pool)
        .await?;
        assert_eq!(
            migrated.list_service_instances(&cluster_id).await?,
            vec![expected]
        );

        drop(migrated);
        let _ = std::fs::remove_file(database_path);
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
        let received_at = Utc::now();
        let old_at = received_at - chrono::Duration::seconds(120);
        let new_at = old_at + chrono::Duration::seconds(1);
        let mut old = heartbeat_update(&local, &remote, old_at, "old", 10)?;
        old.health.last_seen_at = received_at;
        let mut newest = heartbeat_update(&local, &remote, new_at, "new", 11)?;
        newest.health.last_seen_at = received_at + chrono::Duration::milliseconds(1);

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
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&local.node_id)
                .await?,
            Some(new_at)
        );
        assert_eq!(store.list_paths_for(&local.node_id).await?, newest.paths);

        drop(store);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_heartbeat_rejects_aba_generation_and_foreign_cluster(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let original = node("node-a", Ipv4Addr::new(100, 64, 0, 1));
        let remote = node("node-b", Ipv4Addr::new(100, 64, 0, 2));
        store.insert_node(original.clone()).await?;
        store.insert_node(remote.clone()).await?;
        let stale_update = heartbeat_update(&original, &remote, Utc::now(), "stale", 42)?;

        store.remove_node(&original.node_id).await?;
        let mut replacement = original.clone();
        replacement.identity_public_key = "replacement-identity".to_string();
        replacement.registered_at = original.registered_at + Duration::seconds(1);
        store.insert_node(replacement.clone()).await?;
        assert!(matches!(
            store.apply_heartbeat(stale_update).await,
            Err(ControlPlaneError::NodeUpdateRejected { reason, .. })
                if reason.contains("node generation changed")
        ));
        assert_eq!(
            store.get_node(&original.node_id).await?,
            Some(replacement.clone())
        );
        assert_eq!(store.get_health(&original.node_id).await?, None);
        assert!(store.list_paths_for(&original.node_id).await?.is_empty());

        store.remove_node(&original.node_id).await?;
        let mut foreign = replacement;
        foreign.cluster_id = ClusterId::from_string("cluster-b");
        store.insert_node(foreign.clone()).await?;
        let mut foreign_update = heartbeat_update(&foreign, &remote, Utc::now(), "foreign", 43)?;
        foreign_update.cluster_id = ClusterId::from_string("cluster-a");
        assert!(matches!(
            store.apply_heartbeat(foreign_update).await,
            Err(ControlPlaneError::NodeNotFound(node_id)) if node_id == foreign.node_id
        ));
        let foreign_route = Route {
            id: "foreign-route".to_string(),
            cidr: "10.43.0.0/16".parse()?,
            advertised_by: foreign.node_id.clone(),
            via: Some(foreign.node_id.clone()),
            metric: 100,
            tags: BTreeSet::new(),
        };
        assert!(matches!(
            store
                .update_node_routes_if_cluster_policy(
                    &ClusterId::from_string("cluster-a"),
                    &foreign.node_id,
                    vec![foreign_route],
                    None,
                    None,
                )
                .await,
            Err(ControlPlaneError::NodeNotFound(node_id)) if node_id == foreign.node_id
        ));
        assert_eq!(store.get_node(&foreign.node_id).await?, Some(foreign));
        assert_eq!(store.get_health(&original.node_id).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_migration_backfills_legacy_health_signature_timestamp(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        sqlx::query(
            "CREATE TABLE health (node_id TEXT PRIMARY KEY NOT NULL, record_json TEXT NOT NULL)",
        )
        .execute(&pool)
        .await?;
        let signed_at =
            DateTime::parse_from_rfc3339("2026-07-27T01:02:03.456789Z")?.with_timezone(&Utc);
        let health = NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: signed_at,
            latency_ms: None,
            relay_load: None,
            message: None,
        };
        sqlx::query("INSERT INTO health (node_id, record_json) VALUES (?1, ?2)")
            .bind("legacy-node")
            .bind(serde_json::to_string(&health)?)
            .execute(&pool)
            .await?;

        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        assert_eq!(
            store
                .get_heartbeat_signature_timestamp(&NodeId::from_string("legacy-node"))
                .await?,
            Some(signed_at)
        );
        let unsigned_node = NodeId::from_string("unsigned-node");
        store
            .upsert_health(
                unsigned_node.clone(),
                NodeHealth {
                    state: HealthState::Healthy,
                    last_seen_at: signed_at + chrono::Duration::seconds(1),
                    latency_ms: None,
                    relay_load: None,
                    message: None,
                },
            )
            .await?;
        let pool = store.pool.clone();
        drop(store);
        let reopened = SqliteControlPlaneStore::from_pool(pool).await?;
        assert_eq!(
            reopened
                .get_heartbeat_signature_timestamp(&unsigned_node)
                .await?,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_first_token_admission_enforces_max_uses_under_concurrency(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("token-concurrency");
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let admission = Arc::new(TokenAdmission::new(Arc::new(store.clone())));
        let cluster_id = ClusterId::new();
        let mut token_claims = claims(cluster_id.clone());
        token_claims.nonce = "concurrent-token".to_string();
        token_claims.policy.max_token_uses = Some(1);

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

    #[tokio::test]
    async fn sqlite_token_revocation_preserves_concurrent_uses(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("token-revocation-concurrency");
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let admission = Arc::new(TokenAdmission::new(Arc::new(store.clone())));
        let cluster_id = ClusterId::new();
        let mut token_claims = claims(cluster_id.clone());
        token_claims.nonce = "concurrent-revocation".to_string();
        token_claims.policy.max_token_uses = None;

        let task_count = 64;
        let barrier = Arc::new(tokio::sync::Barrier::new(task_count + 1));
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

        barrier.wait().await;
        let revoked = admission
            .revoke_token(TokenRevocationRecord {
                cluster_id: cluster_id.clone(),
                nonce: token_claims.nonce.clone(),
                issuer: token_claims.issuer.clone(),
                key_id: token_claims.key_id.clone(),
                revoked_at: Utc::now(),
            })
            .await?;
        assert_eq!(revoked.revocation.nonce, token_claims.nonce);

        let mut accepted = 0_u32;
        for task in tasks {
            match task.await? {
                Ok(_) => accepted = accepted.saturating_add(1),
                Err(ControlPlaneError::TokenRejected {
                    status: TokenStatus::Revoked,
                    ..
                }) => {}
                Err(error) => {
                    return Err(format!("unexpected concurrent revocation error: {error}").into())
                }
            }
        }

        let final_record = store
            .get_token(&cluster_id, &token_claims.nonce)
            .await?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(token_claims.nonce.clone()))?;
        assert_eq!(final_record.status(Utc::now()), TokenStatus::Revoked);
        assert_eq!(final_record.uses, accepted);
        if let Some(revoked_record) = revoked.record {
            assert!(final_record.has_same_definition(&revoked_record));
        }

        drop(admission);
        drop(store);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }

    #[tokio::test]
    async fn sqlite_preemptive_token_revocation_survives_restart(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (database_url, database_path) = temp_sqlite_url("preemptive-token-revocation");
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let admission = TokenAdmission::new(Arc::new(store.clone()));
        let cluster_id = ClusterId::new();
        let mut token_claims = claims(cluster_id.clone());
        token_claims.nonce = "preemptively-revoked".to_string();
        let revoked_at = Utc::now();
        let outcome = admission
            .revoke_token(TokenRevocationRecord {
                cluster_id: cluster_id.clone(),
                nonce: token_claims.nonce.clone(),
                issuer: token_claims.issuer.clone(),
                key_id: token_claims.key_id.clone(),
                revoked_at,
            })
            .await?;
        assert!(outcome.record.is_none());
        assert_eq!(outcome.revocation.revoked_at, revoked_at);
        assert!(store
            .get_token(&cluster_id, &token_claims.nonce)
            .await?
            .is_none());
        let metrics = store.token_metrics(&cluster_id, Utc::now()).await?;
        assert_eq!(metrics.issued_count, 1);
        assert_eq!(metrics.revoked_count, 1);
        assert_eq!(metrics.use_count, 0);

        drop(admission);
        drop(store);
        let store = SqliteControlPlaneStore::connect(&database_url).await?;
        let admission = TokenAdmission::new(Arc::new(store.clone()));
        assert!(matches!(
            admission.admit_join(&token_claims, Utc::now()).await,
            Err(ControlPlaneError::TokenRejected {
                status: TokenStatus::Revoked,
                ..
            })
        ));
        let stored = store
            .get_token(&cluster_id, &token_claims.nonce)
            .await?
            .ok_or_else(|| ControlPlaneError::TokenNotFound(token_claims.nonce.clone()))?;
        assert_eq!(stored.status(Utc::now()), TokenStatus::Revoked);
        assert_eq!(stored.uses, 0);

        drop(admission);
        drop(store);
        let _ = std::fs::remove_file(database_path);
        Ok(())
    }
}
