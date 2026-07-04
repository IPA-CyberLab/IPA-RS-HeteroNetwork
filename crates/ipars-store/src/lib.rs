use async_trait::async_trait;
use ipars_control_plane::{ControlPlaneError, ControlPlaneStore};
use ipars_types::{NodeId, NodeRecord, PathRecord};
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
        Ok(())
    }
}

#[async_trait]
impl ControlPlaneStore for SqliteControlPlaneStore {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES (?1, ?2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_string(&node).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
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

#[derive(Debug, Clone)]
pub struct PostgresControlPlaneStore {
    pool: PgPool,
}

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
        self.pool
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
        self.pool
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
        Ok(())
    }
}

#[async_trait]
impl ControlPlaneStore for PostgresControlPlaneStore {
    async fn insert_node(&self, node: NodeRecord) -> Result<(), ControlPlaneError> {
        sqlx::query("INSERT INTO nodes (node_id, record_json) VALUES ($1, $2)")
            .bind(node.node_id.as_str())
            .bind(serde_json::to_value(&node).map_err(json_error)?)
            .execute(&self.pool)
            .await
            .map_err(sql_error)?;
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

fn row_to_node(row: sqlx::sqlite::SqliteRow) -> Result<NodeRecord, ControlPlaneError> {
    let record_json: String = row.get("record_json");
    serde_json::from_str(&record_json).map_err(json_error)
}

fn row_to_path(row: sqlx::sqlite::SqliteRow) -> Result<PathRecord, ControlPlaneError> {
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

fn sql_error(error: sqlx::Error) -> ControlPlaneError {
    ControlPlaneError::Store(error.to_string())
}

fn json_error(error: serde_json::Error) -> ControlPlaneError {
    ControlPlaneError::Store(error.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;
    use ipars_control_plane::ControlPlaneStore;
    use ipars_types::{
        ClusterId, NodeRecord, PathMetrics, PathRecord, PathScore, PathState, PeerPathKey, Role,
        TokenPolicy, VpnIp,
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

    #[tokio::test]
    async fn sqlite_store_round_trips_nodes_and_paths() -> Result<(), Box<dyn std::error::Error>> {
        let pool = SqlitePool::connect("sqlite::memory:").await?;
        let store = SqliteControlPlaneStore::from_pool(pool).await?;
        let local = node("node-a", Ipv4Addr::new(100, 64, 0, 1));
        let remote = node("node-b", Ipv4Addr::new(100, 64, 0, 2));
        store.insert_node(local.clone()).await?;
        store.insert_node(remote.clone()).await?;

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
        store.upsert_path(path).await?;

        assert_eq!(store.get_node(&local.node_id).await?, Some(local.clone()));
        assert_eq!(store.list_nodes().await?.len(), 2);
        assert_eq!(store.list_paths_for(&local.node_id).await?.len(), 1);
        Ok(())
    }
}
