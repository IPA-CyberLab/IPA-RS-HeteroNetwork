use super::*;
use ipars_control_plane::http_mesh::{
    EnqueueOutcome, HttpMeshStore, MeshAck, MeshEnvelope, MeshStats, MeshWakeups, MAX_NODE_NONCES,
    MAX_PENDING_BATCHES, MAX_PENDING_BYTES, MAX_RECEIVE_BATCHES, MAX_SOURCE_BATCHES,
};
use sqlx::Transaction;
use std::sync::Arc;
use tokio::sync::Notify;

pub(crate) const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS http_mesh_members (node_id TEXT PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE, cluster_id TEXT NOT NULL, ephemeral BOOLEAN NOT NULL, http_only BOOLEAN NOT NULL, expires_at BIGINT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS http_mesh_member_routes ON http_mesh_members(cluster_id,http_only,node_id,expires_at)",
    "CREATE INDEX IF NOT EXISTS http_mesh_member_expiry ON http_mesh_members(ephemeral,expires_at)",
    "CREATE TABLE IF NOT EXISTS http_mesh_nonces (node_id TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE, nonce TEXT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY(node_id,nonce))",
    "CREATE INDEX IF NOT EXISTS http_mesh_nonce_expiry ON http_mesh_nonces(expires_at)",
    "CREATE TABLE IF NOT EXISTS http_mesh_batches (source TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE, batch_id TEXT NOT NULL, target TEXT NOT NULL REFERENCES nodes(node_id) ON DELETE CASCADE, digest TEXT NOT NULL, bytes BIGINT NOT NULL CHECK(bytes >= 0), expires_at BIGINT NOT NULL, pending BOOLEAN NOT NULL, envelope_json TEXT NOT NULL, PRIMARY KEY(source,batch_id))",
    "CREATE INDEX IF NOT EXISTS http_mesh_target ON http_mesh_batches(target,pending,expires_at,batch_id)",
    "CREATE INDEX IF NOT EXISTS http_mesh_expiry ON http_mesh_batches(expires_at)",
    "CREATE TABLE IF NOT EXISTS http_mesh_stats (node_id TEXT PRIMARY KEY REFERENCES nodes(node_id) ON DELETE CASCADE, sent_bytes BIGINT NOT NULL DEFAULT 0, received_bytes BIGINT NOT NULL DEFAULT 0, last_poll_at BIGINT)",
];

pub(crate) fn sqlite_reaper(pool: &SqlitePool, wakeups: &Arc<MeshWakeups>) {
    let pool = pool.clone();
    let weak = Arc::downgrade(wakeups);
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if weak.strong_count() == 0 {
                return;
            }
            let store = SqliteControlPlaneStore {
                pool: pool.clone(),
                mesh_wakeups: Default::default(),
            };
            let _ = store.reap_expired_mesh_members(Utc::now()).await;
        }
    });
    *wakeups
        .listener
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(task);
}

pub(crate) async fn postgres_listener(
    pool: &PgPool,
    wakeups: &Arc<MeshWakeups>,
) -> Result<(), ControlPlaneError> {
    let notification_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await
        .map_err(sql_error)?;
    let mut listener = sqlx::postgres::PgListener::connect_with(&notification_pool)
        .await
        .map_err(sql_error)?;
    listener
        .listen("heteronet_http_mesh")
        .await
        .map_err(sql_error)?;
    let weak = Arc::downgrade(wakeups);
    let cleanup_pool = pool.clone();
    let task = tokio::spawn(async move {
        let mut cleanup = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            let result = tokio::select! {
                result=listener.recv()=>result,
                _=cleanup.tick()=>{
                    if weak.strong_count()==0 {return;}
                    let _=sqlx::query("DELETE FROM http_mesh_batches WHERE (source,batch_id) IN (SELECT source,batch_id FROM http_mesh_batches WHERE expires_at<=$1 LIMIT 1000)").bind(Utc::now().timestamp_millis()).execute(&cleanup_pool).await;
                    let _=sqlx::query("DELETE FROM http_mesh_nonces WHERE (node_id,nonce) IN (SELECT node_id,nonce FROM http_mesh_nonces WHERE expires_at<=$1 LIMIT 10000)").bind(Utc::now().timestamp_millis()).execute(&cleanup_pool).await;
                    let store=PostgresControlPlaneStore{pool:cleanup_pool.clone(),mesh_wakeups:Default::default()};
                    let _=store.reap_expired_mesh_members(Utc::now()).await;
                    continue;
                }
            };
            match result {
                Ok(notification) => {
                    let Some(wakeups) = weak.upgrade() else {
                        return;
                    };
                    let payload = notification.payload();
                    if payload.len() <= 128 {
                        wakeups.wake(&NodeId::from_string(payload));
                    }
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            }
        }
    });
    *wakeups
        .listener
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(task);
    Ok(())
}

impl SqliteControlPlaneStore {
    async fn mesh_lock(
        &self,
        transaction: &mut Transaction<'_, Sqlite>,
        source: &NodeId,
        _target: &NodeId,
    ) -> Result<(), ControlPlaneError> {
        // Obtain SQLite's write reservation before reads, avoiding a read-to-write
        // transaction upgrade when separate HTTP workers enqueue concurrently.
        sqlx::query("UPDATE http_mesh_stats SET sent_bytes=sent_bytes WHERE node_id=?")
            .bind(source.as_str())
            .execute(&mut **transaction)
            .await
            .map_err(sql_error)?;
        Ok(())
    }
    async fn mesh_notify(
        &self,
        _transaction: &mut Transaction<'_, Sqlite>,
        _target: &NodeId,
    ) -> Result<(), ControlPlaneError> {
        Ok(())
    }
}
impl PostgresControlPlaneStore {
    async fn mesh_lock(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        source: &NodeId,
        target: &NodeId,
    ) -> Result<(), ControlPlaneError> {
        // Namespaces and ordering are fixed across replicas. No global packet lock.
        let mut nodes = vec![source, target];
        nodes.sort();
        nodes.dedup();
        for node in nodes {
            let key = format!("mesh-node:{node}");
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(key)
                .execute(&mut **transaction)
                .await
                .map_err(sql_error)?;
        }
        Ok(())
    }
    async fn mesh_notify(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        target: &NodeId,
    ) -> Result<(), ControlPlaneError> {
        sqlx::query("SELECT pg_notify('heteronet_http_mesh',$1)")
            .bind(target.as_str())
            .execute(&mut **transaction)
            .await
            .map_err(sql_error)?;
        Ok(())
    }
}

macro_rules! mesh_store {
    ($store:ty,$database:ty,$active_node:literal) => {
        impl $store{
            pub(crate) async fn reap_expired_mesh_members(&self,now:chrono::DateTime<Utc>)->Result<usize,ControlPlaneError>{
                let mut query=QueryBuilder::<$database>::new("SELECT m.node_id FROM http_mesh_members m JOIN nodes n ON n.node_id=m.node_id WHERE m.ephemeral=TRUE AND m.expires_at<=");query.push_bind(now.timestamp_millis()).push(" AND ").push($active_node).push(" ORDER BY m.expires_at LIMIT 100");
                let rows=query.build().fetch_all(&self.pool).await.map_err(sql_error)?;
                let mut removed=0;
                for row in rows{
                    let node=NodeId::from_string(row.try_get::<String,_>("node_id").map_err(sql_error)?);
                    match self.remove_node_checked(&node,Some(now)).await{
                        Ok(_)=>removed+=1,
                        Err(ControlPlaneError::NodeNotFound(_)|ControlPlaneError::NodeStateChanged(_))=>{},
                        Err(error)=>return Err(error),
                    }
                }
                Ok(removed)
            }
        }
        #[async_trait]
        impl HttpMeshStore for $store {
            async fn lease(&self,node:&NodeRecord,ephemeral:bool,http_only:bool,now:chrono::DateTime<Utc>)->Result<(),ControlPlaneError>{
                let mut query=QueryBuilder::<$database>::new("INSERT INTO http_mesh_members(node_id,cluster_id,ephemeral,http_only,expires_at) VALUES (");query.push_bind(node.node_id.as_str()).push(",").push_bind(node.cluster_id.as_str()).push(",").push_bind(ephemeral).push(",").push_bind(http_only).push(",").push_bind((now+chrono::Duration::minutes(5)).timestamp_millis()).push(") ON CONFLICT(node_id) DO UPDATE SET ephemeral=excluded.ephemeral,http_only=excluded.http_only,expires_at=excluded.expires_at");
                query.build().execute(&self.pool).await.map_err(sql_error)?;Ok(())
            }
            async fn members(&self,cluster:&ClusterId,after:Option<&NodeId>,limit:usize,now:chrono::DateTime<Utc>)->Result<Vec<NodeId>,ControlPlaneError>{
                let mut query=QueryBuilder::<$database>::new("SELECT node_id FROM http_mesh_members WHERE cluster_id=");query.push_bind(cluster.as_str()).push(" AND http_only=TRUE AND expires_at>").push_bind(now.timestamp_millis());
                if let Some(after)=after{query.push(" AND node_id>").push_bind(after.as_str());}
                query.push(" ORDER BY node_id LIMIT ").push_bind(limit as i64);
                query.build().fetch_all(&self.pool).await.map_err(sql_error)?.into_iter().map(|row|Ok(NodeId::from_string(row.try_get::<String,_>("node_id").map_err(sql_error)?))).collect()
            }
            async fn is_http_only(&self,node:&NodeId)->Result<bool,ControlPlaneError>{
                let mut query=QueryBuilder::<$database>::new("SELECT http_only FROM http_mesh_members WHERE node_id=");query.push_bind(node.as_str());
                query.build().fetch_optional(&self.pool).await.map_err(sql_error)?.map(|row|row.try_get::<bool,_>("http_only").map_err(sql_error)).transpose().map(|value|value.unwrap_or(false))
            }
            async fn consume_nonce(&self,node:&NodeId,nonce:&str,expires_at:chrono::DateTime<Utc>,now:chrono::DateTime<Utc>)->Result<bool,ControlPlaneError>{
                let mut transaction=self.pool.begin().await.map_err(sql_error)?;
                self.mesh_lock(&mut transaction,node,node).await?;
                let mut cleanup=QueryBuilder::<$database>::new("DELETE FROM http_mesh_nonces WHERE node_id=");cleanup.push_bind(node.as_str()).push(" AND expires_at<=").push_bind(now.timestamp_millis());
                cleanup.build().execute(&mut *transaction).await.map_err(sql_error)?;
                let mut query=QueryBuilder::<$database>::new("SELECT nonce FROM http_mesh_nonces WHERE node_id=");query.push_bind(node.as_str()).push(" AND nonce=").push_bind(nonce);
                if query.build().fetch_optional(&mut *transaction).await.map_err(sql_error)?.is_some(){return Ok(false);}
                let mut count=QueryBuilder::<$database>::new("SELECT COUNT(*) AS count FROM http_mesh_nonces WHERE node_id=");count.push_bind(node.as_str());
                let count:i64=count.build().fetch_one(&mut *transaction).await.map_err(sql_error)?.try_get("count").map_err(sql_error)?;
                if count>=MAX_NODE_NONCES as i64{return Err(ControlPlaneError::HttpMeshCapacity);}
                let mut insert=QueryBuilder::<$database>::new("INSERT INTO http_mesh_nonces(node_id,nonce,expires_at) VALUES (");insert.push_bind(node.as_str()).push(",").push_bind(nonce).push(",").push_bind(expires_at.timestamp_millis()).push(")");
                insert.build().execute(&mut *transaction).await.map_err(sql_error)?;
                transaction.commit().await.map_err(sql_error)?;Ok(true)
            }
            async fn enqueue(&self,envelope:MeshEnvelope,now:chrono::DateTime<Utc>)->Result<EnqueueOutcome,ControlPlaneError>{
                let digest=envelope.digest()?;
                let mut transaction=self.pool.begin().await.map_err(sql_error)?;
                self.mesh_lock(&mut transaction,&envelope.source,&envelope.target).await?;
                let mut clean=QueryBuilder::<$database>::new("DELETE FROM http_mesh_batches WHERE expires_at <= ");
                clean.push_bind(now.timestamp_millis()).push(" AND (source=").push_bind(envelope.source.as_str()).push(" OR target=").push_bind(envelope.target.as_str()).push(")");
                clean.build().execute(&mut *transaction).await.map_err(sql_error)?;
                let mut existing=QueryBuilder::<$database>::new("SELECT digest FROM http_mesh_batches WHERE source=");
                existing.push_bind(envelope.source.as_str()).push(" AND batch_id=").push_bind(&envelope.batch_id);
                if let Some(row)=existing.build().fetch_optional(&mut *transaction).await.map_err(sql_error)? {
                    let previous:String=row.try_get("digest").map_err(sql_error)?;
                    return Ok(if previous==digest {EnqueueOutcome::Duplicate} else {EnqueueOutcome::Conflict});
                }
                let mut count=QueryBuilder::<$database>::new("SELECT COUNT(*) AS count,CAST(COALESCE(SUM(bytes),0) AS BIGINT) AS bytes FROM http_mesh_batches WHERE pending=TRUE AND target=");
                count.push_bind(envelope.target.as_str());
                let row=count.build().fetch_one(&mut *transaction).await.map_err(sql_error)?;
                let pending:i64=row.try_get("count").map_err(sql_error)?;
                let bytes:i64=row.try_get("bytes").map_err(sql_error)?;
                let mut source_count=QueryBuilder::<$database>::new("SELECT COUNT(*) AS count FROM http_mesh_batches WHERE source=");
                source_count.push_bind(envelope.source.as_str());
                let source_count:i64=source_count.build().fetch_one(&mut *transaction).await.map_err(sql_error)?.try_get("count").map_err(sql_error)?;
                if pending>=MAX_PENDING_BATCHES as i64 || bytes as u64+envelope.bytes>MAX_PENDING_BYTES || source_count>=MAX_SOURCE_BATCHES as i64 {return Ok(EnqueueOutcome::Full);}
                let body=serde_json::to_string(&envelope).map_err(json_error)?;
                let mut insert=QueryBuilder::<$database>::new("INSERT INTO http_mesh_batches(source,batch_id,target,digest,bytes,expires_at,pending,envelope_json) VALUES (");
                insert.push_bind(envelope.source.as_str()).push(",").push_bind(&envelope.batch_id).push(",").push_bind(envelope.target.as_str()).push(",").push_bind(&digest).push(",").push_bind(envelope.bytes as i64).push(",").push_bind(envelope.expires_at.timestamp_millis()).push(",TRUE,").push_bind(body).push(")");
                insert.build().execute(&mut *transaction).await.map_err(sql_error)?;
                let mut stats=QueryBuilder::<$database>::new("INSERT INTO http_mesh_stats(node_id,sent_bytes) VALUES (");
                stats.push_bind(envelope.source.as_str()).push(",").push_bind(envelope.bytes as i64).push(") ON CONFLICT(node_id) DO UPDATE SET sent_bytes=http_mesh_stats.sent_bytes+excluded.sent_bytes");
                stats.build().execute(&mut *transaction).await.map_err(sql_error)?;
                let mut target=QueryBuilder::<$database>::new("INSERT INTO http_mesh_stats(node_id) VALUES (");
                target.push_bind(envelope.target.as_str()).push(") ON CONFLICT(node_id) DO NOTHING");
                target.build().execute(&mut *transaction).await.map_err(sql_error)?;
                self.mesh_notify(&mut transaction,&envelope.target).await?;
                transaction.commit().await.map_err(sql_error)?;
                self.mesh_wakeups.wake(&envelope.target);
                Ok(EnqueueOutcome::Accepted)
            }

            async fn poll(&self,node:&NodeId,acknowledgements:&[MeshAck],now:chrono::DateTime<Utc>)->Result<Vec<MeshEnvelope>,ControlPlaneError>{
                let mut transaction=self.pool.begin().await.map_err(sql_error)?;
                self.mesh_lock(&mut transaction,node,node).await?;
                let mut received=0_i64;
                for ack in acknowledgements {
                    let mut update=QueryBuilder::<$database>::new("UPDATE http_mesh_batches SET pending=FALSE,envelope_json='' WHERE target=");
                    update.push_bind(node.as_str()).push(" AND source=").push_bind(ack.source.as_str()).push(" AND batch_id=").push_bind(&ack.batch_id).push(" AND pending=TRUE AND expires_at>").push_bind(now.timestamp_millis()).push(" RETURNING bytes");
                    if let Some(row)=update.build().fetch_optional(&mut *transaction).await.map_err(sql_error)? {received=received.saturating_add(row.try_get::<i64,_>("bytes").map_err(sql_error)?);}
                }
                let mut stats=QueryBuilder::<$database>::new("INSERT INTO http_mesh_stats(node_id,received_bytes,last_poll_at) VALUES (");
                stats.push_bind(node.as_str()).push(",").push_bind(received).push(",").push_bind(now.timestamp_millis()).push(") ON CONFLICT(node_id) DO UPDATE SET received_bytes=http_mesh_stats.received_bytes+excluded.received_bytes,last_poll_at=excluded.last_poll_at");
                stats.build().execute(&mut *transaction).await.map_err(sql_error)?;
                let mut query=QueryBuilder::<$database>::new("SELECT envelope_json FROM http_mesh_batches WHERE target=");
                query.push_bind(node.as_str()).push(" AND pending=TRUE AND expires_at>").push_bind(now.timestamp_millis()).push(" ORDER BY expires_at,batch_id LIMIT ").push_bind(MAX_RECEIVE_BATCHES as i64);
                let rows=query.build().fetch_all(&mut *transaction).await.map_err(sql_error)?;
                let result=rows.into_iter().map(|row|{
                    let body:String=row.try_get("envelope_json").map_err(sql_error)?;
                    serde_json::from_str::<MeshEnvelope>(&body).map_err(json_error)
                }).collect::<Result<Vec<_>,_>>()?;
                let mut lease=QueryBuilder::<$database>::new("UPDATE http_mesh_members SET expires_at=");lease.push_bind((now+chrono::Duration::minutes(5)).timestamp_millis()).push(" WHERE node_id=").push_bind(node.as_str());lease.build().execute(&mut *transaction).await.map_err(sql_error)?;
                transaction.commit().await.map_err(sql_error)?;
                Ok(result)
            }

            async fn stats(&self,nodes:&BTreeSet<NodeId>,now:chrono::DateTime<Utc>)->Result<Vec<MeshStats>,ControlPlaneError>{
                if nodes.is_empty(){return Ok(Vec::new());}
                let mut query=QueryBuilder::<$database>::new("SELECT s.node_id,s.sent_bytes,s.received_bytes,s.last_poll_at,COUNT(b.batch_id) AS pending_batches,CAST(COALESCE(SUM(b.bytes),0) AS BIGINT) AS pending_bytes FROM http_mesh_stats s LEFT JOIN http_mesh_batches b ON b.target=s.node_id AND b.pending=TRUE AND b.expires_at>");
                query.push_bind(now.timestamp_millis()).push(" WHERE s.node_id IN (");
                {let mut ids=query.separated(",");for node in nodes{ids.push_bind(node.as_str());}}
                query.push(") GROUP BY s.node_id,s.sent_bytes,s.received_bytes,s.last_poll_at ORDER BY s.node_id");
                query.build().fetch_all(&self.pool).await.map_err(sql_error)?.into_iter().map(|row|{
                    let timestamp:Option<i64>=row.try_get("last_poll_at").map_err(sql_error)?;
                    Ok(MeshStats{node_id:NodeId::from_string(row.try_get::<String,_>("node_id").map_err(sql_error)?),sent_bytes:row.try_get::<i64,_>("sent_bytes").map_err(sql_error)? as u64,received_bytes:row.try_get::<i64,_>("received_bytes").map_err(sql_error)? as u64,pending_bytes:row.try_get::<i64,_>("pending_bytes").map_err(sql_error)? as u64,pending_batches:row.try_get::<i64,_>("pending_batches").map_err(sql_error)? as u64,last_poll_at:timestamp.and_then(chrono::DateTime::from_timestamp_millis)})
                }).collect()
            }
            fn notifier(&self,node:&NodeId)->Arc<Notify>{self.mesh_wakeups.notifier(node)}
        }
    };
}
mesh_store!(SqliteControlPlaneStore, Sqlite, "NOT EXISTS (SELECT 1 FROM json_each(json_extract(n.record_json,'$.tags')) WHERE value='heteronetwork-stopped')");
mesh_store!(
    PostgresControlPlaneStore,
    Postgres,
    "NOT (n.record_json->'tags' ? 'heteronetwork-stopped')"
);
