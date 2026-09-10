//! One-use sudo privilege authority, deliberately NOT exact-command authorization.
use crate::{field, Error, Result, MAX_TTL};
use ipars_quorum::{frost, Manifest};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegePolicy {
    pub host_node_id: String,
    pub manifest: Manifest,
    /// Frozen local UID to pinned owner-subject mapping; no user-controlled lookup.
    pub owners: BTreeMap<u32, String>,
}

impl PrivilegePolicy {
    fn digest(&self) -> Result<[u8; 32]> {
        self.manifest.validate().map_err(|_| Error::Configuration)?;
        if self.host_node_id.is_empty()
            || self.host_node_id.len() > 256
            || !self
                .manifest
                .members
                .iter()
                .any(|member| member.node_id == self.host_node_id)
            || self.owners.is_empty()
            || self.owners.len() > 256
            || self
                .owners
                .iter()
                .any(|(uid, subject)| *uid == 0 || subject.is_empty() || subject.len() > 256)
        {
            return Err(Error::Configuration);
        }
        let mut bytes = b"heteronetwork-sudo-privilege-policy-v1\0".to_vec();
        field(
            &mut bytes,
            &serde_json::to_vec(self).map_err(|_| Error::Configuration)?,
        );
        Ok(Sha256::digest(bytes).into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeGrant {
    pub scope: String,
    pub host_node_id: String,
    pub caller_uid: u32,
    pub owner_subject: String,
    pub runas_uid: u32,
    pub epoch: u64,
    pub manifest_digest: String,
    pub policy_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}

impl PrivilegeGrant {
    pub(crate) fn check_current_time(&self) -> Result<i64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Time)?;
        let now = i64::try_from(now.as_secs()).map_err(|_| Error::Time)?;
        if self.issued_at < 0
            || now < self.issued_at
            || now >= self.expires_at
            || self.expires_at.checked_sub(self.issued_at) != Some(MAX_TTL)
        {
            return Err(Error::Time);
        }
        Ok(now)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = b"heteronetwork-sudo-privilege-grant-v1\0".to_vec();
        for value in [
            &self.scope,
            &self.host_node_id,
            &self.owner_subject,
            &self.manifest_digest,
        ] {
            field(&mut out, value.as_bytes());
        }
        out.extend_from_slice(&self.caller_uid.to_be_bytes());
        out.extend_from_slice(&self.runas_uid.to_be_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPrivilegeGrant {
    pub grant: PrivilegeGrant,
    pub signature: Vec<u8>,
}

pub struct PrivilegeVerifier {
    policy: PrivilegePolicy,
    anchor: [u8; 32],
    pool: SqlitePool,
}

impl PrivilegeVerifier {
    /// Library callers supply trusted metadata. The root daemon additionally checks filesystem provenance.
    pub async fn open(path: &Path, policy: PrivilegePolicy) -> Result<Self> {
        let anchor = policy.digest()?;
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(2));
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(3))
            .connect_with(options)
            .await
            .map_err(|_| Error::Ledger)?;
        sqlx::query("CREATE TABLE IF NOT EXISTS privilege_anchor(id INTEGER PRIMARY KEY CHECK(id=1), digest BLOB NOT NULL)")
            .execute(&pool).await.map_err(|_| Error::Ledger)?;
        sqlx::query("INSERT OR IGNORE INTO privilege_anchor VALUES(1,?)")
            .bind(anchor.as_slice())
            .execute(&pool)
            .await
            .map_err(|_| Error::Ledger)?;
        let stored: Vec<u8> = sqlx::query_scalar("SELECT digest FROM privilege_anchor WHERE id=1")
            .fetch_one(&pool)
            .await
            .map_err(|_| Error::Ledger)?;
        if stored != anchor {
            pool.close().await;
            return Err(Error::Configuration);
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS privilege_grants(nonce BLOB PRIMARY KEY,digest BLOB NOT NULL,expires INTEGER NOT NULL,consumed INTEGER NOT NULL DEFAULT 0)")
            .execute(&pool).await.map_err(|_| Error::Ledger)?;
        Ok(Self {
            policy,
            anchor,
            pool,
        })
    }

    pub async fn challenge(&self, caller_uid: u32, now: i64) -> Result<PrivilegeGrant> {
        let subject = self.policy.owners.get(&caller_uid).ok_or(Error::Context)?;
        if now < 0 {
            return Err(Error::Time);
        }
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable)?;
        if nonce == [0; 32] {
            return Err(Error::Unavailable);
        }
        let grant = PrivilegeGrant {
            scope: "sudo".into(),
            host_node_id: self.policy.host_node_id.clone(),
            caller_uid,
            owner_subject: subject.clone(),
            runas_uid: 0,
            epoch: self.policy.manifest.epoch,
            manifest_digest: self
                .policy
                .manifest
                .digest()
                .map_err(|_| Error::Configuration)?,
            policy_digest: self.anchor,
            nonce,
            issued_at: now,
            expires_at: now.checked_add(MAX_TTL).ok_or(Error::Time)?,
        };
        let result = sqlx::query("INSERT INTO privilege_grants(nonce,digest,expires) SELECT ?,?,? WHERE (SELECT count(*) FROM privilege_grants)<1024 AND EXISTS(SELECT 1 FROM privilege_anchor WHERE id=1 AND digest=?)")
            .bind(nonce.as_slice()).bind(Sha256::digest(grant.signing_bytes()).as_slice()).bind(grant.expires_at)
            .bind(self.anchor.as_slice()).execute(&self.pool).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        Ok(grant)
    }

    pub async fn consume(&self, caller_uid: u32, signed: &SignedPrivilegeGrant) -> Result<()> {
        let grant = &signed.grant;
        if grant.scope != "sudo"
            || grant.host_node_id != self.policy.host_node_id
            || grant.runas_uid != 0
            || grant.caller_uid != caller_uid
            || self.policy.owners.get(&caller_uid) != Some(&grant.owner_subject)
            || grant.epoch != self.policy.manifest.epoch
            || grant.policy_digest != self.anchor
            || grant.manifest_digest
                != self
                    .policy
                    .manifest
                    .digest()
                    .map_err(|_| Error::Configuration)?
        {
            return Err(Error::Context);
        }
        grant.check_current_time()?;
        let signature =
            frost::Signature::deserialize(&signed.signature).map_err(|_| Error::Signature)?;
        self.policy
            .manifest
            .public_keys()
            .map_err(|_| Error::Configuration)?
            .verifying_key()
            .verify(&grant.signing_bytes(), &signature)
            .map_err(|_| Error::Signature)?;
        // Acquire both a pooled connection and SQLite's writer lock before sampling time.
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error::Ledger)?;
        let now = grant.check_current_time()?;
        let result = sqlx::query("UPDATE privilege_grants SET consumed=1 WHERE nonce=? AND digest=? AND consumed=0 AND expires>? AND EXISTS(SELECT 1 FROM privilege_anchor WHERE id=1 AND digest=?)")
            .bind(grant.nonce.as_slice()).bind(Sha256::digest(grant.signing_bytes()).as_slice()).bind(now)
            .bind(self.anchor.as_slice()).execute(&mut *transaction).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        grant.check_current_time()?;
        transaction.commit().await.map_err(|_| Error::Ledger)?;
        // A slow durable commit may burn the grant, but must not admit after expiry.
        grant.check_current_time()?;
        Ok(())
    }
    pub async fn close(self) {
        self.pool.close().await;
    }
}
