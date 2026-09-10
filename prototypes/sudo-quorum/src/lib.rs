//! Non-executing sudo approval verifier prototype. No plugin, socket, PAM, or shell code.
//! All context supplied here must eventually come from a reviewed trusted sudo bridge.

use ipars_quorum::{frost, Manifest};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqlitePool,
};
use std::{collections::BTreeSet, path::Path, time::Duration};
use thiserror::Error;

pub const MAX_TTL: i64 = 60;
const MAX_PENDING: i64 = 1024;
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("host approval context rejected")]
    Context,
    #[error("host approval configuration rejected")]
    Configuration,
    #[error("host approval signature rejected")]
    Signature,
    #[error("host approval expired or clock invalid")]
    Time,
    #[error("host approval unavailable or already consumed")]
    Unavailable,
    #[error("host approval ledger unavailable")]
    Ledger,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Byte vectors preserve Unix argument/path bytes; no shell parsing or UTF-8 normalization.
/// Identity/content fields must be measured by the bridge, never trusted from the caller.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub host_node_id: String,
    pub caller_uid: u32,
    pub caller_gid: u32,
    pub caller_groups: Vec<u32>,
    pub runas_uid: u32,
    pub runas_euid: u32,
    pub runas_gid: u32,
    pub runas_egid: u32,
    pub runas_groups: Vec<u32>,
    pub executable: Vec<u8>,
    pub executable_sha256: [u8; 32],
    pub executable_device: u64,
    pub executable_inode: u64,
    pub argv: Vec<Vec<u8>>,
    pub cwd: Vec<u8>,
    pub cwd_device: u64,
    pub cwd_inode: u64,
    pub environment: Vec<Vec<u8>>,
    pub umask: u32,
}

/// Trusted, local configuration. No wildcard environment values or executable paths.
#[derive(Clone)]
pub struct HostPolicy {
    pub host_node_id: String,
    pub revision: [u8; 32],
    pub environment: Vec<Vec<u8>>,
    pub allowed_executables: BTreeSet<Vec<u8>>,
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn vector(out: &mut Vec<u8>, values: &[Vec<u8>]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        field(out, value);
    }
}

fn groups(out: &mut Vec<u8>, values: &[u32]) {
    out.extend_from_slice(&(values.len() as u64).to_be_bytes());
    for value in values {
        out.extend_from_slice(&value.to_be_bytes());
    }
}

impl HostPolicy {
    fn validate(&self, invocation: &Invocation) -> Result<()> {
        let path =
            |value: &[u8]| value.starts_with(b"/") && value.len() <= 4096 && !value.contains(&0);
        let total = invocation
            .argv
            .iter()
            .chain(&invocation.environment)
            .try_fold(0usize, |n, value| n.checked_add(value.len()))
            .ok_or(Error::Context)?;
        if invocation.host_node_id != self.host_node_id
            || self.host_node_id.is_empty()
            || self.host_node_id.len() > 256
            || self.revision == [0; 32]
            || !path(&invocation.executable)
            || !path(&invocation.cwd)
            || !self.allowed_executables.contains(&invocation.executable)
            || invocation.environment != self.environment
            || invocation.argv.is_empty()
            || invocation.argv.len() > 256
            || invocation.argv[0].is_empty()
            || invocation.environment.len() > 128
            || total > MAX_BYTES
            || invocation.umask > 0o777
            || invocation.caller_groups.len() > 256
            || invocation.runas_groups.len() > 256
            || invocation
                .argv
                .iter()
                .chain(&invocation.environment)
                .any(|value| value.contains(&0))
        {
            return Err(Error::Context);
        }
        let mut names = BTreeSet::new();
        for entry in &invocation.environment {
            let index = entry
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or(Error::Context)?;
            if index == 0 || !names.insert(&entry[..index]) {
                return Err(Error::Context);
            }
        }
        Ok(())
    }

    fn digest(&self, manifest: &Manifest) -> Result<[u8; 32]> {
        let mut bytes = b"heteronetwork-sudo-policy-v1\0".to_vec();
        field(
            &mut bytes,
            manifest
                .digest()
                .map_err(|_| Error::Configuration)?
                .as_bytes(),
        );
        field(&mut bytes, self.host_node_id.as_bytes());
        bytes.extend_from_slice(&self.revision);
        vector(&mut bytes, &self.environment);
        vector(
            &mut bytes,
            &self.allowed_executables.iter().cloned().collect::<Vec<_>>(),
        );
        Ok(Sha256::digest(bytes).into())
    }
}

impl Invocation {
    fn digest(&self) -> [u8; 32] {
        let mut bytes = b"heteronetwork-sudo-invocation-v1\0".to_vec();
        field(&mut bytes, self.host_node_id.as_bytes());
        for id in [
            self.caller_uid,
            self.caller_gid,
            self.runas_uid,
            self.runas_euid,
            self.runas_gid,
            self.runas_egid,
            self.umask,
        ] {
            bytes.extend_from_slice(&id.to_be_bytes());
        }
        groups(&mut bytes, &self.caller_groups);
        groups(&mut bytes, &self.runas_groups);
        field(&mut bytes, &self.executable);
        bytes.extend_from_slice(&self.executable_sha256);
        for value in [
            self.executable_device,
            self.executable_inode,
            self.cwd_device,
            self.cwd_inode,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        vector(&mut bytes, &self.argv);
        field(&mut bytes, &self.cwd);
        vector(&mut bytes, &self.environment);
        Sha256::digest(bytes).into()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub policy_digest: [u8; 32],
    pub invocation_digest: [u8; 32],
    pub nonce: [u8; 32],
    pub issued_at: i64,
    pub expires_at: i64,
}

impl Challenge {
    /// A different domain from HTTP admin claims; existing admin signatures cannot be reused.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = b"heteronetwork-sudo-approval-v1\0".to_vec();
        bytes.extend_from_slice(&self.policy_digest);
        bytes.extend_from_slice(&self.invocation_digest);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.issued_at.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes
    }
}

pub struct HostVerifier {
    manifest: Manifest,
    policy: HostPolicy,
    anchor: [u8; 32],
    pool: SqlitePool,
}

impl HostVerifier {
    /// Prototype trust boundary: caller must provision a private service-owned directory.
    /// This does not implement the production bridge's no-follow/ownership/path checks.
    pub async fn open(path: &Path, manifest: Manifest, policy: HostPolicy) -> Result<Self> {
        manifest.validate().map_err(|_| Error::Configuration)?;
        let anchor = policy.digest(&manifest)?;
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
        sqlx::query("CREATE TABLE IF NOT EXISTS host_anchor (id INTEGER PRIMARY KEY CHECK(id=1), digest BLOB NOT NULL)")
            .execute(&pool).await.map_err(|_| Error::Ledger)?;
        sqlx::query("INSERT OR IGNORE INTO host_anchor(id,digest) VALUES (1,?)")
            .bind(anchor.as_slice())
            .execute(&pool)
            .await
            .map_err(|_| Error::Ledger)?;
        let stored: Vec<u8> = sqlx::query_scalar("SELECT digest FROM host_anchor WHERE id=1")
            .fetch_one(&pool)
            .await
            .map_err(|_| Error::Ledger)?;
        if stored != anchor {
            pool.close().await;
            return Err(Error::Configuration);
        }
        sqlx::query("CREATE TABLE IF NOT EXISTS approvals (nonce BLOB PRIMARY KEY, digest BLOB NOT NULL, expires INTEGER NOT NULL, state INTEGER NOT NULL DEFAULT 0)")
            .execute(&pool).await.map_err(|_| Error::Ledger)?;
        Ok(Self {
            manifest,
            policy,
            anchor,
            pool,
        })
    }

    /// Only the trusted local bridge may request a challenge after sudoers approval.
    pub async fn challenge(&self, invocation: &Invocation, now: i64) -> Result<Challenge> {
        self.policy.validate(invocation)?;
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
        let challenge = Challenge {
            policy_digest: self.anchor,
            invocation_digest: invocation.digest(),
            nonce,
            issued_at: now,
            expires_at: now.checked_add(MAX_TTL).ok_or(Error::Time)?,
        };
        // Single writer statement makes the global capacity check and insert indivisible.
        // No GC in prototype: exhaustion fails closed rather than deleting replay evidence.
        let changed = sqlx::query("INSERT INTO approvals(nonce,digest,expires) SELECT ?,?,? WHERE (SELECT count(*) FROM approvals) < ?")
            .bind(nonce.as_slice()).bind(Sha256::digest(challenge.signing_bytes()).as_slice())
            .bind(challenge.expires_at).bind(MAX_PENDING).execute(&self.pool).await.map_err(|_| Error::Ledger)?;
        if changed.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        Ok(challenge)
    }

    /// Returns approval only. Never executes, spawns, connects to HTTP, or changes credentials.
    pub async fn approve(
        &self,
        invocation: &Invocation,
        challenge: &Challenge,
        signature: &[u8],
        now: i64,
    ) -> Result<()> {
        self.policy.validate(invocation)?;
        if challenge.policy_digest != self.anchor
            || challenge.invocation_digest != invocation.digest()
        {
            return Err(Error::Context);
        }
        if challenge.issued_at < 0
            || now < challenge.issued_at
            || now >= challenge.expires_at
            || challenge.expires_at.checked_sub(challenge.issued_at) != Some(MAX_TTL)
        {
            return Err(Error::Time);
        }
        let signature = frost::Signature::deserialize(signature).map_err(|_| Error::Signature)?;
        self.manifest
            .public_keys()
            .map_err(|_| Error::Configuration)?
            .verifying_key()
            .verify(&challenge.signing_bytes(), &signature)
            .map_err(|_| Error::Signature)?;
        let result = sqlx::query("UPDATE approvals SET state=1 WHERE nonce=? AND digest=? AND state=0 AND expires>? AND EXISTS (SELECT 1 FROM host_anchor WHERE id=1 AND digest=?)")
            .bind(challenge.nonce.as_slice()).bind(Sha256::digest(challenge.signing_bytes()).as_slice())
            .bind(now).bind(self.anchor.as_slice()).execute(&self.pool).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        Ok(())
    }

    /// Trusted local administrative revocation; never callable by an unauthenticated requester.
    pub async fn revoke(&self, nonce: [u8; 32]) -> Result<bool> {
        let result = sqlx::query("UPDATE approvals SET state=2 WHERE nonce=? AND state=0")
            .bind(nonce.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|_| Error::Ledger)?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}
