//! Local v2 lifecycle and durable ledger. No network issuance, generic signing or execution.
use crate::{Error, Result};
use ed25519_dalek::{Signer, SigningKey};
use ipars_quorum::{
    frost,
    sudo::{
        verify_sudo_redemption, SudoChallenge, SudoGrant, SudoLocalInvocation, SudoPolicy,
        SudoToken, VerifiedSudoGrant, MAX_SUDO_TTL_SECS, SUDO_SCHEMA_VERSION,
    },
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    SqliteConnection, SqlitePool,
};
use std::{
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Time)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalV2Config {
    pub host_node_id: String,
    pub policy: SudoPolicy,
}

/// Validate the same public policy and local attestation identity without opening state.
pub fn validate_local_config(config: &LocalV2Config, host_key: &SigningKey) -> Result<()> {
    config.policy.validate().map_err(|_| Error::Configuration)?;
    let host = config
        .policy
        .hosts
        .get(&config.host_node_id)
        .ok_or(Error::Configuration)?;
    if host_key.verifying_key().to_bytes() != host.attestation_public_key {
        return Err(Error::Configuration);
    }
    Ok(())
}

pub struct V2Verifier {
    config: LocalV2Config,
    host_key: SigningKey,
    anchor: [u8; 32],
    pool: SqlitePool,
}

/// Only a trusted root adapter can create this state; no deserialization or public fields.
pub struct V2Session {
    uid: u32,
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    challenge: Option<SudoChallenge>,
    redemption: Option<(SudoToken, SudoLocalInvocation)>,
}

impl V2Verifier {
    /// The embedding root service validates file provenance before this in-process API.
    pub async fn open(path: &Path, config: LocalV2Config, host_key: SigningKey) -> Result<Self> {
        validate_local_config(&config, &host_key)?;
        let mut binding = b"heteronetwork-local-sudo-v2-anchor\0".to_vec();
        binding.extend_from_slice(
            config
                .policy
                .digest()
                .map_err(|_| Error::Configuration)?
                .as_bytes(),
        );
        binding.extend_from_slice(config.host_node_id.as_bytes());
        let anchor: [u8; 32] = Sha256::digest(binding).into();
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
        let mut migration = pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error::Ledger)?;
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *migration)
            .await
            .map_err(|_| Error::Ledger)?;
        if !(0..=1).contains(&version) {
            return Err(Error::Configuration);
        }
        let tables: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
            .fetch_all(&mut *migration).await.map_err(|_| Error::Ledger)?;
        let fresh_database = version == 0 && tables.is_empty();
        let expected = if version == 0 {
            vec!["sudo_v2_anchor", "sudo_v2_invocations"]
        } else {
            vec!["sudo_v2_anchor", "sudo_v2_clock", "sudo_v2_invocations"]
        };
        if !fresh_database && tables != expected {
            return Err(Error::Configuration);
        }
        if version == 0 {
            sqlx::query("CREATE TABLE IF NOT EXISTS sudo_v2_anchor(id INTEGER PRIMARY KEY CHECK(id=1),digest BLOB NOT NULL)")
            .execute(&mut *migration).await.map_err(|_| Error::Ledger)?;
            if fresh_database {
                sqlx::query("INSERT INTO sudo_v2_anchor VALUES(1,?)")
                    .bind(&anchor[..])
                    .execute(&mut *migration)
                    .await
                    .map_err(|_| Error::Ledger)?;
            }
        }
        let stored: Vec<u8> = sqlx::query_scalar("SELECT digest FROM sudo_v2_anchor WHERE id=1")
            .fetch_one(&mut *migration)
            .await
            .map_err(|_| Error::Ledger)?;
        if stored != anchor {
            return Err(Error::Configuration);
        }
        if version == 0 {
            sqlx::query("CREATE TABLE IF NOT EXISTS sudo_v2_invocations(nonce BLOB PRIMARY KEY,uid INTEGER NOT NULL,expires INTEGER NOT NULL,challenge BLOB,redemption BLOB,consumed INTEGER NOT NULL DEFAULT 0)")
                .execute(&mut *migration).await.map_err(|_| Error::Ledger)?;
            // Legacy ledgers had no time floor: quarantine until every old grant expires.
            let last_expiry: i64 =
                sqlx::query_scalar("SELECT coalesce(max(expires),0) FROM sudo_v2_invocations")
                    .fetch_one(&mut *migration)
                    .await
                    .map_err(|_| Error::Ledger)?;
            let floor = i64::try_from(now()?)
                .map_err(|_| Error::Time)?
                .max(last_expiry);
            sqlx::query("CREATE TABLE sudo_v2_clock(id INTEGER PRIMARY KEY CHECK(id=1),floor INTEGER NOT NULL CHECK(floor>=0))")
                .execute(&mut *migration).await.map_err(|_| Error::Ledger)?;
            sqlx::query("INSERT INTO sudo_v2_clock VALUES(1,?)")
                .bind(floor)
                .execute(&mut *migration)
                .await
                .map_err(|_| Error::Ledger)?;
            sqlx::query("PRAGMA user_version=1")
                .execute(&mut *migration)
                .await
                .map_err(|_| Error::Ledger)?;
        } else {
            let _: i64 = sqlx::query_scalar("SELECT floor FROM sudo_v2_clock WHERE id=1")
                .fetch_one(&mut *migration)
                .await
                .map_err(|_| Error::Ledger)?;
            let _: i64 = sqlx::query_scalar("SELECT count(*) FROM sudo_v2_invocations")
                .fetch_one(&mut *migration)
                .await
                .map_err(|_| Error::Ledger)?;
        }
        migration.commit().await.map_err(|_| Error::Ledger)?;
        Ok(Self {
            config,
            host_key,
            anchor,
            pool,
        })
    }

    async fn observe_locked(connection: &mut SqliteConnection) -> Result<u64> {
        let fresh = now()?;
        let result = sqlx::query("UPDATE sudo_v2_clock SET floor=? WHERE id=1 AND floor<=?")
            .bind(i64::try_from(fresh).map_err(|_| Error::Time)?)
            .bind(i64::try_from(fresh).map_err(|_| Error::Time)?)
            .execute(connection)
            .await
            .map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Time);
        }
        Ok(fresh)
    }

    /// Persist a monotone wall-time floor; rollback blocks admission, never changes the clock.
    pub async fn observed_now(&self) -> Result<u64> {
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error::Ledger)?;
        let fresh = Self::observe_locked(&mut transaction).await?;
        transaction.commit().await.map_err(|_| Error::Ledger)?;
        let after = now()?;
        if after < fresh {
            return Err(Error::Time);
        }
        Ok(after)
    }

    pub async fn begin(&self, uid: u32, adapter_nonce: [u8; 32]) -> Result<V2Session> {
        let host = self
            .config
            .policy
            .hosts
            .get(&self.config.host_node_id)
            .ok_or(Error::Configuration)?;
        if adapter_nonce == [0; 32] || !host.callers.contains_key(&uid) {
            return Err(Error::Context);
        }
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error::Ledger)?;
        let issued_at = Self::observe_locked(&mut transaction).await?;
        // At most one capacity-sized batch; never delete an unexpired record or the anchor.
        sqlx::query("DELETE FROM sudo_v2_invocations WHERE nonce IN (SELECT nonce FROM sudo_v2_invocations WHERE expires<=? LIMIT 1024)")
            .bind(i64::try_from(issued_at).map_err(|_| Error::Time)?)
            .execute(&mut *transaction).await.map_err(|_| Error::Ledger)?;
        let expires_at = issued_at
            .checked_add(MAX_SUDO_TTL_SECS)
            .ok_or(Error::Time)?;
        let result = sqlx::query("INSERT INTO sudo_v2_invocations(nonce,uid,expires) SELECT ?,?,? WHERE (SELECT count(*) FROM sudo_v2_invocations)<1024 AND EXISTS(SELECT 1 FROM sudo_v2_anchor WHERE id=1 AND digest=?)")
            .bind(&adapter_nonce[..]).bind(uid).bind(i64::try_from(expires_at).map_err(|_| Error::Time)?)
            .bind(&self.anchor[..]).execute(&mut *transaction).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        transaction.commit().await.map_err(|_| Error::Ledger)?;
        if now()? < issued_at {
            return Err(Error::Time);
        }
        Ok(V2Session {
            uid,
            nonce: adapter_nonce,
            issued_at,
            expires_at,
            challenge: None,
            redemption: None,
        })
    }

    pub async fn bind_requester(
        &self,
        session: &mut V2Session,
        public_key: [u8; 32],
    ) -> Result<SudoChallenge> {
        if session.challenge.is_some() {
            return Err(Error::Unavailable);
        }
        let host = self
            .config
            .policy
            .hosts
            .get(&self.config.host_node_id)
            .ok_or(Error::Configuration)?;
        let grant = SudoGrant {
            schema_version: SUDO_SCHEMA_VERSION,
            cluster_id: self.config.policy.manifest.cluster_id.clone(),
            host_node_id: self.config.host_node_id.clone(),
            caller_uid: session.uid,
            runas_uid: 0,
            identity: host
                .callers
                .get(&session.uid)
                .ok_or(Error::Context)?
                .clone(),
            attestation_key_epoch: host.attestation_key_epoch,
            requester_public_key: public_key,
            manifest_epoch: self.config.policy.manifest.epoch,
            manifest_digest: self
                .config
                .policy
                .manifest
                .digest()
                .map_err(|_| Error::Configuration)?,
            policy_digest: self
                .config
                .policy
                .digest()
                .map_err(|_| Error::Configuration)?,
            nonce: session.nonce,
            issued_at: session.issued_at,
            expires_at: session.expires_at,
        };
        grant
            .validate(&self.config.policy, self.observed_now().await?)
            .map_err(|_| Error::Context)?;
        let challenge = SudoChallenge {
            host_signature: self
                .host_key
                .sign(&grant.attestation_bytes().map_err(|_| Error::Context)?)
                .to_bytes()
                .to_vec(),
            grant,
        };
        let digest = Sha256::digest(challenge.signing_bytes().map_err(|_| Error::Context)?);
        let result = sqlx::query("UPDATE sudo_v2_invocations SET challenge=? WHERE nonce=? AND uid=? AND consumed=0 AND challenge IS NULL AND EXISTS(SELECT 1 FROM sudo_v2_anchor WHERE id=1 AND digest=?)")
            .bind(&digest[..]).bind(&session.nonce[..]).bind(session.uid).bind(&self.anchor[..])
            .execute(&self.pool).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        session.challenge = Some(challenge.clone());
        challenge
            .validate(&self.config.policy, self.observed_now().await?)
            .map_err(|_| Error::Time)?;
        Ok(challenge)
    }

    pub async fn submit_token(
        &self,
        session: &mut V2Session,
        token: SudoToken,
    ) -> Result<SudoLocalInvocation> {
        if session.redemption.is_some() || session.challenge.as_ref() != Some(&token.challenge) {
            return Err(Error::Context);
        }
        token
            .challenge
            .validate(&self.config.policy, self.observed_now().await?)
            .map_err(|_| Error::Context)?;
        let signature =
            frost::Signature::deserialize(&token.signature).map_err(|_| Error::Signature)?;
        self.config
            .policy
            .manifest
            .public_keys()
            .map_err(|_| Error::Configuration)?
            .verifying_key()
            .verify(
                &token
                    .challenge
                    .signing_bytes()
                    .map_err(|_| Error::Context)?,
                &signature,
            )
            .map_err(|_| Error::Signature)?;
        let mut nonce = [0; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Unavailable)?;
        if nonce == [0; 32] || nonce == session.nonce {
            return Err(Error::Unavailable);
        }
        let invocation = SudoLocalInvocation {
            host_node_id: self.config.host_node_id.clone(),
            caller_uid: session.uid,
            runas_uid: 0,
            nonce,
            issued_at: self.observed_now().await?,
            expires_at: session.expires_at,
        };
        let digest = Sha256::digest(invocation.proof_bytes(&token).map_err(|_| Error::Context)?);
        let result = sqlx::query("UPDATE sudo_v2_invocations SET redemption=? WHERE nonce=? AND uid=? AND consumed=0 AND redemption IS NULL AND challenge IS NOT NULL AND EXISTS(SELECT 1 FROM sudo_v2_anchor WHERE id=1 AND digest=?)")
            .bind(&digest[..]).bind(&session.nonce[..]).bind(session.uid).bind(&self.anchor[..])
            .execute(&self.pool).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        token
            .challenge
            .validate(&self.config.policy, self.observed_now().await?)
            .map_err(|_| Error::Time)?;
        session.redemption = Some((token, invocation.clone()));
        Ok(invocation)
    }

    pub async fn consume(&self, session: &V2Session, proof: &[u8]) -> Result<VerifiedSudoGrant> {
        let (token, invocation) = session.redemption.as_ref().ok_or(Error::Unavailable)?;
        let verified =
            verify_sudo_redemption(&self.config.policy, token, invocation, proof, now()?)
                .map_err(|_| Error::Signature)?;
        let digest = Sha256::digest(invocation.proof_bytes(token).map_err(|_| Error::Context)?);
        let challenge = Sha256::digest(
            token
                .challenge
                .signing_bytes()
                .map_err(|_| Error::Context)?,
        );
        let mut transaction = self
            .pool
            .begin_with("BEGIN IMMEDIATE")
            .await
            .map_err(|_| Error::Ledger)?;
        let fresh = Self::observe_locked(&mut transaction).await?;
        verified.validate_at(fresh).map_err(|_| Error::Time)?;
        let result = sqlx::query("UPDATE sudo_v2_invocations SET consumed=1 WHERE nonce=? AND uid=? AND challenge=? AND redemption=? AND consumed=0 AND expires>? AND EXISTS(SELECT 1 FROM sudo_v2_anchor WHERE id=1 AND digest=?)")
            .bind(&session.nonce[..]).bind(session.uid).bind(&challenge[..]).bind(&digest[..])
            .bind(i64::try_from(fresh).map_err(|_| Error::Time)?).bind(&self.anchor[..])
            .execute(&mut *transaction).await.map_err(|_| Error::Ledger)?;
        if result.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        verified
            .validate_at(Self::observe_locked(&mut transaction).await?)
            .map_err(|_| Error::Time)?;
        transaction.commit().await.map_err(|_| Error::Ledger)?;
        verified
            .validate_at(self.observed_now().await?)
            .map_err(|_| Error::Time)?;
        Ok(verified)
    }

    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipars_quorum::{
        sudo::{SudoHostPolicy, SudoIdentity, SudoRound1Request, SudoRound2Request},
        Manifest, Member, SignerEngine,
    };
    use std::collections::BTreeMap;
    type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

    struct Fixture {
        config: LocalV2Config,
        host: SigningKey,
        requester: SigningKey,
        keys: Vec<frost::keys::KeyPackage>,
    }
    fn fixture() -> TestResult<Fixture> {
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "local-v2-test".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://node-{identifier}.example/"),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let host = SigningKey::generate(&mut OsRng);
        let policy = SudoPolicy {
            schema_version: 2,
            manifest,
            hosts: BTreeMap::from([(
                "node-1".into(),
                SudoHostPolicy {
                    attestation_key_epoch: 1,
                    attestation_public_key: host.verifying_key().to_bytes(),
                    callers: BTreeMap::from([(
                        1000,
                        SudoIdentity {
                            issuer: "https://id.example/realm".into(),
                            subject: "owner".into(),
                        },
                    )]),
                },
            )]),
        };
        Ok(Fixture {
            config: LocalV2Config {
                host_node_id: "node-1".into(),
                policy,
            },
            host,
            requester: SigningKey::generate(&mut OsRng),
            keys: shares
                .into_values()
                .map(frost::keys::KeyPackage::try_from)
                .collect::<std::result::Result<_, _>>()?,
        })
    }

    #[test]
    fn check_config_accepts_valid_identity_without_state() -> TestResult {
        let f = fixture()?;
        let directory = tempfile::tempdir()?;
        validate_local_config(&f.config, &f.host)?;
        assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn check_config_rejects_invalid_policy_and_key_before_ledger() -> TestResult {
        for mismatch in [false, true] {
            let mut f = fixture()?;
            if mismatch {
                f.host = SigningKey::generate(&mut OsRng);
            } else {
                f.config.policy.schema_version = 1;
            }
            assert!(validate_local_config(&f.config, &f.host).is_err());
            let directory = tempfile::tempdir()?;
            assert!(
                V2Verifier::open(&directory.path().join("sudo-v2.sqlite"), f.config, f.host)
                    .await
                    .is_err()
            );
            assert_eq!(std::fs::read_dir(directory.path())?.count(), 0);
        }
        Ok(())
    }

    #[test]
    fn check_config_rejects_unknown_host() -> TestResult {
        let mut f = fixture()?;
        f.config.host_node_id = "not-in-policy".into();
        assert!(validate_local_config(&f.config, &f.host).is_err());
        Ok(())
    }

    fn issue(f: &Fixture, challenge: SudoChallenge) -> TestResult<SudoToken> {
        issue_at(f, challenge, now()?)
    }

    fn issue_at(f: &Fixture, challenge: SudoChallenge, time: u64) -> TestResult<SudoToken> {
        let mut engines = Vec::new();
        let mut responses = Vec::new();
        let mut commitments = BTreeMap::new();
        for (member, key) in f.config.policy.manifest.members.iter().zip(&f.keys).take(2) {
            let mut engine = SignerEngine::new(
                f.config.policy.manifest.clone(),
                &member.node_id,
                key.clone(),
                1,
                30,
            )?;
            let mut request = SudoRound1Request {
                identifier: member.identifier,
                challenge: challenge.clone(),
                requester_proof: vec![],
            };
            request.requester_proof = f
                .requester
                .sign(&request.proof_bytes()?)
                .to_bytes()
                .to_vec();
            let response =
                engine.round1_sudo(&f.config.policy, &challenge.grant.identity, &request, time)?;
            commitments.insert(
                frost::Identifier::try_from(response.identifier)?,
                response.commitments,
            );
            responses.push(response);
            engines.push(engine);
        }
        let package = frost::SigningPackage::new(commitments, &challenge.signing_bytes()?);
        let mut shares = BTreeMap::new();
        for (engine, response) in engines.iter_mut().zip(responses) {
            let mut request = SudoRound2Request {
                identifier: response.identifier,
                session_id: response.session_id,
                challenge: challenge.clone(),
                signing_package: package.clone(),
                requester_proof: vec![],
            };
            request.requester_proof = f
                .requester
                .sign(&request.proof_bytes()?)
                .to_bytes()
                .to_vec();
            shares.insert(
                frost::Identifier::try_from(response.identifier)?,
                engine.round2_sudo(&f.config.policy, &challenge.grant.identity, &request, time)?,
            );
        }
        Ok(SudoToken {
            challenge,
            signature: frost::aggregate(
                &package,
                &shares,
                &f.config.policy.manifest.public_keys()?,
            )?
            .serialize()?,
        })
    }

    #[tokio::test]
    async fn expired_capacity_reused_without_reviving_old_token() -> TestResult {
        let f = fixture()?;
        let dir = tempfile::tempdir()?;
        let verifier =
            V2Verifier::open(&dir.path().join("ledger"), f.config.clone(), f.host.clone()).await?;
        let mut old = verifier.begin(1000, [8; 32]).await?;
        let mut challenge = verifier
            .bind_requester(&mut old, f.requester.verifying_key().to_bytes())
            .await?;
        // Historical signed grant, without waiting or altering the host clock.
        challenge.grant.issued_at = now()? - 120;
        challenge.grant.expires_at = challenge.grant.issued_at + 60;
        challenge.host_signature = f
            .host
            .sign(&challenge.grant.attestation_bytes()?)
            .to_bytes()
            .to_vec();
        let token = issue_at(&f, challenge.clone(), challenge.grant.issued_at)?;
        sqlx::query("UPDATE sudo_v2_invocations SET expires=? WHERE nonce=?")
            .bind(i64::try_from(challenge.grant.expires_at)?)
            .bind(&old.nonce[..])
            .execute(&verifier.pool)
            .await?;
        let mut tx = verifier.pool.begin().await?;
        for i in 0u32..1023 {
            let mut nonce = [9; 32];
            nonce[..4].copy_from_slice(&i.to_be_bytes());
            sqlx::query("INSERT INTO sudo_v2_invocations(nonce,uid,expires) VALUES(?,1000,?)")
                .bind(&nonce[..])
                .bind(i64::try_from(now()? + 60)?)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        let mut fresh = verifier.begin(1000, old.nonce).await?;
        verifier
            .bind_requester(&mut fresh, f.requester.verifying_key().to_bytes())
            .await?;
        assert!(verifier.submit_token(&mut fresh, token).await.is_err());
        assert!(verifier.begin(1000, [10; 32]).await.is_err()); // All 1024 are now live.
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sudo_v2_invocations")
            .fetch_one(&verifier.pool)
            .await?;
        assert_eq!(count, 1024);
        verifier.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn rollback_floor_survives_restart_and_blocks_gc_and_consumption() -> TestResult {
        let f = fixture()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger");
        let verifier = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        let mut session = verifier.begin(1000, [11; 32]).await?;
        let challenge = verifier
            .bind_requester(&mut session, f.requester.verifying_key().to_bytes())
            .await?;
        let token = issue(&f, challenge)?;
        let invocation = verifier.submit_token(&mut session, token.clone()).await?;
        let proof = f
            .requester
            .sign(&invocation.proof_bytes(&token)?)
            .to_bytes();
        sqlx::query("UPDATE sudo_v2_clock SET floor=?")
            .bind(i64::try_from(now()? + 120)?)
            .execute(&verifier.pool)
            .await?;
        sqlx::query("INSERT INTO sudo_v2_invocations(nonce,uid,expires) VALUES(?,1000,1)")
            .bind(&[12u8; 32][..])
            .execute(&verifier.pool)
            .await?;
        verifier.close().await;
        let reopened = V2Verifier::open(&path, f.config, f.host).await?;
        assert!(matches!(
            reopened.begin(1000, [13; 32]).await,
            Err(Error::Time)
        ));
        assert!(matches!(
            reopened.consume(&session, &proof).await,
            Err(Error::Time)
        ));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sudo_v2_invocations")
            .fetch_one(&reopened.pool)
            .await?;
        assert_eq!(count, 2);
        reopened.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn legacy_migration_quarantines_and_unknown_schema_is_not_reset() -> TestResult {
        let f = fixture()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger");
        let verifier = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        verifier.begin(1000, [14; 32]).await?;
        sqlx::query("DROP TABLE sudo_v2_clock")
            .execute(&verifier.pool)
            .await?;
        sqlx::query("PRAGMA user_version=0")
            .execute(&verifier.pool)
            .await?;
        verifier.close().await;
        let migrated = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        assert!(matches!(
            migrated.begin(1000, [15; 32]).await,
            Err(Error::Time)
        ));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sudo_v2_invocations")
            .fetch_one(&migrated.pool)
            .await?;
        assert_eq!(count, 1);
        sqlx::query("PRAGMA user_version=99")
            .execute(&migrated.pool)
            .await?;
        assert!(matches!(
            V2Verifier::open(&path, f.config, f.host).await,
            Err(Error::Configuration)
        ));
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&migrated.pool)
            .await?;
        assert_eq!(version, 99);
        sqlx::query("PRAGMA user_version=1")
            .execute(&migrated.pool)
            .await?;
        sqlx::query("DROP TABLE sudo_v2_clock")
            .execute(&migrated.pool)
            .await?;
        assert!(matches!(
            V2Verifier::open(&path, migrated.config.clone(), migrated.host_key.clone()).await,
            Err(Error::Configuration)
        ));
        sqlx::query("PRAGMA user_version=0")
            .execute(&migrated.pool)
            .await?;
        sqlx::query("DELETE FROM sudo_v2_anchor")
            .execute(&migrated.pool)
            .await?;
        assert!(
            V2Verifier::open(&path, migrated.config.clone(), migrated.host_key.clone())
                .await
                .is_err()
        );
        let anchors: i64 = sqlx::query_scalar("SELECT count(*) FROM sudo_v2_anchor")
            .fetch_one(&migrated.pool)
            .await?;
        assert_eq!(anchors, 0); // Missing durable anchors are never silently recreated.
        migrated.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn host_attestation_requester_binding_and_distinct_redemption_proof() -> TestResult {
        let f = fixture()?;
        let dir = tempfile::tempdir()?;
        let verifier =
            V2Verifier::open(&dir.path().join("ledger"), f.config.clone(), f.host.clone()).await?;
        assert!(verifier.begin(1001, [1; 32]).await.is_err());
        assert!(verifier.begin(1000, [0; 32]).await.is_err());
        let mut session = verifier.begin(1000, [2; 32]).await?;
        let challenge = verifier
            .bind_requester(&mut session, f.requester.verifying_key().to_bytes())
            .await?;
        challenge.validate(&f.config.policy, now()?)?;
        assert_eq!(challenge.grant.caller_uid, 1000);
        assert_eq!(challenge.grant.host_node_id, "node-1");
        assert!(verifier
            .bind_requester(&mut session, f.host.verifying_key().to_bytes())
            .await
            .is_err());
        let token = issue(&f, challenge)?;
        let mut bad = token.clone();
        bad.signature[0] ^= 1;
        assert!(verifier.submit_token(&mut session, bad).await.is_err());
        let invocation = verifier.submit_token(&mut session, token.clone()).await?;
        assert_ne!(invocation.nonce, token.challenge.grant.nonce);
        assert!(invocation.expires_at <= token.challenge.grant.expires_at);
        assert!(verifier
            .submit_token(&mut session, token.clone())
            .await
            .is_err());
        let mut substituted = invocation.clone();
        substituted.nonce[0] ^= 1;
        let wrong = f
            .requester
            .sign(&substituted.proof_bytes(&token)?)
            .to_bytes();
        assert!(verifier.consume(&session, &wrong).await.is_err());
        let proof = f
            .requester
            .sign(&invocation.proof_bytes(&token)?)
            .to_bytes();
        let verified = verifier.consume(&session, &proof).await?;
        assert_eq!(verified.invocation(), &invocation);
        assert!(verifier.consume(&session, &proof).await.is_err());
        verifier.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_consumption_reopen_and_anchor_key_checks() -> TestResult {
        let f = fixture()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger");
        assert!(
            V2Verifier::open(&path, f.config.clone(), f.requester.clone())
                .await
                .is_err()
        );
        assert!(!path.exists());
        let a = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        let b = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        let mut session = a.begin(1000, [3; 32]).await?;
        let challenge = a
            .bind_requester(&mut session, f.requester.verifying_key().to_bytes())
            .await?;
        let token = issue(&f, challenge)?;
        let invocation = a.submit_token(&mut session, token.clone()).await?;
        let proof = f
            .requester
            .sign(&invocation.proof_bytes(&token)?)
            .to_bytes();
        let (left, right) = tokio::join!(a.consume(&session, &proof), b.consume(&session, &proof));
        assert_ne!(left.is_ok(), right.is_ok());
        a.close().await;
        b.close().await;
        let reopened = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        assert!(reopened.begin(1000, [3; 32]).await.is_err());
        assert!(reopened.consume(&session, &proof).await.is_err());
        reopened.close().await;
        let mut changed = f.config.clone();
        changed
            .policy
            .hosts
            .get_mut("node-1")
            .ok_or("host missing")?
            .attestation_key_epoch += 1;
        assert!(V2Verifier::open(&path, changed, f.host).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn redemption_expiring_while_writer_lock_held_never_admits() -> TestResult {
        use sqlx::{sqlite::SqliteConnection, Connection};
        let f = fixture()?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("ledger");
        let verifier = V2Verifier::open(&path, f.config.clone(), f.host.clone()).await?;
        let mut session = verifier.begin(1000, [4; 32]).await?;
        let challenge = verifier
            .bind_requester(&mut session, f.requester.verifying_key().to_bytes())
            .await?;
        let token = issue(&f, challenge)?;
        let mut invocation = verifier.submit_token(&mut session, token.clone()).await?;
        // Shorten only this test's local redemption lifetime; update its durable exact digest.
        while SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .subsec_millis()
            >= 100
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        invocation.expires_at = now()? + 1;
        let digest = Sha256::digest(invocation.proof_bytes(&token)?);
        sqlx::query("UPDATE sudo_v2_invocations SET redemption=? WHERE nonce=?")
            .bind(&digest[..])
            .bind(&session.nonce[..])
            .execute(&verifier.pool)
            .await?;
        session.redemption = Some((token.clone(), invocation.clone()));
        let proof = f
            .requester
            .sign(&invocation.proof_bytes(&token)?)
            .to_bytes();
        let mut blocker =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path)).await?;
        let lock = blocker.begin_with("BEGIN IMMEDIATE").await?;
        let consume = verifier.consume(&session, &proof);
        tokio::pin!(consume);
        tokio::select! {
            _ = &mut consume => return Err("consume completed while writer lock held".into()),
            _ = tokio::time::sleep(Duration::from_millis(50)) => (),
        }
        let expiry = UNIX_EPOCH + Duration::from_secs(invocation.expires_at);
        if let Ok(remaining) = expiry.duration_since(SystemTime::now()) {
            tokio::time::sleep(remaining + Duration::from_millis(50)).await;
        }
        lock.rollback().await?;
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), &mut consume).await?,
            Err(Error::Time)
        ));
        let consumed: i64 =
            sqlx::query_scalar("SELECT consumed FROM sudo_v2_invocations WHERE nonce=?")
                .bind(&session.nonce[..])
                .fetch_one(&mut blocker)
                .await?;
        assert_eq!(consumed, 0);
        blocker.close().await?;
        Ok(())
    }
}
