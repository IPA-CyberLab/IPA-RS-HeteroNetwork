use ipars_host_authorization_prototype::privilege::{
    PrivilegeGrant, PrivilegePolicy, PrivilegeVerifier, SignedPrivilegeGrant,
};
use ipars_quorum::{frost, Manifest, Member};
use rand_core::OsRng;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn now() -> TestResult<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn fixture() -> TestResult<(PrivilegePolicy, Vec<frost::keys::KeyPackage>)> {
    let (shares, public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)?;
    let manifest = Manifest {
        schema_version: 1,
        cluster_id: "sudo-privilege-test".into(),
        epoch: 1,
        members: (1..=3)
            .map(|identifier| Member {
                node_id: format!("node-{identifier}"),
                identifier,
                endpoint: format!("https://signer-{identifier}.example/"),
            })
            .collect(),
        public_key_package: public.serialize()?,
    };
    let keys = shares
        .into_values()
        .map(frost::keys::KeyPackage::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((
        PrivilegePolicy {
            host_node_id: "node-1".into(),
            manifest,
            owners: BTreeMap::from([(1000, "pinned-owner".into())]),
        },
        keys,
    ))
}

fn sign(
    policy: &PrivilegePolicy,
    keys: &[frost::keys::KeyPackage],
    grant: PrivilegeGrant,
) -> TestResult<SignedPrivilegeGrant> {
    let (a, ca) = frost::round1::commit(keys[0].signing_share(), &mut OsRng);
    let (b, cb) = frost::round1::commit(keys[1].signing_share(), &mut OsRng);
    let ia = *keys[0].identifier();
    let ib = *keys[1].identifier();
    let package =
        frost::SigningPackage::new(BTreeMap::from([(ia, ca), (ib, cb)]), &grant.signing_bytes());
    let signature = frost::aggregate(
        &package,
        &BTreeMap::from([
            (ia, frost::round2::sign(&package, &a, &keys[0])?),
            (ib, frost::round2::sign(&package, &b, &keys[1])?),
        ]),
        &policy.manifest.public_keys()?,
    )?
    .serialize()?;
    Ok(SignedPrivilegeGrant { grant, signature })
}

#[tokio::test]
async fn scoped_grants_reject_host_uid_owner_epoch_scope_and_expiry() -> TestResult {
    let (policy, keys) = fixture()?;
    let dir = tempfile::tempdir()?;
    let verifier = PrivilegeVerifier::open(&dir.path().join("ledger"), policy.clone()).await?;
    assert!(verifier.challenge(0, 100).await.is_err());
    assert!(verifier.challenge(1001, 100).await.is_err());
    let grant = verifier.challenge(1000, now()?).await?;
    for change in 0..7 {
        let mut altered = grant.clone();
        match change {
            0 => altered.host_node_id = "host-b".into(),
            1 => altered.caller_uid = 1001,
            2 => altered.owner_subject = "different-owner".into(),
            3 => altered.epoch += 1,
            4 => altered.scope = "http-admin".into(),
            5 => altered.runas_uid = 1001,
            _ => altered.nonce[0] ^= 1,
        }
        // Even a cryptographically valid majority signature cannot alter the local challenge.
        let signed = sign(&policy, &keys, altered)?;
        assert!(verifier.consume(1000, &signed).await.is_err());
    }
    let signed = sign(&policy, &keys, grant)?;
    let expired = sign(&policy, &keys, verifier.challenge(1000, now()? - 60).await?)?;
    assert!(verifier.consume(1000, &expired).await.is_err());
    let future = sign(&policy, &keys, verifier.challenge(1000, now()? + 60).await?)?;
    assert!(verifier.consume(1000, &future).await.is_err());
    assert!(verifier.consume(1001, &signed).await.is_err());
    verifier.consume(1000, &signed).await?;
    verifier.close().await;
    Ok(())
}

#[tokio::test]
async fn concurrent_consumption_and_restart_never_replay() -> TestResult {
    let (policy, keys) = fixture()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let a = PrivilegeVerifier::open(&path, policy.clone()).await?;
    let b = PrivilegeVerifier::open(&path, policy.clone()).await?;
    let signed = sign(&policy, &keys, a.challenge(1000, now()?).await?)?;
    let (ra, rb) = tokio::join!(a.consume(1000, &signed), b.consume(1000, &signed));
    assert_ne!(ra.is_ok(), rb.is_ok());
    a.close().await;
    b.close().await;
    let c = PrivilegeVerifier::open(&path, policy).await?;
    assert!(c.consume(1000, &signed).await.is_err());
    c.close().await;
    Ok(())
}

#[tokio::test]
async fn expiry_during_sqlite_writer_contention_rejects_without_consuming() -> TestResult {
    use sqlx::{
        sqlite::{SqliteConnectOptions, SqliteConnection},
        Connection,
    };
    let (policy, keys) = fixture()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let verifier = PrivilegeVerifier::open(&path, policy.clone()).await?;
    let mut blocker =
        SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path)).await?;
    // Start near a second boundary so expiry is comfortably inside the 2s busy timeout.
    tokio::time::timeout(Duration::from_secs(2), async {
        while SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .subsec_millis()
            >= 100
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    })
    .await??;
    let signed = sign(&policy, &keys, verifier.challenge(1000, now()? - 59).await?)?;
    let lock = blocker.begin_with("BEGIN IMMEDIATE").await?;
    assert!(
        now()? < signed.grant.expires_at,
        "fixture must begin unexpired"
    );
    let consume = verifier.consume(1000, &signed);
    tokio::pin!(consume);
    tokio::select! {
        _ = &mut consume => return Err("consume completed while the writer lock was held".into()),
        _ = tokio::time::sleep(Duration::from_millis(50)) => (),
    }
    let expiry = UNIX_EPOCH + Duration::from_secs(signed.grant.expires_at.try_into()?);
    if let Ok(remaining) = expiry.duration_since(SystemTime::now()) {
        tokio::time::sleep(remaining + Duration::from_millis(50)).await;
    }
    assert!(now()? >= signed.grant.expires_at);
    lock.rollback().await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(3), &mut consume).await?,
        Err(ipars_host_authorization_prototype::Error::Time)
    ));
    let consumed: i64 = sqlx::query_scalar("SELECT consumed FROM privilege_grants WHERE nonce=?")
        .bind(signed.grant.nonce.as_slice())
        .fetch_one(&mut blocker)
        .await?;
    assert_eq!(consumed, 0);
    blocker.close().await?;
    Ok(())
}

#[tokio::test]
async fn foreign_host_policy_is_rejected_before_ledger_creation() -> TestResult {
    let (mut policy, _) = fixture()?;
    policy.host_node_id = "foreign-host".into();
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    assert!(matches!(
        PrivilegeVerifier::open(&path, policy).await,
        Err(ipars_host_authorization_prototype::Error::Configuration)
    ));
    assert!(!path.exists());
    Ok(())
}

#[tokio::test]
async fn frozen_mapping_manifest_and_domain_are_not_interchangeable() -> TestResult {
    let (policy, keys) = fixture()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger");
    let verifier = PrivilegeVerifier::open(&path, policy.clone()).await?;
    let signed = sign(&policy, &keys, verifier.challenge(1000, now()?).await?)?;
    assert!(signed
        .grant
        .signing_bytes()
        .starts_with(b"heteronetwork-sudo-privilege-grant-v1\0"));
    let mut bad = signed.clone();
    bad.signature[0] ^= 1;
    assert!(verifier.consume(1000, &bad).await.is_err());
    verifier.close().await;
    let mut changed = policy.clone();
    changed.owners.insert(1000, "replacement".into());
    assert!(PrivilegeVerifier::open(&path, changed).await.is_err());
    let mut changed = policy;
    changed.manifest.epoch += 1;
    assert!(PrivilegeVerifier::open(&path, changed).await.is_err());
    Ok(())
}
