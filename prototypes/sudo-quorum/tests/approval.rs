use ipars_host_authorization_prototype::{Challenge, HostPolicy, HostVerifier, Invocation};
use ipars_quorum::{frost, Manifest, Member};
use rand_core::OsRng;
use std::collections::{BTreeMap, BTreeSet};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn fixture() -> TestResult<(
    Manifest,
    Vec<frost::keys::KeyPackage>,
    HostPolicy,
    Invocation,
)> {
    let (shares, public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)?;
    let manifest = Manifest {
        schema_version: 1,
        cluster_id: "sudo-test".to_string(),
        epoch: 1,
        members: (1..=3)
            .map(|identifier| Member {
                node_id: format!("node-{identifier}"),
                identifier,
                endpoint: format!("http://127.0.0.1:{}", 19000 + identifier),
            })
            .collect(),
        public_key_package: public.serialize()?,
    };
    let keys = shares
        .into_values()
        .map(frost::keys::KeyPackage::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    let policy = HostPolicy {
        host_node_id: "host-a".to_string(),
        revision: [1; 32],
        environment: vec![b"LANG=C".to_vec()],
        allowed_executables: BTreeSet::from([b"/usr/bin/id".to_vec()]),
    };
    let invocation = Invocation {
        host_node_id: "host-a".to_string(),
        caller_uid: 1000,
        caller_gid: 1000,
        caller_groups: vec![1000],
        runas_uid: 0,
        runas_euid: 0,
        runas_gid: 0,
        runas_egid: 0,
        runas_groups: vec![0],
        executable: b"/usr/bin/id".to_vec(),
        executable_sha256: [2; 32],
        executable_device: 1,
        executable_inode: 2,
        argv: vec![b"id".to_vec(), b"-u".to_vec()],
        cwd: b"/".to_vec(),
        cwd_device: 1,
        cwd_inode: 1,
        environment: policy.environment.clone(),
        umask: 0o077,
    };
    Ok((manifest, keys, policy, invocation))
}

fn sign(
    manifest: &Manifest,
    keys: &[frost::keys::KeyPackage],
    challenge: &Challenge,
) -> TestResult<Vec<u8>> {
    let (na, ca) = frost::round1::commit(keys[0].signing_share(), &mut OsRng);
    let (nb, cb) = frost::round1::commit(keys[1].signing_share(), &mut OsRng);
    let a = *keys[0].identifier();
    let b = *keys[1].identifier();
    let package = frost::SigningPackage::new(
        BTreeMap::from([(a, ca), (b, cb)]),
        &challenge.signing_bytes(),
    );
    let sa = frost::round2::sign(&package, &na, &keys[0])?;
    let sb = frost::round2::sign(&package, &nb, &keys[1])?;
    Ok(frost::aggregate(
        &package,
        &BTreeMap::from([(a, sa), (b, sb)]),
        &manifest.public_keys()?,
    )?
    .serialize()?)
}

#[tokio::test]
async fn consumed_approval_survives_close_and_reopen() -> TestResult {
    let (manifest, keys, policy, invocation) = fixture()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger.sqlite");
    let verifier = HostVerifier::open(&path, manifest.clone(), policy.clone()).await?;
    let challenge = verifier.challenge(&invocation, 100).await?;
    let signature = sign(&manifest, &keys, &challenge)?;
    verifier
        .approve(&invocation, &challenge, &signature, 101)
        .await?;
    verifier.close().await;
    let verifier = HostVerifier::open(&path, manifest, policy).await?;
    assert!(verifier
        .approve(&invocation, &challenge, &signature, 102)
        .await
        .is_err());
    verifier.close().await;
    Ok(())
}

#[tokio::test]
async fn exact_host_ids_argv_cwd_environment_and_executable_are_bound() -> TestResult {
    let (manifest, keys, policy, original) = fixture()?;
    let dir = tempfile::tempdir()?;
    let verifier =
        HostVerifier::open(&dir.path().join("ledger.sqlite"), manifest.clone(), policy).await?;
    let challenge = verifier.challenge(&original, 100).await?;
    let signature = sign(&manifest, &keys, &challenge)?;
    let mut mutations = Vec::new();
    let mut value = original.clone();
    value.host_node_id = "host-b".into();
    mutations.push(value);
    let mut value = original.clone();
    value.caller_uid += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.runas_uid += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.runas_euid += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.runas_groups.push(1);
    mutations.push(value);
    let mut value = original.clone();
    value.argv.push(b"extra".to_vec());
    mutations.push(value);
    let mut value = original.clone();
    value.argv = vec![b"id -u".to_vec()];
    mutations.push(value);
    let mut value = original.clone();
    value.cwd = b"/tmp".to_vec();
    mutations.push(value);
    let mut value = original.clone();
    value.cwd_inode += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.executable_inode += 1;
    mutations.push(value);
    let mut value = original.clone();
    value.executable_sha256[0] ^= 1;
    mutations.push(value);
    let mut value = original.clone();
    value.environment[0] = b"LANG=en".to_vec();
    mutations.push(value);
    let mut value = original.clone();
    value.umask = 0;
    mutations.push(value);
    for mutation in mutations {
        assert!(verifier
            .approve(&mutation, &challenge, &signature, 101)
            .await
            .is_err());
    }
    verifier
        .approve(&original, &challenge, &signature, 101)
        .await?;
    verifier.close().await;
    Ok(())
}

#[tokio::test]
async fn independent_connections_cannot_consume_twice_and_revocation_denies() -> TestResult {
    let (manifest, keys, policy, invocation) = fixture()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger.sqlite");
    let a = HostVerifier::open(&path, manifest.clone(), policy.clone()).await?;
    let b = HostVerifier::open(&path, manifest.clone(), policy).await?;
    let challenge = a.challenge(&invocation, 100).await?;
    let signature = sign(&manifest, &keys, &challenge)?;
    let (ra, rb) = tokio::join!(
        a.approve(&invocation, &challenge, &signature, 101),
        b.approve(&invocation, &challenge, &signature, 101)
    );
    assert_ne!(ra.is_ok(), rb.is_ok());
    let challenge = a.challenge(&invocation, 102).await?;
    let signature = sign(&manifest, &keys, &challenge)?;
    assert!(b.revoke(challenge.nonce).await?);
    assert!(a
        .approve(&invocation, &challenge, &signature, 103)
        .await
        .is_err());
    a.close().await;
    b.close().await;
    Ok(())
}

#[tokio::test]
async fn invalid_signature_expiry_and_unknown_nonce_do_not_approve() -> TestResult {
    let (manifest, keys, policy, invocation) = fixture()?;
    let dir = tempfile::tempdir()?;
    let verifier =
        HostVerifier::open(&dir.path().join("ledger.sqlite"), manifest.clone(), policy).await?;
    let challenge = verifier.challenge(&invocation, 100).await?;
    let signature = sign(&manifest, &keys, &challenge)?;
    let mut bad = signature.clone();
    bad[0] ^= 1;
    assert!(verifier
        .approve(&invocation, &challenge, &bad, 101)
        .await
        .is_err());
    assert!(verifier
        .approve(&invocation, &challenge, &signature, 160)
        .await
        .is_err());
    assert!(verifier
        .approve(&invocation, &challenge, &signature, 99)
        .await
        .is_err());
    let mut unknown = challenge.clone();
    unknown.nonce[0] ^= 1;
    let unknown_signature = sign(&manifest, &keys, &unknown)?;
    assert!(verifier
        .approve(&invocation, &unknown, &unknown_signature, 101)
        .await
        .is_err());
    verifier
        .approve(&invocation, &challenge, &signature, 101)
        .await?;
    verifier.close().await;
    Ok(())
}

#[tokio::test]
async fn policy_changes_cannot_silently_replace_durable_anchor() -> TestResult {
    let (manifest, _, policy, invocation) = fixture()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ledger.sqlite");
    let verifier = HostVerifier::open(&path, manifest.clone(), policy.clone()).await?;
    verifier.challenge(&invocation, 100).await?;
    verifier.close().await;
    let mut changed = policy;
    changed.revision[0] ^= 1;
    assert!(HostVerifier::open(&path, manifest, changed).await.is_err());
    Ok(())
}

#[tokio::test]
async fn unbounded_or_nul_context_is_rejected() -> TestResult {
    let (manifest, _, policy, mut invocation) = fixture()?;
    let dir = tempfile::tempdir()?;
    let verifier = HostVerifier::open(&dir.path().join("ledger.sqlite"), manifest, policy).await?;
    invocation.argv.push(vec![b'x'; 65537]);
    assert!(verifier.challenge(&invocation, 100).await.is_err());
    invocation.argv = vec![b"id\0-u".to_vec()];
    assert!(verifier.challenge(&invocation, 100).await.is_err());
    verifier.close().await;
    Ok(())
}
