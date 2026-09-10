//! Coordinator for typed, host-attested sudo issuance only. No local execution.
use super::*;
use ipars_quorum::sudo::{
    SudoChallenge, SudoPolicy, SudoRound1Request, SudoRound2Request, SudoToken,
};
use std::future::Future;
use std::sync::Arc;

#[derive(Debug, Args)]
pub struct SudoIssueArgs {
    /// Locally trusted policy, including the frozen manifest and host attestation keys.
    #[arg(long)]
    policy: PathBuf,
    /// Host-signed challenge produced by the trusted root-local mechanism.
    #[arg(long)]
    challenge: PathBuf,
    #[arg(long)]
    requester_key: PathBuf,
    /// Private owner access-token file.
    #[arg(long)]
    oidc_token: PathBuf,
    #[arg(long)]
    token_out: PathBuf,
    #[command(flatten)]
    transport: TransportArgs,
}

trait Transport: Clone + Send + Sync + 'static {
    fn round1(
        &self,
        url: Url,
        request: SudoRound1Request,
    ) -> impl Future<Output = anyhow::Result<ipars_quorum::Round1Response>> + Send;
    fn round2(
        &self,
        url: Url,
        request: SudoRound2Request,
    ) -> impl Future<Output = anyhow::Result<Round2Response>> + Send;
}

#[derive(Clone)]
struct HttpTransport {
    client: reqwest::Client,
    token: Zeroizing<String>,
}

impl Transport for HttpTransport {
    async fn round1(
        &self,
        url: Url,
        request: SudoRound1Request,
    ) -> anyhow::Result<ipars_quorum::Round1Response> {
        post_round(&self.client, url, &self.token, &request).await
    }
    async fn round2(&self, url: Url, request: SudoRound2Request) -> anyhow::Result<Round2Response> {
        post_round(&self.client, url, &self.token, &request).await
    }
}

fn validate(
    policy: &SudoPolicy,
    challenge: &SudoChallenge,
    key: &ed25519_dalek::SigningKey,
    timestamp: u64,
) -> anyhow::Result<()> {
    challenge.validate(policy, timestamp)?;
    if challenge.grant.requester_public_key != key.verifying_key().to_bytes() {
        bail!("requester private key does not match host-attested sudo challenge");
    }
    Ok(())
}

fn verify_token(policy: &SudoPolicy, token: &SudoToken, timestamp: u64) -> anyhow::Result<()> {
    token.challenge.validate(policy, timestamp)?;
    let signature = frost::Signature::deserialize(&token.signature)
        .map_err(|_| anyhow::anyhow!("invalid sudo threshold signature"))?;
    policy
        .manifest
        .public_keys()?
        .verifying_key()
        .verify(&token.challenge.signing_bytes()?, &signature)
        .map_err(|_| anyhow::anyhow!("sudo threshold signature verification failed"))
}

async fn coordinate<T: Transport>(
    policy: SudoPolicy,
    challenge: SudoChallenge,
    key: ed25519_dalek::SigningKey,
    bounds: &TransportArgs,
    transport: T,
    clock: Arc<dyn Fn() -> anyhow::Result<u64> + Send + Sync>,
) -> anyhow::Result<SudoToken> {
    validate(&policy, &challenge, &key, clock()?)?;
    // Check every frozen endpoint before disclosing any owner credential.
    let endpoints = policy
        .manifest
        .members
        .iter()
        .map(|member| {
            let base = endpoint(&member.endpoint, bounds)?;
            Ok((
                member.identifier,
                exact_target(&base, "/v1/quorum/sudo/round1")?,
                exact_target(&base, "/v1/quorum/sudo/round2")?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let threshold = usize::from(policy.manifest.threshold());
    let policy = Arc::new(policy);
    let deadline = tokio::time::Instant::now()
        + Duration::from_secs(challenge.grant.expires_at.saturating_sub(clock()?).min(40));
    let permits = Arc::new(tokio::sync::Semaphore::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    for (identifier, first, second) in endpoints {
        let mut request = SudoRound1Request {
            identifier,
            challenge: challenge.clone(),
            requester_proof: Vec::new(),
        };
        request.requester_proof = key.sign(&request.proof_bytes()?).to_bytes().to_vec();
        let (transport, policy, clock, permits) = (
            transport.clone(),
            policy.clone(),
            clock.clone(),
            permits.clone(),
        );
        tasks.spawn(async move {
            let _permit = permits.acquire_owned().await?;
            request.challenge.validate(&policy, clock()?)?;
            let response = transport.round1(first, request.clone()).await?;
            request.challenge.validate(&policy, clock()?)?;
            if response.identifier != identifier || response.session_id == [0; 32] {
                bail!("sudo round-one response does not match frozen signer");
            }
            Ok::<_, anyhow::Error>((second, response))
        });
    }
    let mut selected = Vec::new();
    while selected.len() < threshold {
        match tokio::time::timeout_at(deadline, tasks.join_next()).await {
            Ok(Some(Ok(Ok(response)))) => selected.push(response),
            Ok(Some(_)) => continue,
            _ => break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    validate(&policy, &challenge, &key, clock()?)?;
    if selected.len() != threshold {
        bail!("frozen sudo majority unavailable; pending sessions expire automatically");
    }
    let mut commitments = BTreeMap::new();
    for (_, response) in &selected {
        let id = frost::Identifier::try_from(response.identifier)?;
        if commitments.insert(id, response.commitments).is_some() {
            bail!("duplicate sudo signer commitment");
        }
    }
    let package = frost::SigningPackage::new(commitments, &challenge.signing_bytes()?);
    let mut tasks = tokio::task::JoinSet::new();
    for (url, response) in selected {
        let mut request = SudoRound2Request {
            identifier: response.identifier,
            session_id: response.session_id,
            challenge: challenge.clone(),
            signing_package: package.clone(),
            requester_proof: Vec::new(),
        };
        request.requester_proof = key.sign(&request.proof_bytes()?).to_bytes().to_vec();
        let (transport, policy, clock) = (transport.clone(), policy.clone(), clock.clone());
        tasks.spawn(async move {
            request.challenge.validate(&policy, clock()?)?;
            let result = transport.round2(url, request.clone()).await?;
            request.challenge.validate(&policy, clock()?)?;
            Ok::<_, anyhow::Error>((response.identifier, result.signature_share))
        });
    }
    let mut shares = BTreeMap::new();
    while let Ok(Some(result)) = tokio::time::timeout_at(deadline, tasks.join_next()).await {
        if let Ok(Ok((identifier, share))) = result {
            shares.insert(frost::Identifier::try_from(identifier)?, share);
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    validate(&policy, &challenge, &key, clock()?)?;
    if shares.len() != threshold {
        bail!("sudo round two failed; commitments must not be reused");
    }
    let signature = frost::aggregate(&package, &shares, &policy.manifest.public_keys()?)
        .map_err(|_| anyhow::anyhow!("sudo threshold aggregation failed"))?;
    let token = SudoToken {
        challenge,
        signature: signature.serialize()?,
    };
    verify_token(&policy, &token, clock()?)?;
    Ok(token)
}

#[cfg(unix)]
struct StagedOutput {
    directory: File,
    name: PathBuf,
    cleanup: bool,
}
#[cfg(unix)]
impl Drop for StagedOutput {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = nix::unistd::unlinkat(
                &self.directory,
                &self.name,
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            );
        }
    }
}

#[cfg(unix)]
fn publication_parent(path: &Path) -> anyhow::Result<(File, PathBuf)> {
    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components: Vec<_> = absolute.components().collect();
    if components.len() < 2
        || components[0] != Component::RootDir
        || !components[1..]
            .iter()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        bail!("sudo output requires a file path without parent traversal");
    }
    let uid = nix::unistd::geteuid().as_raw();
    let mut directory = File::open("/")?;
    // Each checked descriptor anchors the next lookup, including the final parent.
    for (index, component) in components[1..].iter().enumerate() {
        let final_parent = index + 2 == components.len();
        let metadata = directory.metadata()?;
        let trusted_sticky_ancestor =
            !final_parent && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (metadata.mode() & 0o022 != 0 && !trusted_sticky_ancestor)
        {
            bail!("sudo output directory ancestry is not trusted");
        }
        let Component::Normal(name) = component else {
            bail!("invalid sudo output path");
        };
        if final_parent {
            return Ok((directory, PathBuf::from(name)));
        }
        directory = File::from(
            openat(
                &directory,
                Path::new(name),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .context("cannot open trusted sudo output directory")?,
        );
    }
    bail!("invalid sudo output path")
}

#[cfg(unix)]
fn publish(
    path: &Path,
    token: &SudoToken,
    before_publish: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use nix::fcntl::{openat, AtFlags, OFlag};
    use nix::sys::stat::Mode;
    use nix::unistd::{linkat, unlinkat, UnlinkatFlags};

    let (directory, output_name) = publication_parent(path)?;
    let mut random = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| anyhow::anyhow!("cannot generate sudo staging name"))?;
    let name = PathBuf::from(format!(".sudo-token-{}", URL_SAFE_NO_PAD.encode(random)));
    let file = File::from(
        openat(
            &directory,
            &name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .context("cannot create private sudo staging file")?,
    );
    let mut staging = StagedOutput {
        directory,
        name,
        cleanup: true,
    };
    write_json(file, token)?;
    before_publish()?;
    // All mutations stay within the pinned parent even if its pathname is replaced.
    linkat(
        &staging.directory,
        &staging.name,
        &staging.directory,
        &output_name,
        AtFlags::empty(),
    )
    .context("cannot publish private sudo token; output must not exist")?;
    unlinkat(
        &staging.directory,
        &staging.name,
        UnlinkatFlags::NoRemoveDir,
    )
    .context("cannot remove sudo token staging link")?;
    staging.cleanup = false;
    staging
        .directory
        .sync_all()
        .context("cannot sync sudo token directory")?;
    Ok(())
}

#[cfg(not(unix))]
fn publish(
    _path: &Path,
    _token: &SudoToken,
    _before_publish: impl FnOnce() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    bail!("private sudo publication requires Unix directory permission enforcement")
}

pub(super) async fn issue(args: SudoIssueArgs) -> anyhow::Result<()> {
    let policy: SudoPolicy = read_json(&args.policy, false)?;
    let challenge: SudoChallenge = read_json(&args.challenge, false)?;
    let key = requester_key(&args.requester_key)?;
    validate(&policy, &challenge, &key, now()?)?;
    if args.token_out.try_exists()? || std::fs::symlink_metadata(&args.token_out).is_ok() {
        bail!("sudo token output must not exist");
    }
    let transport = HttpTransport {
        client: http_client()?,
        token: oidc_token(&args.oidc_token)?,
    };
    let token = coordinate(
        policy.clone(),
        challenge,
        key,
        &args.transport,
        transport,
        Arc::new(now),
    )
    .await?;
    publish(&args.token_out, &token, || {
        verify_token(&policy, &token, now()?)
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ipars_quorum::sudo::{SudoGrant, SudoHostPolicy, SudoIdentity, SUDO_SCHEMA_VERSION};
    use ipars_quorum::SignerEngine;
    use std::os::unix::fs::MetadataExt;
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    };

    // Reproducible dealer material is confined to this in-memory test fixture.
    struct TestRng(u64);
    impl rand_core::CryptoRng for TestRng {}
    impl RngCore for TestRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct Mock {
        policy: SudoPolicy,
        engines: Arc<Mutex<BTreeMap<u16, SignerEngine>>>,
        time: Arc<AtomicU64>,
        requests: Arc<AtomicUsize>,
        available: u16,
        expire_round2: bool,
        wrong_identifier: bool,
    }
    impl Transport for Mock {
        async fn round1(
            &self,
            _: Url,
            request: SudoRound1Request,
        ) -> anyhow::Result<ipars_quorum::Round1Response> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            if request.identifier > self.available {
                bail!("offline");
            }
            let mut result = self
                .engines
                .lock()
                .map_err(|_| anyhow::anyhow!("test signer lock poisoned"))?
                .get_mut(&request.identifier)
                .context("missing test signer")?
                .round1_sudo(
                    &self.policy,
                    &request.challenge.grant.identity,
                    &request,
                    self.time.load(Ordering::SeqCst),
                )?;
            if self.wrong_identifier {
                result.identifier = 99;
            }
            Ok(result)
        }
        async fn round2(
            &self,
            _: Url,
            request: SudoRound2Request,
        ) -> anyhow::Result<Round2Response> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let signature_share = self
                .engines
                .lock()
                .map_err(|_| anyhow::anyhow!("test signer lock poisoned"))?
                .get_mut(&request.identifier)
                .context("missing test signer")?
                .round2_sudo(
                    &self.policy,
                    &request.challenge.grant.identity,
                    &request,
                    self.time.load(Ordering::SeqCst),
                )?;
            if self.expire_round2 {
                self.time.store(160, Ordering::SeqCst);
            }
            Ok(Round2Response { signature_share })
        }
    }

    fn fixture() -> anyhow::Result<(SudoPolicy, SudoChallenge, ed25519_dalek::SigningKey, Mock)> {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            TestRng(71),
        )?;
        let manifest = Manifest {
            schema_version: SCHEMA_VERSION,
            cluster_id: "sudo-cli-test".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://node-{identifier}.example.test"),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let host = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[22; 32]);
        let identity = SudoIdentity {
            issuer: "https://owner.example.test".into(),
            subject: "owner".into(),
        };
        let policy = SudoPolicy {
            schema_version: SUDO_SCHEMA_VERSION,
            manifest,
            hosts: BTreeMap::from([(
                "node-1".into(),
                SudoHostPolicy {
                    attestation_key_epoch: 1,
                    attestation_public_key: host.verifying_key().to_bytes(),
                    callers: BTreeMap::from([(1000, identity.clone())]),
                },
            )]),
        };
        let grant = SudoGrant {
            schema_version: SUDO_SCHEMA_VERSION,
            cluster_id: policy.manifest.cluster_id.clone(),
            host_node_id: "node-1".into(),
            caller_uid: 1000,
            runas_uid: 0,
            identity,
            attestation_key_epoch: 1,
            requester_public_key: key.verifying_key().to_bytes(),
            manifest_epoch: 1,
            manifest_digest: policy.manifest.digest()?,
            policy_digest: policy.digest()?,
            nonce: [23; 32],
            issued_at: 100,
            expires_at: 160,
        };
        let challenge = SudoChallenge {
            host_signature: host.sign(&grant.attestation_bytes()?).to_bytes().to_vec(),
            grant,
        };
        let engines = policy
            .manifest
            .members
            .iter()
            .map(|member| {
                let id = frost::Identifier::try_from(member.identifier)?;
                Ok((
                    member.identifier,
                    SignerEngine::new(
                        policy.manifest.clone(),
                        &member.node_id,
                        frost::keys::KeyPackage::try_from(shares[&id].clone())?,
                        16,
                        60,
                    )?,
                ))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let mock = Mock {
            policy: policy.clone(),
            engines: Arc::new(Mutex::new(engines)),
            time: Arc::new(AtomicU64::new(100)),
            requests: Arc::new(AtomicUsize::new(0)),
            available: 3,
            expire_round2: false,
            wrong_identifier: false,
        };
        Ok((policy, challenge, key, mock))
    }

    async fn run_mock(
        policy: SudoPolicy,
        challenge: SudoChallenge,
        key: ed25519_dalek::SigningKey,
        mock: Mock,
    ) -> anyhow::Result<SudoToken> {
        let time = mock.time.clone();
        coordinate(
            policy,
            challenge,
            key,
            &TransportArgs::default(),
            mock,
            Arc::new(move || Ok(time.load(Ordering::SeqCst))),
        )
        .await
    }

    #[tokio::test]
    async fn signed_majority_and_private_atomic_publication() -> anyhow::Result<()> {
        let (policy, challenge, key, mut mock) = fixture()?;
        mock.available = 2;
        let token = run_mock(policy.clone(), challenge, key, mock).await?;
        verify_token(&policy, &token, 100)?;
        let mut corrupt = token.clone();
        corrupt.signature[0] ^= 1;
        assert!(verify_token(&policy, &corrupt, 100).is_err());
        assert!(verify_token(&policy, &token, 160).is_err());
        let dir = std::env::temp_dir().canonicalize()?.join(format!(
            "sudo-cli-{}-{}",
            std::process::id(),
            URL_SAFE_NO_PAD.encode(token.signature.as_slice())
        ));
        std::fs::create_dir(&dir)?;
        let out = dir.join("token.json");
        publish(&out, &token, || Ok(()))?;
        assert_eq!(std::fs::metadata(&out)?.mode() & 0o777, 0o600);
        assert_eq!(read_json::<SudoToken>(&out, true)?, token);
        assert!(publish(&out, &corrupt, || Ok(())).is_err());
        assert_eq!(read_json::<SudoToken>(&out, true)?, token);
        assert!(publish(&dir.join("expired"), &token, || bail!("expired")).is_err());
        assert_eq!(std::fs::read_dir(&dir)?.count(), 1);
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    struct PublicationScratch(PathBuf);
    impl PublicationScratch {
        fn new() -> anyhow::Result<Self> {
            use std::os::unix::fs::DirBuilderExt;
            let mut nonce = [0; 32];
            OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| anyhow::anyhow!("cannot generate test directory name"))?;
            let path = std::env::temp_dir()
                .canonicalize()?
                .join(format!("sudo-publish-{}", URL_SAFE_NO_PAD.encode(nonce)));
            std::fs::DirBuilder::new().mode(0o700).create(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for PublicationScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn publication_rejects_writable_ancestry_and_symlinks() -> anyhow::Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let scratch = PublicationScratch::new()?;
        let (_, challenge, _, _) = fixture()?;
        let token = SudoToken {
            challenge,
            signature: vec![0; 64],
        };
        let parent = scratch.0.join("parent");
        let child = parent.join("child");
        std::fs::create_dir(&parent)?;
        std::fs::create_dir(&child)?;
        for mode in [0o777, 0o770, 0o1777] {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(mode))?;
            assert!(publish(&parent.join("token"), &token, || panic!(
                "untrusted parent admitted"
            ))
            .is_err());
            // Root-owned sticky ancestors follow the daemon's existing trust policy.
            if mode != 0o1777 || nix::unistd::geteuid().as_raw() != 0 {
                assert!(publish(&child.join("token"), &token, || panic!(
                    "untrusted ancestor admitted"
                ))
                .is_err());
            }
        }
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))?;
        let alias = scratch.0.join("alias");
        symlink(&parent, &alias)?;
        assert!(publish(&alias.join("token"), &token, || panic!(
            "symlink parent admitted"
        ))
        .is_err());
        assert!(publish(&child.join("../token"), &token, || panic!(
            "parent traversal admitted"
        ))
        .is_err());
        symlink("missing", parent.join("token"))?;
        assert!(publish(&parent.join("token"), &token, || Ok(())).is_err());
        assert_eq!(
            std::fs::read_link(parent.join("token"))?,
            PathBuf::from("missing")
        );
        assert_eq!(std::fs::read_dir(&parent)?.count(), 2);
        assert_eq!(std::fs::read_dir(&child)?.count(), 0);
        Ok(())
    }

    #[test]
    fn publication_pins_parent_during_substitution_and_cleanup() -> anyhow::Result<()> {
        use std::os::unix::fs::symlink;
        let (_, challenge, _, _) = fixture()?;
        let token = SudoToken {
            challenge,
            signature: vec![0; 64],
        };
        for substitute_symlink in [false, true] {
            for reject in [false, true] {
                let scratch = PublicationScratch::new()?;
                let parent = scratch.0.join("parent");
                let moved = scratch.0.join("moved");
                let replacement = scratch.0.join("replacement");
                std::fs::create_dir(&parent)?;
                std::fs::create_dir(&replacement)?;
                let result = publish(&parent.join("token"), &token, || {
                    let name = std::fs::read_dir(&parent)?
                        .next()
                        .context("missing staged file")??
                        .file_name();
                    std::fs::rename(&parent, &moved)?;
                    if substitute_symlink {
                        symlink(&replacement, &parent)?;
                    } else {
                        std::fs::rename(&replacement, &parent)?;
                    }
                    let mut marker = reserve_output(&parent.join(name))?;
                    marker.write_all(b"replacement must remain untouched")?;
                    if reject {
                        bail!("expired before publication");
                    }
                    Ok(())
                });
                assert_eq!(result.is_err(), reject);
                assert!(!parent.join("token").exists());
                let entries = std::fs::read_dir(&parent)?.collect::<std::io::Result<Vec<_>>>()?;
                assert_eq!(entries.len(), 1);
                assert_eq!(
                    read_file(&entries[0].path(), true)?,
                    b"replacement must remain untouched"
                );
                assert_eq!(std::fs::read_dir(&moved)?.count(), usize::from(!reject));
                if !reject {
                    assert_eq!(read_json::<SudoToken>(&moved.join("token"), true)?, token);
                    assert_eq!(
                        std::fs::metadata(moved.join("token"))?.mode() & 0o777,
                        0o600
                    );
                }
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_untrusted_challenges_before_network() -> anyhow::Result<()> {
        for case in 0..6 {
            let (mut policy, mut challenge, mut key, mock) = fixture()?;
            match case {
                0 => challenge.grant.host_node_id = "node-2".into(),
                1 => {
                    policy
                        .hosts
                        .get_mut("node-1")
                        .context("missing test host")?
                        .attestation_key_epoch = 2
                }
                2 => key = ed25519_dalek::SigningKey::from_bytes(&[99; 32]),
                3 => challenge.host_signature[0] ^= 1,
                4 => {
                    mock.time.store(160, Ordering::SeqCst);
                }
                _ => {
                    mock.time.store(99, Ordering::SeqCst);
                }
            }
            assert!(run_mock(policy, challenge, key, mock.clone())
                .await
                .is_err());
            assert_eq!(mock.requests.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }

    #[test]
    fn parses_only_typed_issuance_inputs() -> anyhow::Result<()> {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            command: QuorumCommand,
        }
        let cli = Cli::try_parse_from([
            "quorum",
            "sudo-issue",
            "--policy",
            "policy.json",
            "--challenge",
            "challenge.json",
            "--requester-key",
            "requester.key",
            "--oidc-token",
            "owner.token",
            "--token-out",
            "sudo.json",
        ])?;
        assert!(matches!(cli.command, QuorumCommand::SudoIssue(_)));
        assert!(Cli::try_parse_from(["quorum", "sudo-issue", "--command", "anything"]).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn validates_even_unavailable_frozen_endpoints_before_network() -> anyhow::Result<()> {
        let (mut policy, mut challenge, key, mut mock) = fixture()?;
        policy.manifest.members[2].endpoint = "http://203.0.113.1".into();
        challenge.grant.manifest_digest = policy.manifest.digest()?;
        challenge.grant.policy_digest = policy.digest()?;
        challenge.host_signature = ed25519_dalek::SigningKey::from_bytes(&[21; 32])
            .sign(&challenge.grant.attestation_bytes()?)
            .to_bytes()
            .to_vec();
        mock.available = 2;
        mock.policy = policy.clone();
        assert!(run_mock(policy, challenge, key, mock.clone())
            .await
            .is_err());
        assert_eq!(mock.requests.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn missing_majority_misbound_response_and_network_expiry_fail_closed(
    ) -> anyhow::Result<()> {
        for case in 0..3 {
            let (policy, challenge, key, mut mock) = fixture()?;
            match case {
                0 => mock.available = 1,
                1 => mock.wrong_identifier = true,
                _ => mock.expire_round2 = true,
            }
            assert!(run_mock(policy, challenge, key, mock).await.is_err());
        }
        Ok(())
    }
}
