//! Approval client only; the fixed root-local service owns invocation and execution state.
use super::*;
#[cfg(unix)]
use ipars_quorum::sudo::local::{Operation, Reply, Request, Response, PROTOCOL_VERSION};
#[cfg(unix)]
use ipars_quorum::sudo::verify_sudo_redemption;

#[derive(Debug, Args)]
pub struct SudoApproveArgs {
    /// Invocation handle emitted by the sudo-v2 plugin (64 hexadecimal characters).
    #[arg(long, value_parser = parse_handle)]
    handle: [u8; 32],
    #[arg(long)]
    policy: PathBuf,
    #[arg(long)]
    requester_key: PathBuf,
    #[arg(long)]
    oidc_token: PathBuf,
    #[command(flatten)]
    transport: TransportArgs,
}

fn parse_handle(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("sudo handle must contain exactly 64 hexadecimal characters".into());
    }
    let mut nonce = [0; 32];
    for (index, byte) in nonce.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid sudo handle".to_string())?;
    }
    if nonce == [0; 32] {
        return Err("sudo handle must be nonzero".into());
    }
    Ok(nonce)
}

#[cfg(unix)]
fn original_uid(real: u32, effective: u32) -> anyhow::Result<u32> {
    if real == 0 || real != effective {
        bail!("sudo approval requires the original non-root user, without changed effective UID");
    }
    Ok(real)
}

#[cfg(unix)]
trait LocalTransport {
    fn exchange(
        &mut self,
        request: Request,
        expires_at: Option<u64>,
    ) -> impl Future<Output = anyhow::Result<Reply>>;
}

#[cfg(unix)]
struct Approval {
    policy: SudoPolicy,
    key: ed25519_dalek::SigningKey,
    handle: [u8; 32],
    uid: u32,
    bounds: TransportArgs,
    clock: Arc<dyn Fn() -> anyhow::Result<u64> + Send + Sync>,
}

#[cfg(unix)]
impl Approval {
    fn validate_challenge(&self, challenge: &SudoChallenge) -> anyhow::Result<()> {
        original_uid(self.uid, self.uid)?;
        validate(&self.policy, challenge, &self.key, (self.clock)()?)?;
        if challenge.grant.nonce != self.handle || challenge.grant.caller_uid != self.uid {
            bail!("local sudo challenge does not match this user and invocation handle");
        }
        Ok(())
    }

    async fn exchange(
        &self,
        local: &mut impl LocalTransport,
        operation: Operation,
        expires_at: Option<u64>,
    ) -> anyhow::Result<Response> {
        if expires_at.is_some_and(|expiry| (self.clock)().map_or(true, |time| time >= expiry)) {
            bail!("local sudo approval expired");
        }
        let reply = local
            .exchange(
                Request {
                    version: PROTOCOL_VERSION,
                    nonce: self.handle,
                    operation,
                },
                expires_at,
            )
            .await?;
        if reply.version != PROTOCOL_VERSION {
            bail!("unsupported local sudo protocol version");
        }
        Ok(reply.response)
    }

    async fn run(
        &self,
        local: &mut impl LocalTransport,
        quorum: impl Transport,
    ) -> anyhow::Result<()> {
        original_uid(self.uid, self.uid)?;
        self.policy.validate()?;
        let Response::Challenge { challenge } = self
            .exchange(
                local,
                Operation::BindRequester {
                    requester_public_key: self.key.verifying_key().to_bytes(),
                },
                None,
            )
            .await?
        else {
            bail!("expected a host-attested local sudo challenge");
        };
        self.validate_challenge(&challenge)?;
        let token = coordinate(
            self.policy.clone(),
            challenge,
            self.key.clone(),
            &self.bounds,
            quorum,
            self.clock.clone(),
        )
        .await?;
        self.validate_challenge(&token.challenge)?;
        verify_token(&self.policy, &token, (self.clock)()?)?;
        let Response::Redemption { invocation } = self
            .exchange(
                local,
                Operation::SubmitToken {
                    token: Box::new(token.clone()),
                },
                Some(token.challenge.grant.expires_at),
            )
            .await?
        else {
            bail!("expected a fresh local sudo redemption invocation");
        };
        self.validate_challenge(&token.challenge)?;
        if invocation.caller_uid != self.uid
            || invocation.nonce == self.handle
            || invocation.nonce == [0; 32]
        {
            bail!("local sudo redemption does not match this user or has no fresh nonce");
        }
        let proof = self
            .key
            .sign(&invocation.proof_bytes(&token)?)
            .to_bytes()
            .to_vec();
        let verified =
            verify_sudo_redemption(&self.policy, &token, &invocation, &proof, (self.clock)()?)?;
        verified.validate_at((self.clock)()?)?;
        let response = self
            .exchange(
                local,
                Operation::Redeem {
                    requester_proof: proof,
                },
                Some(invocation.expires_at),
            )
            .await?;
        if !matches!(response, Response::Submitted) {
            bail!("local sudo service did not acknowledge approval submission; do not retry automatically");
        }
        Ok(())
    }
}

#[cfg(unix)]
mod socket {
    use super::*;
    use ipars_quorum::sudo::local::{MAX_FRAME_BYTES, SUBMIT_SOCKET};
    use nix::fcntl::{openat, AtFlags, OFlag};
    use nix::sys::stat::{fstatat, Mode, SFlag};
    use std::os::unix::fs::MetadataExt;
    use std::path::Component;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::UnixStream;

    const TIMEOUT: Duration = Duration::from_secs(3);

    fn trusted_socket(path: &Path) -> anyhow::Result<(nix::libc::dev_t, nix::libc::ino_t)> {
        let components: Vec<_> = path.components().collect();
        if components.len() < 2
            || components[0] != Component::RootDir
            || !components[1..]
                .iter()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            bail!("invalid fixed local sudo socket path");
        }
        let mut directory = File::open("/")?;
        for (index, part) in components[1..].iter().enumerate() {
            let metadata = directory.metadata()?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                bail!("local sudo socket requires root-owned non-writable directory ancestry");
            }
            let Component::Normal(name) = part else {
                bail!("invalid local sudo socket path");
            };
            if index + 2 == components.len() {
                let metadata = fstatat(&directory, Path::new(name), AtFlags::AT_SYMLINK_NOFOLLOW)?;
                if metadata.st_uid != 0
                    || metadata.st_nlink != 1
                    || SFlag::from_bits_truncate(metadata.st_mode) & SFlag::S_IFMT
                        != SFlag::S_IFSOCK
                {
                    bail!("local sudo endpoint must be a root-owned socket, not a symlink");
                }
                return Ok((metadata.st_dev, metadata.st_ino));
            }
            directory = File::from(openat(
                &directory,
                Path::new(name),
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?);
        }
        bail!("invalid local sudo socket path")
    }

    fn root_peer(uid: u32) -> anyhow::Result<()> {
        if uid != 0 {
            bail!("local sudo socket peer is not root");
        }
        Ok(())
    }

    fn authenticate_peer(stream: &UnixStream) -> anyhow::Result<()> {
        root_peer(stream.peer_cred()?.uid())
    }

    async fn frame<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        request: &Request,
    ) -> anyhow::Result<Reply> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(request)
                .map_err(|_| anyhow::anyhow!("cannot encode local sudo request"))?,
        );
        if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
            bail!("local sudo request exceeds frame limit");
        }
        stream.write_u32(u32::try_from(bytes.len())?).await?;
        stream.write_all(&bytes).await?;
        let length = stream.read_u32().await? as usize;
        if length == 0 || length > MAX_FRAME_BYTES {
            bail!("invalid local sudo reply frame size");
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        stream.read_exact(&mut bytes).await?;
        let reply: Reply = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid local sudo reply"))?;
        if reply.version != PROTOCOL_VERSION {
            bail!("unsupported local sudo protocol version");
        }
        Ok(reply)
    }

    pub(super) struct SocketTransport;
    impl LocalTransport for SocketTransport {
        async fn exchange(
            &mut self,
            request: Request,
            expires_at: Option<u64>,
        ) -> anyhow::Result<Reply> {
            tokio::time::timeout(TIMEOUT, async {
                let identity = trusted_socket(Path::new(SUBMIT_SOCKET))?;
                let mut stream = UnixStream::connect(SUBMIT_SOCKET).await?;
                // No request bytes leave before both kernel credentials and path checks pass.
                authenticate_peer(&stream)?;
                if trusted_socket(Path::new(SUBMIT_SOCKET))? != identity {
                    bail!("local sudo socket changed while connecting");
                }
                if expires_at.is_some_and(|expiry| now().map_or(true, |time| time >= expiry)) {
                    bail!("local sudo approval expired before transmission");
                }
                frame(&mut stream, &request).await
            })
            .await
            .map_err(|_| anyhow::anyhow!("local sudo exchange timed out; no automatic retry"))?
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn request() -> Request {
            Request {
                version: PROTOCOL_VERSION,
                nonce: [7; 32],
                operation: Operation::BindRequester {
                    requester_public_key: [8; 32],
                },
            }
        }

        #[tokio::test]
        async fn local_frames_are_bounded_versioned_and_strict() -> anyhow::Result<()> {
            for case in 0..6 {
                let (mut client, mut server) = tokio::io::duplex(MAX_FRAME_BYTES * 2);
                let server = tokio::spawn(async move {
                    let size = server.read_u32().await? as usize;
                    let mut bytes = vec![0; size];
                    server.read_exact(&mut bytes).await?;
                    let incoming: Request = serde_json::from_slice(&bytes)?;
                    assert_eq!(incoming.version, PROTOCOL_VERSION);
                    let payload = match case {
                        0 => serde_json::to_vec(&Reply { version: PROTOCOL_VERSION, response: Response::Submitted })?,
                        1 => serde_json::to_vec(&Reply { version: 1, response: Response::Submitted })?,
                        2 => b"{\"version\":2,\"response\":{\"type\":\"submitted\"},\"caller_uid\":0}".to_vec(),
                        _ => Vec::new(),
                    };
                    let length = match case {
                        3 => (MAX_FRAME_BYTES + 1) as u32,
                        4 => 0,
                        5 => 20,
                        _ => payload.len() as u32,
                    };
                    server.write_u32(length).await?;
                    server.write_all(&payload).await?;
                    Ok::<_, anyhow::Error>(())
                });
                let result = frame(&mut client, &request()).await;
                assert_eq!(result.is_ok(), case == 0);
                server.await??;
            }
            let (mut client, mut server) = tokio::io::duplex(64);
            let oversized = Request {
                version: PROTOCOL_VERSION,
                nonce: [7; 32],
                operation: Operation::Redeem {
                    requester_proof: vec![1; MAX_FRAME_BYTES],
                },
            };
            assert!(frame(&mut client, &oversized).await.is_err());
            assert!(
                tokio::time::timeout(Duration::from_millis(10), server.read_u8())
                    .await
                    .is_err()
            );
            Ok(())
        }

        #[tokio::test]
        async fn local_peer_authentication_uses_kernel_credentials_and_rejects_nonroot(
        ) -> anyhow::Result<()> {
            assert!(root_peer(0).is_ok());
            assert!(root_peer(1000).is_err());
            let (client, mut server) = UnixStream::pair()?;
            assert_eq!(
                authenticate_peer(&client).is_ok(),
                nix::unistd::geteuid().as_raw() == 0
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(10), server.read_u8())
                    .await
                    .is_err()
            );
            assert!(trusted_socket(Path::new("relative/socket")).is_err());
            assert!(trusted_socket(Path::new("/run/../socket")).is_err());
            assert!(trusted_socket(Path::new("/dev/null")).is_err());
            Ok(())
        }
    }
}

#[cfg(unix)]
pub(crate) async fn approve(args: SudoApproveArgs) -> anyhow::Result<()> {
    let uid = original_uid(
        nix::unistd::getuid().as_raw(),
        nix::unistd::geteuid().as_raw(),
    )?;
    let policy: SudoPolicy = read_json(&args.policy, false)?;
    policy.validate()?;
    let key = requester_key(&args.requester_key)?;
    let quorum = HttpTransport {
        client: http_client()?,
        token: oidc_token(&args.oidc_token)?,
    };
    let approval = Approval {
        policy,
        key,
        handle: args.handle,
        uid,
        bounds: args.transport,
        clock: Arc::new(now),
    };
    approval.run(&mut socket::SocketTransport, quorum).await?;
    println!("{}", serde_json::json!({ "status": "approval_submitted" }));
    Ok(())
}

#[cfg(not(unix))]
pub(crate) async fn approve(_args: SudoApproveArgs) -> anyhow::Result<()> {
    bail!("local sudo approval requires Unix kernel peer credentials")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use ipars_quorum::sudo::SudoLocalInvocation;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[derive(Clone)]
    struct Counted<T> {
        inner: T,
        calls: Arc<AtomicUsize>,
    }
    impl<T: Transport> Transport for Counted<T> {
        async fn round1(
            &self,
            url: Url,
            request: SudoRound1Request,
        ) -> anyhow::Result<ipars_quorum::Round1Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.round1(url, request).await
        }
        async fn round2(
            &self,
            url: Url,
            request: SudoRound2Request,
        ) -> anyhow::Result<Round2Response> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.round2(url, request).await
        }
    }

    struct MockLocal {
        policy: SudoPolicy,
        challenge: SudoChallenge,
        handle: [u8; 32],
        phase: u8,
        fault: u8,
        time: Arc<AtomicU64>,
        redemption: Option<(SudoToken, SudoLocalInvocation)>,
        verified: bool,
    }
    impl LocalTransport for MockLocal {
        async fn exchange(&mut self, request: Request, _: Option<u64>) -> anyhow::Result<Reply> {
            assert_eq!(request.version, PROTOCOL_VERSION);
            assert_eq!(request.nonce, self.handle);
            let response = match (self.phase, request.operation) {
                (
                    0,
                    Operation::BindRequester {
                        requester_public_key: _,
                    },
                ) => {
                    if self.fault == 1 {
                        Response::Submitted
                    } else {
                        Response::Challenge {
                            challenge: self.challenge.clone(),
                        }
                    }
                }
                (1, Operation::SubmitToken { token }) => {
                    verify_token(&self.policy, &token, self.time.load(Ordering::SeqCst))?;
                    let mut invocation = SudoLocalInvocation {
                        host_node_id: token.challenge.grant.host_node_id.clone(),
                        caller_uid: token.challenge.grant.caller_uid,
                        runas_uid: 0,
                        nonce: [24; 32],
                        issued_at: 100,
                        expires_at: 160,
                    };
                    match self.fault {
                        3 => invocation.caller_uid += 1,
                        4 => invocation.nonce = self.handle,
                        5 => invocation.nonce = [0; 32],
                        6 => invocation.host_node_id = "node-2".into(),
                        7 => invocation.expires_at += 1,
                        8 => invocation.runas_uid = 1000,
                        9 => {
                            self.time.store(160, Ordering::SeqCst);
                        }
                        _ => {}
                    }
                    self.redemption = Some((*token, invocation.clone()));
                    if self.fault == 10 {
                        Response::Submitted
                    } else {
                        Response::Redemption { invocation }
                    }
                }
                (2, Operation::Redeem { requester_proof }) => {
                    let (token, invocation) = self
                        .redemption
                        .as_ref()
                        .context("missing mock redemption")?;
                    verify_sudo_redemption(
                        &self.policy,
                        token,
                        invocation,
                        &requester_proof,
                        self.time.load(Ordering::SeqCst),
                    )?;
                    let mut altered = invocation.clone();
                    altered.nonce = [25; 32];
                    assert!(verify_sudo_redemption(
                        &self.policy,
                        token,
                        &altered,
                        &requester_proof,
                        100
                    )
                    .is_err());
                    self.verified = true;
                    if self.fault == 11 {
                        Response::Challenge {
                            challenge: self.challenge.clone(),
                        }
                    } else {
                        Response::Submitted
                    }
                }
                _ => bail!("unexpected mock local state or operation"),
            };
            self.phase += 1;
            Ok(Reply {
                version: if self.fault == 2 { 1 } else { PROTOCOL_VERSION },
                response,
            })
        }
    }

    fn setup() -> anyhow::Result<(Approval, MockLocal, Counted<super::super::tests::Mock>)> {
        let (policy, challenge, key, quorum) = super::super::tests::fixture()?;
        let time = Arc::new(AtomicU64::new(100));
        let clock = time.clone();
        let approval = Approval {
            policy: policy.clone(),
            key,
            handle: challenge.grant.nonce,
            uid: 1000,
            bounds: TransportArgs::default(),
            clock: Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
        };
        let local = MockLocal {
            policy,
            handle: challenge.grant.nonce,
            challenge,
            phase: 0,
            fault: 0,
            time,
            redemption: None,
            verified: false,
        };
        Ok((
            approval,
            local,
            Counted {
                inner: quorum,
                calls: Arc::new(AtomicUsize::new(0)),
            },
        ))
    }

    #[tokio::test]
    async fn local_workflow_submits_real_majority_and_bound_redemption_proof() -> anyhow::Result<()>
    {
        let (approval, mut local, quorum) = setup()?;
        approval.run(&mut local, quorum.clone()).await?;
        assert_eq!(local.phase, 3);
        assert!(local.verified);
        assert!(quorum.calls.load(Ordering::SeqCst) >= 4);
        Ok(())
    }

    #[tokio::test]
    async fn local_challenge_rejections_precede_quorum_requests() -> anyhow::Result<()> {
        for case in 0..8 {
            let (mut approval, mut local, quorum) = setup()?;
            match case {
                0 => local.fault = 1,
                1 => local.fault = 2,
                2 => {
                    approval.handle = [88; 32];
                    local.handle = approval.handle;
                }
                3 => approval.uid = 1001,
                4 => approval.key = ed25519_dalek::SigningKey::from_bytes(&[55; 32]),
                5 => local.challenge.host_signature[0] ^= 1,
                6 => {
                    local.time.store(160, Ordering::SeqCst);
                }
                _ => approval.uid = 0,
            }
            assert!(approval.run(&mut local, quorum.clone()).await.is_err());
            assert_eq!(quorum.calls.load(Ordering::SeqCst), 0);
            assert!(local.phase <= 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn local_redemption_identity_nonce_scope_expiry_and_state_fail_closed(
    ) -> anyhow::Result<()> {
        for fault in 3..=11 {
            let (approval, mut local, quorum) = setup()?;
            local.fault = fault;
            assert!(approval.run(&mut local, quorum).await.is_err());
            assert_eq!(local.phase, if fault == 11 { 3 } else { 2 });
            assert_eq!(local.verified, fault == 11);
        }
        Ok(())
    }

    #[test]
    fn local_cli_requires_handle_and_original_nonroot_uid() -> anyhow::Result<()> {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(subcommand)]
            command: QuorumCommand,
        }
        let args = [
            "quorum",
            "sudo-approve",
            "--handle",
            &"17".repeat(32),
            "--policy",
            "policy.json",
            "--requester-key",
            "requester.key",
            "--oidc-token",
            "owner.token",
        ];
        assert!(matches!(
            Cli::try_parse_from(args)?.command,
            QuorumCommand::SudoApprove(_)
        ));
        for flag in ["--socket", "--command", "--token-out", "--caller-uid"] {
            assert!(Cli::try_parse_from(args.into_iter().chain([flag, "untrusted"])).is_err());
        }
        for value in [
            "00".repeat(32),
            "17".repeat(31),
            "gg".repeat(32),
            "é".repeat(32),
        ] {
            assert!(parse_handle(&value).is_err());
        }
        assert_eq!(
            parse_handle(&"AB".repeat(32)).map_err(anyhow::Error::msg)?,
            [0xab; 32]
        );
        assert_eq!(original_uid(1000, 1000)?, 1000);
        for (real, effective) in [(0, 0), (1000, 0), (0, 1000), (1000, 1001)] {
            assert!(original_uid(real, effective).is_err());
        }
        Ok(())
    }
}
