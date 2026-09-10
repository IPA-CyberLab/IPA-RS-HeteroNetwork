//! Versioned local-only sudo-v2 transport. Existing v1 sockets/types are not accepted.
use crate::{
    local::{listener, trusted},
    privilege_v2::{now, LocalV2Config, V2Verifier},
};
use ed25519_dalek::SigningKey;
pub use ipars_quorum::sudo::local::{
    Operation as V2Operation, Reply as V2Reply, Request as V2Request, Response as V2Response,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    sync::{mpsc, oneshot, Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};
use zeroize::Zeroizing;

pub const VERSION: u32 = ipars_quorum::sudo::local::PROTOCOL_VERSION;
pub const RUN: &str = "/run/ipars-sudo-v2";
pub const ADAPTER: &str = "/run/ipars-sudo-v2/adapter.sock";
pub const SUBMIT: &str = ipars_quorum::sudo::local::SUBMIT_SOCKET;
pub const CONFIG: &str = "/etc/ipars-sudo-v2/config.json";
pub const HOST_KEY: &str = "/etc/ipars-sudo-v2/host.key";
pub const STATE: &str = "/var/lib/ipars-sudo-v2";
const LIMIT: usize = ipars_quorum::sudo::local::MAX_FRAME_BYTES;

fn denied() -> io::Error {
    io::Error::other("local sudo-v2 request unavailable or rejected")
}

pub async fn read_frame<T: for<'a> Deserialize<'a>>(stream: &mut UnixStream) -> io::Result<T> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > LIMIT {
        return Err(denied());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| denied())
}

pub async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| denied())?;
    if bytes.len() > LIMIT {
        return Err(denied());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await
}

fn private_file(path: &Path, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    trusted(path, false, Some(0o600))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o600
        || meta.len() > limit as u64
    {
        return Err(denied());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(denied());
    }
    Ok(bytes)
}

struct Command {
    operation: V2Operation,
    response: oneshot::Sender<io::Result<V2Response>>,
}
struct Entry {
    uid: u32,
    sender: mpsc::Sender<Command>,
}
type Pending = Arc<Mutex<BTreeMap<[u8; 32], Entry>>>;

async fn adapter(
    mut stream: UnixStream,
    verifier: Arc<V2Verifier>,
    pending: Pending,
) -> io::Result<()> {
    if stream.peer_cred()?.uid() != 0 {
        return Err(denied());
    }
    let mut bytes = [0; 40];
    timeout(Duration::from_secs(3), stream.read_exact(&mut bytes))
        .await
        .map_err(|_| denied())??;
    if &bytes[..4] != b"SQV2" {
        return Err(denied());
    }
    let uid = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| denied())?);
    let nonce: [u8; 32] = bytes[8..].try_into().map_err(|_| denied())?;
    let mut session = verifier.begin(uid, nonce).await.map_err(|_| denied())?;
    let (sender, mut receiver) = mpsc::channel::<Command>(1);
    pending.lock().await.insert(nonce, Entry { uid, sender });
    let result = timeout(Duration::from_secs(60), async {
        stream.write_all(&nonce).await?;
        loop {
            let mut extra = [0];
            let command = tokio::select! {
                _ = stream.read(&mut extra) => return Err(denied()),
                command = receiver.recv() => command.ok_or_else(denied)?,
            };
            let response = match command.operation {
                V2Operation::BindRequester {
                    requester_public_key,
                } => verifier
                    .bind_requester(&mut session, requester_public_key)
                    .await
                    .map(|challenge| V2Response::Challenge { challenge })
                    .map_err(|_| denied()),
                V2Operation::SubmitToken { token } => verifier
                    .submit_token(&mut session, *token)
                    .await
                    .map(|invocation| V2Response::Redemption { invocation })
                    .map_err(|_| denied()),
                V2Operation::Redeem { requester_proof } => {
                    if requester_proof.len() != 64 {
                        let _ = command.response.send(Err(denied()));
                        continue;
                    }
                    match verifier.consume(&session, &requester_proof).await {
                        Ok(verified) => {
                            let _ = command.response.send(Ok(V2Response::Submitted));
                            let mut ack = [0u8; 9];
                            ack[0] = 1;
                            ack[1..]
                                .copy_from_slice(&verified.invocation().expires_at.to_be_bytes());
                            let mut written = 0;
                            while written < ack.len() {
                                stream.writable().await?;
                                verified
                                    .validate_at(now().map_err(|_| denied())?)
                                    .map_err(|_| denied())?;
                                match stream.try_write(&ack[written..]) {
                                    Ok(0) => return Err(denied()),
                                    Ok(count) => written += count,
                                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                        continue
                                    }
                                    _ => return Err(denied()),
                                }
                            }
                            verified
                                .validate_at(now().map_err(|_| denied())?)
                                .map_err(|_| denied())?;
                            return Ok(());
                        }
                        Err(_) => Err(denied()),
                    }
                }
            };
            // Losing a response never rebinds a requester or regenerates a redemption nonce.
            let _ = command.response.send(response);
        }
    })
    .await
    .map_err(|_| denied())
    .and_then(|result| result);
    pending.lock().await.remove(&nonce);
    result
}

async fn submit(mut stream: UnixStream, pending: Pending) -> io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    let request: V2Request = read_frame(&mut stream).await?;
    if request.version != VERSION {
        return Err(denied());
    }
    let entries = pending.lock().await;
    let entry = entries.get(&request.nonce).ok_or_else(denied)?;
    if entry.uid != uid {
        return Err(denied());
    }
    let (response, receiver) = oneshot::channel();
    entry
        .sender
        .try_send(Command {
            operation: request.operation,
            response,
        })
        .map_err(|_| denied())?;
    drop(entries);
    let response = receiver.await.map_err(|_| denied())??;
    write_frame(
        &mut stream,
        &V2Reply {
            version: VERSION,
            response,
        },
    )
    .await
}

pub async fn serve() -> io::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(denied());
    }
    let config: LocalV2Config =
        serde_json::from_slice(&private_file(Path::new(CONFIG), 1_048_576)?)
            .map_err(|_| denied())?;
    let seed = private_file(Path::new(HOST_KEY), 32)?;
    let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| denied())?;
    let key = SigningKey::from_bytes(seed);
    trusted(Path::new(RUN), true, Some(0o755))?;
    trusted(Path::new(STATE), true, Some(0o700))?;
    let database = Path::new(STATE).join("sudo-v2.sqlite");
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&database)
    {
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error),
    }
    for path in [
        database.clone(),
        Path::new(STATE).join("sudo-v2.sqlite-wal"),
        Path::new(STATE).join("sudo-v2.sqlite-shm"),
        Path::new(STATE).join("sudo-v2.sqlite-journal"),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                trusted(&path, false, Some(0o600))?;
                if !meta.is_file() || meta.nlink() != 1 {
                    return Err(denied());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && path != database => (),
            Err(error) => return Err(error),
        }
    }
    let verifier = Arc::new(
        V2Verifier::open(&database, config, key)
            .await
            .map_err(|_| denied())?,
    );
    let adapters = listener(ADAPTER, 0o600)?;
    let submissions = listener(SUBMIT, 0o666)?;
    let pending = Pending::default();
    let adapter_slots = Arc::new(Semaphore::new(8));
    let submit_slots = Arc::new(Semaphore::new(16));
    let mut tasks = JoinSet::new();
    loop {
        while tasks.try_join_next().is_some() {}
        tokio::select! {
            result = adapters.accept() => {
                let (stream, _) = result?;
                if let Ok(permit) = adapter_slots.clone().try_acquire_owned() {
                    let (verifier, pending) = (verifier.clone(), pending.clone());
                    tasks.spawn(async move { let _permit = permit; let _ = adapter(stream, verifier, pending).await; });
                }
            }
            result = submissions.accept() => {
                let (stream, _) = result?;
                if let Ok(permit) = submit_slots.clone().try_acquire_owned() {
                    let pending = pending.clone();
                    tasks.spawn(async move { let _permit = permit; let _ = timeout(Duration::from_secs(5), submit(stream, pending)).await; });
                }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
