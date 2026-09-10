//! Linux-only, fixed-path local transport. No HTTP, command execution, or signing keys.
use crate::privilege::{PrivilegeGrant, PrivilegePolicy, PrivilegeVerifier, SignedPrivilegeGrant};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::{oneshot, Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};

pub const RUN: &str = "/run/ipars-sudo-prototype";
pub const ADAPTER: &str = "/run/ipars-sudo-prototype/adapter.sock";
pub const SUBMIT: &str = "/run/ipars-sudo-prototype/submit.sock";
pub const CONFIG: &str = "/etc/ipars-sudo-prototype.json";
pub const STATE: &str = "/var/lib/ipars-sudo-prototype";
const LIMIT: usize = 16 * 1024;

fn denied() -> io::Error {
    io::Error::other("local sudo grant unavailable or rejected")
}
fn seconds() -> io::Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| denied())?
        .as_secs()
        .try_into()
        .map_err(|_| denied())
}

/// Root-only ancestry is checked before opening any privileged file or socket.
pub(super) fn trusted(path: &Path, directory: bool, mode: Option<u32>) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(denied());
    }
    for ancestor in path.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor)?;
        if meta.uid() != 0
            || meta.mode() & 0o022 != 0
            || meta.file_type().is_symlink()
            || (ancestor != path && !meta.is_dir())
        {
            return Err(denied());
        }
        if ancestor == path
            && (meta.is_dir() != directory || mode.is_some_and(|mode| meta.mode() & 0o777 != mode))
        {
            return Err(denied());
        }
    }
    Ok(())
}

pub fn load_policy() -> io::Result<PrivilegePolicy> {
    trusted(Path::new(CONFIG), false, Some(0o600))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(CONFIG)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
        || meta.len() > 1024 * 1024
    {
        return Err(denied());
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(denied());
    }
    serde_json::from_slice(&bytes).map_err(|_| denied())
}

pub(super) fn listener(path: &str, mode: u32) -> io::Result<UnixListener> {
    // Never unlink an existing socket or silently replace another service.
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.bind(&socket2::SockAddr::unix(path)?)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    socket.listen(16)?;
    socket.set_nonblocking(true)?;
    UnixListener::from_std(socket.into())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub nonce: [u8; 32],
    /// None fetches this UID's active challenge. Some submits a signed grant.
    pub signed: Option<SignedPrivilegeGrant>,
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

struct Pending {
    grant: PrivilegeGrant,
    sender: Option<oneshot::Sender<SignedPrivilegeGrant>>,
}
type PendingMap = Arc<Mutex<BTreeMap<[u8; 32], Pending>>>;

async fn adapter(
    mut stream: UnixStream,
    verifier: Arc<PrivilegeVerifier>,
    pending: PendingMap,
) -> io::Result<()> {
    if stream.peer_cred()?.uid() != 0 {
        return Err(denied());
    }
    let mut request = [0; 8];
    timeout(Duration::from_secs(3), stream.read_exact(&mut request))
        .await
        .map_err(|_| denied())??;
    if &request[..4] != b"SQP1" {
        return Err(denied());
    }
    let uid = u32::from_be_bytes(request[4..8].try_into().map_err(|_| denied())?);
    let grant = verifier
        .challenge(uid, seconds()?)
        .await
        .map_err(|_| denied())?;
    let nonce = grant.nonce;
    let (sender, receiver) = oneshot::channel();
    pending.lock().await.insert(
        nonce,
        Pending {
            grant: grant.clone(),
            sender: Some(sender),
        },
    );
    let result = timeout(Duration::from_secs(60), async {
        stream.write_all(&nonce).await?;
        let mut unexpected = [0];
        let signed = tokio::select! {
            // EOF or additional adapter input cancels; no reusable admission after disconnect.
            _ = stream.read(&mut unexpected) => return Err(denied()),
            result = receiver => result.map_err(|_| denied())?,
        };
        if signed.grant != grant {
            return Err(denied());
        }
        verifier.consume(uid, &signed).await.map_err(|_| denied())?;
        // A lost acknowledgement burns the grant. Never undo durable consumption.
        loop {
            stream.writable().await?;
            grant.check_current_time().map_err(|_| denied())?;
            match stream.try_write(&[1]) {
                Ok(1) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                _ => return Err(denied()),
            }
        }
    })
    .await
    .map_err(|_| denied())
    .and_then(|result| result);
    pending.lock().await.remove(&nonce);
    result
}

async fn submission(mut stream: UnixStream, pending: PendingMap) -> io::Result<()> {
    let uid = stream.peer_cred()?.uid();
    let request: Submission = read_frame(&mut stream).await?;
    let mut entries = pending.lock().await;
    let entry = entries.get_mut(&request.nonce).ok_or_else(denied)?;
    if entry.grant.caller_uid != uid || seconds()? >= entry.grant.expires_at {
        return Err(denied());
    }
    if let Some(signed) = request.signed {
        if signed.grant != entry.grant {
            return Err(denied());
        }
        entry
            .sender
            .take()
            .ok_or_else(denied)?
            .send(signed)
            .map_err(|_| denied())?;
        drop(entries);
        // Accepted for verification, not evidence of execution or successful consumption.
        write_frame(&mut stream, &serde_json::json!({"submitted":true})).await
    } else {
        let grant = entry.grant.clone();
        drop(entries);
        write_frame(&mut stream, &grant).await
    }
}

pub async fn serve() -> io::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        return Err(denied());
    }
    let policy = load_policy()?;
    trusted(Path::new(RUN), true, Some(0o755))?;
    trusted(Path::new(STATE), true, Some(0o700))?;
    let database = Path::new(STATE).join("privilege.sqlite");
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
    trusted(&database, false, Some(0o600))?;
    let meta = File::open(&database)?.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return Err(denied());
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = Path::new(STATE).join(format!("privilege.sqlite{suffix}"));
        match std::fs::symlink_metadata(&sidecar) {
            Ok(meta) => {
                trusted(&sidecar, false, Some(0o600))?;
                if !meta.is_file() || meta.nlink() != 1 {
                    return Err(denied());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    let verifier = Arc::new(
        PrivilegeVerifier::open(&database, policy)
            .await
            .map_err(|_| denied())?,
    );
    let adapters = listener(ADAPTER, 0o600)?;
    let submissions = listener(SUBMIT, 0o666)?;
    let pending = PendingMap::default();
    let adapter_slots = Arc::new(Semaphore::new(8));
    let submission_slots = Arc::new(Semaphore::new(16));
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
                if let Ok(permit) = submission_slots.clone().try_acquire_owned() {
                    let pending = pending.clone();
                    tasks.spawn(async move { let _permit = permit;
                        let _ = timeout(Duration::from_secs(5), submission(stream, pending)).await;
                    });
                }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}
