//! Native length-delimited TCP transport. The public stream contains no HTTP
//! request, Upgrade, TLS handshake, shared management credential, or plaintext
//! inner payload. WireGuard supplies end-to-end encryption and authentication.
use crate::{
    decode_batch, encode_open, OpenResponse, TunnelAuth, TunnelError, TunnelHub, MAX_BATCH_BYTES,
    MAX_PACKET_BYTES,
};
use ipars_types::NodeId;
use serde::{Deserialize, Serialize};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{watch, Mutex},
};

pub const PREFACE: &[u8; 8] = b"HNTCP1\r\n";
const MAX_HEADER: usize = 4096;
const MAX_OPEN: usize = MAX_PACKET_BYTES + 2054;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpOpen {
    pub node: NodeId,
    pub relay: bool,
    pub timestamp: i64,
    pub nonce: String,
    pub proof: String,
}
pub type Authorizer = Arc<
    dyn Fn(
            TcpOpen,
            Vec<u8>,
        ) -> Pin<
            Box<dyn Future<Output = Result<(Arc<TunnelHub>, OpenResponse), TunnelError>> + Send>,
        > + Send
        + Sync,
>;

pub struct TcpTunnel {
    pub resolved_endpoint: std::net::SocketAddr,
    reader: Mutex<OwnedReadHalf>,
    writer: Mutex<OwnedWriteHalf>,
}
impl TcpTunnel {
    pub async fn open_url(
        value: &str,
        node: &NodeId,
        first: Vec<u8>,
        auth: Option<&TunnelAuth>,
        failures: &std::collections::BTreeMap<String, u64>,
    ) -> Result<Self, TunnelError> {
        let canonical = ipars_types::normalize_public_transport_url(value, false)
            .map_err(|_| TunnelError::InvalidPacket)?;
        let url = reqwest::Url::parse(&canonical).map_err(|_| TunnelError::InvalidPacket)?;
        if url.scheme() != "tcp" {
            return Err(TunnelError::InvalidPacket);
        }
        tokio::time::timeout(Duration::from_secs(4), async {
            let stream = crate::endpoint::tcp_stream(&url).await?;
            Self::establish(stream, node, first, auth, failures).await
        })
        .await
        .map_err(|_| TunnelError::BackendTimeout)?
    }
    pub async fn open(
        endpoint: std::net::SocketAddr,
        node: &NodeId,
        first: Vec<u8>,
        auth: Option<&TunnelAuth>,
        failures: &std::collections::BTreeMap<String, u64>,
    ) -> Result<Self, TunnelError> {
        tokio::time::timeout(Duration::from_secs(4), async {
            let stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(endpoint))
                .await
                .map_err(|_| TunnelError::BackendTimeout)??;
            Self::establish(stream, node, first, auth, failures).await
        })
        .await
        .map_err(|_| TunnelError::BackendTimeout)?
    }
    async fn establish(
        mut stream: TcpStream,
        node: &NodeId,
        first: Vec<u8>,
        auth: Option<&TunnelAuth>,
        failures: &std::collections::BTreeMap<String, u64>,
    ) -> Result<Self, TunnelError> {
        let stream_endpoint = stream.peer_addr()?;
        stream.set_nodelay(true)?;
        let body = if auth.is_some() {
            encode_open(&first, failures)?
        } else {
            first
        };
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let proof = auth
            .map(|auth| auth.proof(node, timestamp, &nonce, &body))
            .transpose()?
            .unwrap_or_default();
        let header = serde_json::to_vec(&TcpOpen {
            node: node.clone(),
            relay: auth.is_none(),
            timestamp,
            nonce,
            proof,
        })
        .map_err(|_| TunnelError::InvalidPacket)?;
        if header.len() > MAX_HEADER || body.len() > MAX_OPEN {
            return Err(TunnelError::InvalidPacket);
        }
        stream.write_all(PREFACE).await?;
        stream.write_u16(header.len() as u16).await?;
        stream.write_u32(body.len() as u32).await?;
        stream.write_all(&header).await?;
        stream.write_all(&body).await?;
        if stream.read_u8().await? != 0 {
            return Err(TunnelError::Unauthorized);
        }
        let (reader, writer) = stream.into_split();
        Ok(Self {
            resolved_endpoint: stream_endpoint,
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
        })
    }
    pub async fn send(&self, body: Vec<u8>) -> Result<(), TunnelError> {
        decode_batch(&body)?;
        tokio::time::timeout(
            Duration::from_secs(20),
            self.writer.lock().await.write_all(&body),
        )
        .await
        .map_err(|_| TunnelError::BackendTimeout)??;
        Ok(())
    }
    pub async fn receive(&self) -> Result<Vec<Vec<u8>>, TunnelError> {
        let mut reader = self.reader.lock().await;
        let len = tokio::time::timeout(Duration::from_secs(30), reader.read_u16())
            .await
            .map_err(|_| TunnelError::BackendTimeout)?? as usize;
        if len == 0 {
            tokio::time::timeout(
                Duration::from_secs(5),
                self.writer.lock().await.write_u16(0),
            )
            .await
            .map_err(|_| TunnelError::BackendTimeout)??;
            return Ok(Vec::new());
        }
        if len > MAX_PACKET_BYTES {
            return Err(TunnelError::InvalidPacket);
        }
        let mut packet = vec![0; len];
        tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut packet))
            .await
            .map_err(|_| TunnelError::BackendTimeout)??;
        Ok(vec![packet])
    }
}

/// Admission is bounded before reading any body. An authenticated connection
/// owns one fixed UDP backend session; every cancellation releases its socket.
pub async fn serve(
    listener: TcpListener,
    authorize: Authorizer,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), TunnelError> {
    let connections = Arc::new(tokio::sync::Semaphore::new(2048));
    let opening = Arc::new(tokio::sync::Semaphore::new(32));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            changed=shutdown.changed()=>{if changed.is_err()||*shutdown.borrow(){break;}},
            completed=tasks.join_next(),if !tasks.is_empty()=>{let _=completed;},
            accepted=listener.accept()=>{
                let (mut socket,_)=match accepted {Ok(connection)=>connection,Err(_)=>{tokio::time::sleep(Duration::from_millis(200)).await;continue;}};
                let Ok(connection)=connections.clone().try_acquire_owned()else{continue;};
                let Ok(permit)=opening.clone().try_acquire_owned()else{continue;};let authorize=authorize.clone();
                tasks.spawn(async move{
                    let _connection=connection;
                    let result=tokio::time::timeout(Duration::from_secs(5),async{
                        let mut preface=[0;8];socket.read_exact(&mut preface).await?;
                        if &preface!=PREFACE{return Err(TunnelError::InvalidPacket);}
                        let header_size=socket.read_u16().await? as usize;let body_size=socket.read_u32().await? as usize;
                        if !(1..=MAX_HEADER).contains(&header_size)||body_size==0||body_size>MAX_OPEN{return Err(TunnelError::InvalidPacket);}
                        let mut header=vec![0;header_size];socket.read_exact(&mut header).await?;
                        let header:TcpOpen=serde_json::from_slice(&header).map_err(|_|TunnelError::InvalidPacket)?;
                        if header.node.as_str().is_empty()||header.node.as_str().len()>128{return Err(TunnelError::Unauthorized);}
                        let mut body=vec![0;body_size];socket.read_exact(&mut body).await?;authorize(header,body).await
                    }).await;
                    drop(permit);
                    let Ok(Ok((hub,opened)))=result else {let _=socket.write_u8(1).await;return;};
                    let token=opened.token;
                    if socket.write_u8(0).await.is_ok(){let _=pipe(socket,&hub,&token).await;}
                    hub.close(&token).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn pipe(socket: TcpStream, hub: &TunnelHub, token: &str) -> Result<(), TunnelError> {
    socket.set_nodelay(true)?;
    let (mut reader, mut writer) = socket.into_split();
    let send = async {
        loop {
            let len = tokio::time::timeout(Duration::from_secs(45), reader.read_u16())
                .await
                .map_err(|_| TunnelError::BackendTimeout)?? as usize;
            if len == 0 {
                hub.touch(token).await?;
                continue;
            }
            if len > MAX_PACKET_BYTES {
                return Err(TunnelError::InvalidPacket);
            }
            let mut body = Vec::with_capacity(len + 2);
            body.extend_from_slice(&(len as u16).to_be_bytes());
            body.resize(len + 2, 0);
            tokio::time::timeout(Duration::from_secs(20), reader.read_exact(&mut body[2..]))
                .await
                .map_err(|_| TunnelError::BackendTimeout)??;
            hub.send(token, &body).await?;
        }
    };
    let receive = async {
        loop {
            let mut body = hub.receive(token).await?;
            if body.is_empty() {
                body.extend_from_slice(&[0, 0]);
            }
            if body.len() > MAX_BATCH_BYTES {
                return Err(TunnelError::InvalidPacket);
            }
            tokio::time::timeout(Duration::from_secs(20), writer.write_all(&body))
                .await
                .map_err(|_| TunnelError::BackendTimeout)??;
        }
    };
    tokio::select! {result=send=>result,result=receive=>result}
}
