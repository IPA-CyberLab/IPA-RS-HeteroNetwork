//! DNS is resolved at the connecting endpoint, including CNAME chains. Only
//! public answers are dialed; HTTP keeps the original hostname for Host/SNI.
use crate::TunnelError;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

pub async fn resolve(url: &reqwest::Url) -> Result<Vec<SocketAddr>, TunnelError> {
    let host = url
        .host_str()
        .ok_or(TunnelError::InvalidPacket)?
        .trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .ok_or(TunnelError::InvalidPacket)?;
    let addresses = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| TunnelError::DnsUnavailable)?
        .map_err(|_| TunnelError::DnsUnavailable)?
        .take(32)
        .collect()
    };
    let mut public = Vec::new();
    for address in addresses {
        if ipars_types::socket_addr_is_globally_routable(address) && !public.contains(&address) {
            public.push(address);
            if public.len() == 32 {
                break;
            }
        }
    }
    if public.is_empty() {
        return Err(TunnelError::DnsRejected);
    }
    let ipv4_first = public[0].is_ipv4();
    let (first, second): (Vec<_>, Vec<_>) = public
        .into_iter()
        .partition(|address| address.is_ipv4() == ipv4_first);
    let mut addresses = Vec::new();
    for index in 0..first.len().max(second.len()) {
        if let Some(address) = first.get(index) {
            addresses.push(*address);
        }
        if addresses.len() == 8 {
            break;
        }
        if let Some(address) = second.get(index) {
            addresses.push(*address);
        }
        if addresses.len() == 8 {
            break;
        }
    }
    Ok(addresses)
}

pub async fn tcp_stream(url: &reqwest::Url) -> Result<tokio::net::TcpStream, TunnelError> {
    let addresses = resolve(url).await?;
    let mut attempts = tokio::task::JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        attempts.spawn(async move {
            tokio::time::sleep(Duration::from_millis(index as u64 * 250)).await;
            tokio::net::TcpStream::connect(address).await
        });
    }
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut last = TunnelError::BackendTimeout;
        while let Some(completed) = attempts.join_next().await {
            match completed {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => last = error.into(),
                Err(_) => {}
            }
        }
        Err(last)
    })
    .await
    .map_err(|_| TunnelError::BackendTimeout)?;
    attempts.abort_all();
    result
}

pub async fn http_client(url: &reqwest::Url) -> Result<reqwest::Client, TunnelError> {
    let addresses = resolve(url).await?;
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(25))
        .pool_max_idle_per_host(2)
        .resolve_to_addrs(
            url.host_str().ok_or(TunnelError::InvalidPacket)?,
            &addresses,
        )
        .build()?)
}

pub async fn udp_addresses(urls: &[String]) -> Result<(String, Vec<SocketAddr>), TunnelError> {
    let mut last = TunnelError::DnsUnavailable;
    for value in urls {
        let url = reqwest::Url::parse(value).map_err(|_| TunnelError::InvalidPacket)?;
        match resolve(&url).await {
            Ok(addresses) => return Ok((value.clone(), addresses)),
            Err(error) => last = error,
        }
    }
    Err(last)
}
