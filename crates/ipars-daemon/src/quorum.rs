use std::fs::OpenOptions;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use clap::Args;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Args)]
pub struct QuorumSignerArgs {
    /// Validate trusted inputs without binding a port or issuing signatures.
    #[arg(long)]
    pub check_config: bool,
    #[arg(long, env = "HETERONETWORK_ADMIN_QUORUM_MANIFEST_PATH")]
    pub manifest_path: PathBuf,
    #[arg(long, env = "HETERONETWORK_ADMIN_QUORUM_KEY_PACKAGE_PATH")]
    pub key_package_path: PathBuf,
    #[arg(long, env = "HETERONETWORK_ADMIN_QUORUM_NODE_ID")]
    pub node_id: String,
    #[arg(long, env = "HETERONETWORK_ADMIN_QUORUM_LISTEN")]
    pub listen: SocketAddr,
    #[arg(long, env = "HETERONETWORK_VPN_POOL", default_value = "10.250.0.0/16")]
    pub vpn_pool: ipnet::IpNet,
    #[arg(long, env = "HETERONETWORK_WEB_OIDC_ISSUER_URL")]
    pub oidc_issuer_url: String,
    #[arg(
        long,
        env = "HETERONETWORK_WEB_OIDC_CLIENT_ID",
        default_value = "heteronetwork-web"
    )]
    pub oidc_client_id: String,
    #[arg(long, env = "HETERONETWORK_WEB_OIDC_REQUIRED_EMAIL")]
    pub oidc_required_email: String,
    #[arg(long, env = "HETERONETWORK_ADMIN_QUORUM_OWNER_SUBJECT")]
    pub oidc_required_subject: String,
    #[arg(long, env = "HETERONETWORK_WEB_OIDC_BACKCHANNEL_BASE_URL")]
    pub oidc_backchannel_base_url: Option<String>,
    #[arg(
        long,
        env = "HETERONETWORK_WEB_OIDC_BACKCHANNEL_FALLBACK_BASE_URLS",
        value_delimiter = ','
    )]
    pub oidc_backchannel_fallback_base_urls: Vec<String>,
}

pub fn read_config<T: DeserializeOwned>(path: &Path, secret: bool) -> anyhow::Result<T> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags((nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits())
        .open(path)
        .context("cannot open quorum configuration file")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "quorum configuration must be a regular file"
    );
    let uid = nix::unistd::geteuid().as_raw();
    ensure!(
        metadata.uid() == 0 || metadata.uid() == uid,
        "quorum configuration has an untrusted owner"
    );
    let forbidden = if secret { 0o077 } else { 0o022 };
    ensure!(
        metadata.mode() & forbidden == 0,
        "quorum configuration permissions are too broad"
    );
    ensure!(
        metadata.len() <= MAX_CONFIG_BYTES,
        "quorum configuration is too large"
    );
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_CONFIG_BYTES,
        "quorum configuration is too large"
    );
    // Serde errors can include secret values. Do not forward them to logs.
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("invalid quorum configuration JSON"))
}

fn validate_listen(args: &QuorumSignerArgs) -> anyhow::Result<()> {
    ensure!(
        args.listen.port() >= 1024,
        "quorum signer requires an unprivileged port"
    );
    ensure!(
        args.listen.ip().is_loopback()
            || (!args.listen.ip().is_unspecified()
                && !args.listen.ip().is_multicast()
                && !ipars_types::ip_addr_is_globally_routable(args.listen.ip())
                && args.vpn_pool.contains(&args.listen.ip())),
        "quorum signer must bind a specific VPN or loopback address"
    );
    Ok(())
}

pub async fn configure_control_plane<S: ipars_control_plane::ControlPlaneStore>(
    plane: &ipars_control_plane::ControlPlane<S>,
    path: Option<&Path>,
) -> anyhow::Result<Option<ipars_quorum::Manifest>> {
    let anchor = plane.get_admin_quorum_manifest_anchor().await?;
    let Some(path) = path else {
        ensure!(
            anchor.is_none(),
            "admin quorum is enabled in shared storage; a trusted manifest is required"
        );
        return Ok(None);
    };
    let manifest: ipars_quorum::Manifest = read_config(path, false)?;
    manifest.validate()?;
    ensure!(
        manifest.cluster_id == plane.config().cluster_id.as_str(),
        "admin quorum manifest belongs to another cluster"
    );
    let digest = manifest.digest()?;
    if let Some(anchor) = anchor {
        ensure!(
            anchor.manifest_epoch == manifest.epoch && anchor.manifest_digest == digest,
            "admin quorum manifest conflicts with the shared anchor"
        );
    } else {
        let registered: std::collections::BTreeSet<_> = plane
            .list_nodes()
            .await?
            .into_iter()
            .map(|node| node.node_id.to_string())
            .collect();
        let voters: std::collections::BTreeSet<_> = manifest
            .members
            .iter()
            .map(|member| member.node_id.clone())
            .collect();
        ensure!(
            registered == voters,
            "initial admin quorum roster must include every registered non-client node"
        );
        plane
            .bind_admin_quorum_manifest(manifest.epoch, &digest)
            .await?;
    }
    Ok(Some(manifest))
}

pub async fn run_signer(args: QuorumSignerArgs) -> anyhow::Result<()> {
    validate_listen(&args)?;
    let manifest = read_config(&args.manifest_path, false)?;
    let key_package = read_config(&args.key_package_path, true)?;
    let auth = super::WebUiAuthConfig::new(
        super::WebAuthProvider::Keycloak,
        args.oidc_issuer_url,
        args.oidc_client_id,
        None,
        args.oidc_backchannel_base_url,
        "openid profile email".to_string(),
    )
    .map_err(anyhow::Error::msg)?
    .with_required_email(args.oidc_required_email)
    .map_err(anyhow::Error::msg)?
    .with_required_subject(args.oidc_required_subject)
    .map_err(anyhow::Error::msg)?
    .with_backchannel_fallback_base_urls(args.oidc_backchannel_fallback_base_urls)
    .map_err(anyhow::Error::msg)?;
    let app =
        ipars_control_plane_http::quorum::signer_router(manifest, key_package, args.node_id, auth)
            .map_err(anyhow::Error::msg)?;
    if args.check_config {
        tracing::info!("quorum signer configuration is valid");
        return Ok(());
    }
    super::serve_router(args.listen, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn signer_never_binds_wildcard_or_cleartext_public_address() -> anyhow::Result<()> {
        let mut args = QuorumSignerArgs {
            check_config: false,
            manifest_path: "manifest.json".into(),
            key_package_path: "share.json".into(),
            node_id: "node-test".into(),
            listen: "10.250.0.1:19790".parse()?,
            vpn_pool: "10.250.0.0/16".parse()?,
            oidc_issuer_url: "http://127.0.0.1:18079/realms/test".into(),
            oidc_client_id: "test".into(),
            oidc_required_email: "owner@example.test".into(),
            oidc_required_subject: "owner-subject".into(),
            oidc_backchannel_base_url: None,
            oidc_backchannel_fallback_base_urls: Vec::new(),
        };
        assert!(validate_listen(&args).is_ok());
        for address in ["0.0.0.0:19790", "192.168.1.1:19790", "10.250.0.1:443"] {
            args.listen = address.parse()?;
            assert!(validate_listen(&args).is_err());
        }
        args.listen = "127.0.0.1:19790".parse()?;
        assert!(validate_listen(&args).is_ok());
        args.vpn_pool = "0.0.0.0/0".parse()?;
        args.listen = "8.8.8.8:19790".parse()?;
        assert!(validate_listen(&args).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn enabled_cluster_cannot_start_without_manifest() -> anyhow::Result<()> {
        let store = std::sync::Arc::new(ipars_control_plane::InMemoryStore::default());
        let plane = ipars_control_plane::ControlPlane::new(
            ipars_control_plane::ControlPlaneConfig::new(
                ipars_types::ClusterId::from_string("test-cluster"),
                "10.250.0.0/16".parse()?,
            ),
            store,
        );
        assert!(configure_control_plane(&plane, None).await?.is_none());
        plane.bind_admin_quorum_manifest(1, &"a".repeat(64)).await?;
        assert!(configure_control_plane(&plane, None).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn initial_manifest_cannot_replace_registered_membership() -> anyhow::Result<()> {
        use ipars_quorum::{frost, Manifest, Member};
        let (_shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )?;
        let manifest = Manifest {
            schema_version: ipars_quorum::SCHEMA_VERSION,
            cluster_id: "test-cluster".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("http://127.0.0.1:{}/", 19790 + identifier),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let plane = ipars_control_plane::ControlPlane::new(
            ipars_control_plane::ControlPlaneConfig::new(
                ipars_types::ClusterId::from_string("test-cluster"),
                "10.250.0.0/16".parse()?,
            ),
            std::sync::Arc::new(ipars_control_plane::InMemoryStore::default()),
        );
        let path =
            std::env::temp_dir().join(format!("hn-quorum-manifest-{}.json", uuid_for_test()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        serde_json::to_writer(file, &manifest)?;
        let result = configure_control_plane(&plane, Some(&path)).await;
        std::fs::remove_file(path)?;
        assert!(result.is_err());
        assert!(plane.get_admin_quorum_manifest_anchor().await?.is_none());
        Ok(())
    }

    #[test]
    fn configuration_reader_rejects_symlinks_and_public_secrets() -> anyhow::Result<()> {
        let dir = std::env::temp_dir().join(format!("hn-quorum-config-{}", uuid_for_test()));
        std::fs::create_dir(&dir)?;
        let path = dir.join("config.json");
        let link = dir.join("link.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(b"{}")?;
        assert!(read_config::<serde_json::Value>(&path, true).is_ok());
        std::os::unix::fs::symlink(&path, &link)?;
        assert!(read_config::<serde_json::Value>(&link, false).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(read_config::<serde_json::Value>(&path, true).is_err());
        assert!(read_config::<serde_json::Value>(&path, false).is_ok());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }

    fn uuid_for_test() -> String {
        use rand_core::{OsRng, RngCore};
        format!("{}-{}", std::process::id(), OsRng.next_u64())
    }
}
