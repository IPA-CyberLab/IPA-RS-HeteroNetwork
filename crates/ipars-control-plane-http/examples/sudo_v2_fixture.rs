//! Disposable full-v2 fixture only. Never provision these dealer shares outside the container.
#[cfg(target_os = "linux")]
mod linux {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use ipars_control_plane_http::{
        quorum::sudo::sudo_signer_router, WebAuthProvider, WebUiAuthConfig,
    };
    use ipars_quorum::{
        frost,
        sudo::{
            SudoHostPolicy, SudoIdentity, SudoLocalInvocation, SudoPolicy, SudoToken,
            SUDO_SCHEMA_VERSION,
        },
        Manifest, Member,
    };
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        os::unix::fs::OpenOptionsExt,
        path::Path,
    };

    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    const ROOT: &str = "/opt/full-v2";
    const ADDRESS: &str = "172.30.99.2";
    const ISSUER: &str = "https://owner.invalid/realms/disposable";

    fn private(path: impl AsRef<Path>, bytes: &[u8]) -> Result {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?
            .write_all(bytes)?;
        Ok(())
    }

    #[tokio::main]
    pub async fn run() -> Result {
        if !Path::new("/.dockerenv").exists() || !Path::new("/opt/full-v2/DISPOSABLE").exists() {
            return Err("disposable full-v2 container required".into());
        }
        let args: Vec<_> = std::env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("init") => {
                let (shares, public) = frost::keys::generate_with_dealer(
                    3,
                    2,
                    frost::keys::IdentifierList::Default,
                    rand_core::OsRng,
                )?;
                let manifest = Manifest {
                    schema_version: 1,
                    cluster_id: "disposable-full-v2".into(),
                    epoch: 1,
                    members: (1..=3)
                        .map(|identifier| Member {
                            identifier,
                            node_id: format!("node-{identifier}"),
                            endpoint: format!("http://{ADDRESS}:{}/", 19100 + identifier),
                        })
                        .collect(),
                    public_key_package: public.serialize()?,
                };
                let host = SigningKey::generate(&mut rand_core::OsRng);
                let requester = SigningKey::generate(&mut rand_core::OsRng);
                let policy = SudoPolicy {
                    schema_version: SUDO_SCHEMA_VERSION,
                    manifest,
                    hosts: BTreeMap::from([(
                        "node-1".into(),
                        SudoHostPolicy {
                            attestation_key_epoch: 1,
                            attestation_public_key: host.verifying_key().to_bytes(),
                            callers: BTreeMap::from([(
                                1000,
                                SudoIdentity {
                                    issuer: ISSUER.into(),
                                    subject: "owner".into(),
                                },
                            )]),
                        },
                    )]),
                };
                policy.validate()?;
                private(format!("{ROOT}/policy.json"), &serde_json::to_vec(&policy)?)?;
                private(
                    "/etc/ipars-sudo-v2/config.json",
                    &serde_json::to_vec(
                        &serde_json::json!({"host_node_id":"node-1", "policy":policy}),
                    )?,
                )?;
                private("/etc/ipars-sudo-v2/host.key", &host.to_bytes())?;
                private(
                    format!("{ROOT}/requester.key"),
                    URL_SAFE_NO_PAD.encode(requester.to_bytes()).as_bytes(),
                )?;
                private(
                    format!("{ROOT}/requester.pub"),
                    &serde_json::to_vec(&requester.verifying_key().to_bytes())?,
                )?;
                for id in 1..=3u16 {
                    let key = frost::keys::KeyPackage::try_from(
                        shares
                            .get(&frost::Identifier::try_from(id)?)
                            .ok_or("missing share")?
                            .clone(),
                    )?;
                    private(format!("{ROOT}/share-{id}"), &key.serialize()?)?;
                }
            }
            Some("serve") => {
                let id: u16 = args.get(2).ok_or("missing signer id")?.parse()?;
                if !(1..=3).contains(&id) {
                    return Err("invalid signer id".into());
                }
                let policy =
                    serde_json::from_slice(&std::fs::read(format!("{ROOT}/policy.json"))?)?;
                let key = frost::keys::KeyPackage::deserialize(&std::fs::read(format!(
                    "{ROOT}/share-{id}"
                ))?)?;
                // Explicit trusted local backchannel, not a TLS verification exception.
                let auth = WebUiAuthConfig::new(
                    WebAuthProvider::Keycloak,
                    ISSUER.into(),
                    "disposable".into(),
                    None,
                    Some("http://127.0.0.1:19200/realms/disposable".into()),
                    "openid".into(),
                )?
                .with_required_email("owner@example.invalid".into())?
                .with_required_subject("owner".into())?;
                let app = sudo_signer_router(policy, key, format!("node-{id}"), auth)?;
                let listener =
                    tokio::net::TcpListener::bind(format!("{ADDRESS}:{}", 19100 + id)).await?;
                axum::serve(listener, app).await?;
            }
            Some("redeem-proof") => {
                // Typed local proof only; no arbitrary signing or offline threshold signing mode.
                let mut bytes = Vec::new();
                std::io::stdin().take(32769).read_to_end(&mut bytes)?;
                if bytes.len() > 32768 {
                    return Err("oversized proof input".into());
                }
                let (token, invocation): (SudoToken, SudoLocalInvocation) =
                    serde_json::from_slice(&bytes)?;
                let seed =
                    URL_SAFE_NO_PAD.decode(std::fs::read(format!("{ROOT}/requester.key"))?)?;
                let seed: [u8; 32] = seed.try_into().map_err(|_| "invalid requester seed")?;
                let proof = SigningKey::from_bytes(&seed)
                    .sign(&invocation.proof_bytes(&token)?)
                    .to_bytes()
                    .to_vec();
                serde_json::to_writer(std::io::stdout(), &proof)?;
            }
            _ => return Err("expected init, serve ID, or redeem-proof".into()),
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("sudo_v2_fixture requires a disposable Linux container");
    std::process::ExitCode::FAILURE
}
