//! Offline disposable test issuance only. Never deploy this example or fixture keys.
use ed25519_dalek::{Signer, SigningKey};
use ipars_host_authorization_prototype::privilege_v2::LocalV2Config;
use ipars_quorum::{
    frost,
    sudo::{
        SudoChallenge, SudoHostPolicy, SudoIdentity, SudoLocalInvocation, SudoPolicy,
        SudoRound1Request, SudoRound2Request, SudoToken,
    },
    Manifest, Member, SignerEngine,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

#[derive(Serialize, Deserialize)]
struct Keys {
    shares: Vec<frost::keys::KeyPackage>,
    requester: [u8; 32],
}
const KEYS: &str = "/opt/quorum-lifecycle/v2-test-keys.json";
const CONFIG: &str = "/etc/ipars-sudo-v2/config.json";

fn private(path: &str, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new("/.dockerenv").exists() || !nix::unistd::geteuid().is_root() {
        return Err("disposable root container only".into());
    }
    let mode = std::env::args().nth(1).ok_or("fixture mode required")?;
    if mode == "provision" {
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, OsRng)?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "disposable-sudo-v2".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://node-{identifier}.invalid/"),
                })
                .collect(),
            public_key_package: public.serialize()?,
        };
        let host = SigningKey::generate(&mut OsRng);
        let policy = SudoPolicy {
            schema_version: 2,
            manifest,
            hosts: BTreeMap::from([(
                "node-1".into(),
                SudoHostPolicy {
                    attestation_key_epoch: 1,
                    attestation_public_key: host.verifying_key().to_bytes(),
                    callers: BTreeMap::from([(
                        1000,
                        SudoIdentity {
                            issuer: "https://issuer.invalid/realm".into(),
                            subject: "fixture-owner".into(),
                        },
                    )]),
                },
            )]),
        };
        let config = LocalV2Config {
            host_node_id: "node-1".into(),
            policy,
        };
        config.policy.validate()?;
        private(CONFIG, &serde_json::to_vec(&config)?)?;
        private("/etc/ipars-sudo-v2/host.key", &host.to_bytes())?;
        let keys = Keys {
            shares: shares
                .into_values()
                .map(frost::keys::KeyPackage::try_from)
                .collect::<Result<_, _>>()?,
            requester: SigningKey::generate(&mut OsRng).to_bytes(),
        };
        private(KEYS, &serde_json::to_vec(&keys)?)?;
        return Ok(());
    }
    let keys: Keys = serde_json::from_slice(&std::fs::read(KEYS)?)?;
    let requester = SigningKey::from_bytes(&keys.requester);
    if mode == "requester" {
        println!(
            "{}",
            serde_json::to_string(&requester.verifying_key().to_bytes())?
        );
        return Ok(());
    }
    let config: LocalV2Config = serde_json::from_slice(&std::fs::read(CONFIG)?)?;
    let mut input = Vec::new();
    std::io::stdin().take(16385).read_to_end(&mut input)?;
    if input.len() > 16384 {
        return Err("fixture input too large".into());
    }
    if mode == "issue" {
        let challenge: SudoChallenge = serde_json::from_slice(&input)?;
        let now = ipars_host_authorization_prototype::privilege_v2::now()?;
        challenge.validate(&config.policy, now)?;
        if challenge.grant.requester_public_key != requester.verifying_key().to_bytes() {
            return Err("fixture requester mismatch".into());
        }
        let mut engines = Vec::new();
        let mut responses = Vec::new();
        let mut commitments = BTreeMap::new();
        for (key, member) in keys
            .shares
            .iter()
            .zip(&config.policy.manifest.members)
            .take(2)
        {
            let mut engine = SignerEngine::new(
                config.policy.manifest.clone(),
                &member.node_id,
                key.clone(),
                1,
                30,
            )?;
            let mut request = SudoRound1Request {
                identifier: member.identifier,
                challenge: challenge.clone(),
                requester_proof: vec![],
            };
            request.requester_proof = requester.sign(&request.proof_bytes()?).to_bytes().to_vec();
            let response =
                engine.round1_sudo(&config.policy, &challenge.grant.identity, &request, now)?;
            commitments.insert(
                frost::Identifier::try_from(response.identifier)?,
                response.commitments,
            );
            responses.push(response);
            engines.push(engine);
        }
        let package = frost::SigningPackage::new(commitments, &challenge.signing_bytes()?);
        let mut shares = BTreeMap::new();
        for (engine, response) in engines.iter_mut().zip(responses) {
            let mut request = SudoRound2Request {
                identifier: response.identifier,
                session_id: response.session_id,
                challenge: challenge.clone(),
                signing_package: package.clone(),
                requester_proof: vec![],
            };
            request.requester_proof = requester.sign(&request.proof_bytes()?).to_bytes().to_vec();
            shares.insert(
                frost::Identifier::try_from(response.identifier)?,
                engine.round2_sudo(&config.policy, &challenge.grant.identity, &request, now)?,
            );
        }
        let token = SudoToken {
            challenge,
            signature: frost::aggregate(&package, &shares, &config.policy.manifest.public_keys()?)?
                .serialize()?,
        };
        println!("{}", serde_json::to_string(&token)?);
    } else if mode == "redeem" {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Redemption {
            token: SudoToken,
            invocation: SudoLocalInvocation,
        }
        let request: Redemption = serde_json::from_slice(&input)?;
        request.token.challenge.validate(
            &config.policy,
            ipars_host_authorization_prototype::privilege_v2::now()?,
        )?;
        if request.token.challenge.grant.requester_public_key
            != requester.verifying_key().to_bytes()
        {
            return Err("fixture requester mismatch".into());
        }
        println!(
            "{}",
            serde_json::to_string(
                &requester
                    .sign(&request.invocation.proof_bytes(&request.token)?)
                    .to_bytes()
                    .to_vec()
            )?
        );
    } else {
        return Err("unknown fixture mode".into());
    }
    Ok(())
}
