//! Typed sudo-level privilege issuance, not exact-command or HTTP authorization.
//! OIDC verification, trusted policy provisioning, local caller attestation, fresh
//! clocks and atomic durable redemption are embedding responsibilities. No executor.
pub mod local;

use crate::{
    field, frost, hex_digest, valid_id, Error, Manifest, Result, Round1Response, SignerEngine,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SUDO_SCHEMA_VERSION: u32 = 2;
pub const MAX_SUDO_TTL_SECS: u64 = 60;
const MAX_POLICY_BYTES: usize = 1_048_576;

/// The transport must construct the authenticated identity from verified OIDC,
/// never from request JSON. Issuer and subject are compared exactly, not by email.
/// Issuer identifiers must be HTTPS URLs. A trusted HTTP OIDC backchannel may be
/// used by the transport, but never changes or normalizes this pinned issuer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoIdentity {
    pub issuer: String,
    pub subject: String,
}

impl SudoIdentity {
    fn validate(&self) -> Result<()> {
        if self.issuer.len() > 2048
            || !self.issuer.starts_with("https://")
            || self.issuer.chars().any(char::is_whitespace)
            || self.subject.is_empty()
            || self.subject.len() > 256
            || self.subject.chars().any(char::is_control)
        {
            return Err(Error::Claims);
        }
        let issuer = url::Url::parse(&self.issuer).map_err(|_| Error::Claims)?;
        if issuer.scheme() != "https"
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err(Error::Claims);
        }
        Ok(())
    }

    fn append(&self, out: &mut Vec<u8>) {
        field(out, self.issuer.as_bytes());
        field(out, self.subject.as_bytes());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoHostPolicy {
    pub attestation_key_epoch: u64,
    pub attestation_public_key: [u8; 32],
    pub callers: BTreeMap<u32, SudoIdentity>,
}

/// Full trusted policy, loaded locally, never accepted as signer request membership.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoPolicy {
    pub schema_version: u32,
    pub manifest: Manifest,
    pub hosts: BTreeMap<String, SudoHostPolicy>,
}

fn strong_key(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| Error::Key)?;
    if key.is_weak() {
        return Err(Error::Key);
    }
    Ok(key)
}

fn verify_ed25519(key: &[u8; 32], message: &[u8], bytes: &[u8]) -> Result<()> {
    let key = strong_key(key).map_err(|_| Error::Proof)?;
    let signature = Signature::from_slice(bytes).map_err(|_| Error::Proof)?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::Proof)
}

impl SudoPolicy {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.manifest.validate()?;
        if self.schema_version != SUDO_SCHEMA_VERSION
            || self.hosts.is_empty()
            || self.hosts.len() > self.manifest.members.len()
        {
            return Err(Error::Manifest);
        }
        let mut out = b"heteronetwork-sudo-policy-v2\0".to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        field(&mut out, self.manifest.digest()?.as_bytes());
        out.extend_from_slice(&(self.hosts.len() as u64).to_be_bytes());
        let mut callers = 0usize;
        let mut host_keys = BTreeSet::new();
        for (node, host) in &self.hosts {
            if !self
                .manifest
                .members
                .iter()
                .any(|member| &member.node_id == node)
                || host.attestation_key_epoch == 0
                || host.callers.is_empty()
                || host.callers.len() > 256
            {
                return Err(Error::Manifest);
            }
            strong_key(&host.attestation_public_key)?;
            if !host_keys.insert(host.attestation_public_key) {
                return Err(Error::Key);
            }
            field(&mut out, node.as_bytes());
            out.extend_from_slice(&host.attestation_key_epoch.to_be_bytes());
            out.extend_from_slice(&host.attestation_public_key);
            out.extend_from_slice(&(host.callers.len() as u64).to_be_bytes());
            callers += host.callers.len();
            if callers > 4096 {
                return Err(Error::Capacity);
            }
            for (uid, identity) in &host.callers {
                if *uid == 0 {
                    return Err(Error::Claims);
                }
                identity.validate()?;
                out.extend_from_slice(&uid.to_be_bytes());
                identity.append(&mut out);
                if out.len() > MAX_POLICY_BYTES {
                    return Err(Error::Capacity);
                }
            }
        }
        Ok(out)
    }

    pub fn validate(&self) -> Result<()> {
        self.canonical_bytes().map(|_| ())
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex_digest(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoGrant {
    pub schema_version: u32,
    pub cluster_id: String,
    pub host_node_id: String,
    pub caller_uid: u32,
    pub runas_uid: u32,
    pub identity: SudoIdentity,
    pub attestation_key_epoch: u64,
    pub requester_public_key: [u8; 32],
    pub manifest_epoch: u64,
    pub manifest_digest: String,
    pub policy_digest: String,
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

fn lifetime(issued: u64, expires: u64, now: u64) -> Result<()> {
    if issued > now || expires <= now || expires <= issued || expires - issued > MAX_SUDO_TTL_SECS {
        return Err(Error::Time);
    }
    Ok(())
}

impl SudoGrant {
    fn shape(&self) -> Result<()> {
        if self.schema_version != SUDO_SCHEMA_VERSION
            || !valid_id(&self.cluster_id)
            || !valid_id(&self.host_node_id)
            || self.caller_uid == 0
            || self.runas_uid != 0
            || self.attestation_key_epoch == 0
            || self.manifest_epoch == 0
            || self.nonce == [0; 32]
            || [&self.manifest_digest, &self.policy_digest]
                .iter()
                .any(|digest| {
                    digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
        {
            return Err(Error::Claims);
        }
        self.identity.validate()?;
        strong_key(&self.requester_public_key)?;
        Ok(())
    }

    pub fn validate(&self, policy: &SudoPolicy, now: u64) -> Result<()> {
        self.shape()?;
        if self.policy_digest != policy.digest()?
            || self.cluster_id != policy.manifest.cluster_id
            || self.manifest_epoch != policy.manifest.epoch
            || self.manifest_digest != policy.manifest.digest()?
        {
            return Err(Error::Claims);
        }
        let host = policy.hosts.get(&self.host_node_id).ok_or(Error::Claims)?;
        if self.attestation_key_epoch != host.attestation_key_epoch
            || host.callers.get(&self.caller_uid) != Some(&self.identity)
        {
            return Err(Error::Claims);
        }
        lifetime(self.issued_at, self.expires_at, now)
    }

    /// Exact bytes for the pinned host attestation key. Scope is the fixed sudo-v2 domain.
    pub fn attestation_bytes(&self) -> Result<Vec<u8>> {
        self.shape()?;
        let mut out = b"heteronetwork-sudo-host-attestation-v2\0".to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        field(&mut out, self.cluster_id.as_bytes());
        field(&mut out, self.host_node_id.as_bytes());
        out.extend_from_slice(&self.caller_uid.to_be_bytes());
        out.extend_from_slice(&self.runas_uid.to_be_bytes());
        self.identity.append(&mut out);
        out.extend_from_slice(&self.attestation_key_epoch.to_be_bytes());
        out.extend_from_slice(&self.requester_public_key);
        out.extend_from_slice(&self.manifest_epoch.to_be_bytes());
        field(&mut out, self.manifest_digest.as_bytes());
        field(&mut out, self.policy_digest.as_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(out)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoChallenge {
    pub grant: SudoGrant,
    pub host_signature: Vec<u8>,
}

impl SudoChallenge {
    pub fn validate(&self, policy: &SudoPolicy, now: u64) -> Result<()> {
        self.grant.validate(policy, now)?;
        let host = policy
            .hosts
            .get(&self.grant.host_node_id)
            .ok_or(Error::Claims)?;
        verify_ed25519(
            &host.attestation_public_key,
            &self.grant.attestation_bytes()?,
            &self.host_signature,
        )
    }

    /// Only this typed host-authenticated challenge is threshold-signed.
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        if self.host_signature.len() != 64 {
            return Err(Error::Proof);
        }
        let mut out = b"heteronetwork-sudo-privilege-grant-v2\0".to_vec();
        field(&mut out, &self.grant.attestation_bytes()?);
        field(&mut out, &self.host_signature);
        Ok(out)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoRound1Request {
    pub identifier: u16,
    pub challenge: SudoChallenge,
    pub requester_proof: Vec<u8>,
}

impl SudoRound1Request {
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        let mut out = b"heteronetwork-sudo-round1-pop-v2\0".to_vec();
        out.extend_from_slice(&self.identifier.to_be_bytes());
        field(&mut out, &self.challenge.signing_bytes()?);
        Ok(out)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SudoRound2Request {
    pub identifier: u16,
    pub session_id: [u8; 32],
    pub challenge: SudoChallenge,
    pub signing_package: frost::SigningPackage,
    pub requester_proof: Vec<u8>,
}

impl SudoRound2Request {
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        // Check sizes before serializing an untrusted FROST transcript.
        if self.signing_package.signing_commitments().len() > 1024
            || self.signing_package.message().len() > 8192
        {
            return Err(Error::Package);
        }
        let mut out = b"heteronetwork-sudo-round2-pop-v2\0".to_vec();
        out.extend_from_slice(&self.identifier.to_be_bytes());
        out.extend_from_slice(&self.session_id);
        field(&mut out, &self.challenge.signing_bytes()?);
        field(
            &mut out,
            &self
                .signing_package
                .serialize()
                .map_err(|_| Error::Package)?,
        );
        Ok(out)
    }
}

impl SignerEngine {
    fn validate_sudo_identity(
        &self,
        policy: &SudoPolicy,
        authenticated: &SudoIdentity,
        challenge: &SudoChallenge,
        now: u64,
    ) -> Result<()> {
        if self.manifest.digest()? != policy.manifest.digest()? {
            return Err(Error::Manifest);
        }
        challenge.validate(policy, now)?;
        if authenticated != &challenge.grant.identity {
            return Err(Error::Proof);
        }
        Ok(())
    }

    pub fn round1_sudo(
        &mut self,
        policy: &SudoPolicy,
        authenticated: &SudoIdentity,
        request: &SudoRound1Request,
        now: u64,
    ) -> Result<Round1Response> {
        self.validate_sudo_identity(policy, authenticated, &request.challenge, now)?;
        if request.identifier != self.identifier {
            return Err(Error::Proof);
        }
        verify_ed25519(
            &request.challenge.grant.requester_public_key,
            &request.proof_bytes()?,
            &request.requester_proof,
        )?;
        self.allocate_pending(
            request.challenge.signing_bytes()?,
            request.challenge.grant.expires_at,
            now,
        )
    }

    pub fn round2_sudo(
        &mut self,
        policy: &SudoPolicy,
        authenticated: &SudoIdentity,
        request: &SudoRound2Request,
        now: u64,
    ) -> Result<frost::round2::SignatureShare> {
        // Burn the ephemeral nonce even when policy, identity, attestation or PoP is invalid.
        let pending = self
            .pending
            .remove(&request.session_id)
            .ok_or(Error::Session)?;
        self.validate_sudo_identity(policy, authenticated, &request.challenge, now)?;
        if request.identifier != self.identifier {
            return Err(Error::Proof);
        }
        verify_ed25519(
            &request.challenge.grant.requester_public_key,
            &request.proof_bytes()?,
            &request.requester_proof,
        )?;
        self.sign_pending(
            pending,
            &request.challenge.signing_bytes()?,
            &request.signing_package,
            now,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoToken {
    pub challenge: SudoChallenge,
    pub signature: Vec<u8>,
}

/// Created by trusted local IPC for this invocation, NOT trusted from token JSON.
/// The caller must enforce fresh unpredictable nonce allocation and durable single use.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SudoLocalInvocation {
    pub host_node_id: String,
    pub caller_uid: u32,
    pub runas_uid: u32,
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl SudoLocalInvocation {
    pub fn proof_bytes(&self, token: &SudoToken) -> Result<Vec<u8>> {
        if !valid_id(&self.host_node_id)
            || self.caller_uid == 0
            || self.runas_uid != 0
            || self.nonce == [0; 32]
            || token.signature.len() != 64
        {
            return Err(Error::Claims);
        }
        let mut out = b"heteronetwork-sudo-redemption-pop-v2\0".to_vec();
        field(&mut out, &token.challenge.signing_bytes()?);
        field(&mut out, &token.signature);
        field(&mut out, self.host_node_id.as_bytes());
        out.extend_from_slice(&self.caller_uid.to_be_bytes());
        out.extend_from_slice(&self.runas_uid.to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(out)
    }
}

/// No deserialization or public constructor. This is verification evidence, not consumption.
#[derive(Clone, Debug)]
pub struct VerifiedSudoGrant {
    grant: SudoGrant,
    invocation: SudoLocalInvocation,
}

impl VerifiedSudoGrant {
    pub fn grant(&self) -> &SudoGrant {
        &self.grant
    }
    pub fn invocation(&self) -> &SudoLocalInvocation {
        &self.invocation
    }
    /// Recheck a fresh trusted time after acquiring the redemption writer lock and before admission.
    pub fn validate_at(&self, now: u64) -> Result<()> {
        lifetime(self.grant.issued_at, self.grant.expires_at, now)?;
        lifetime(self.invocation.issued_at, self.invocation.expires_at, now)
    }
}

pub fn verify_sudo_redemption(
    policy: &SudoPolicy,
    token: &SudoToken,
    invocation: &SudoLocalInvocation,
    requester_proof: &[u8],
    now: u64,
) -> Result<VerifiedSudoGrant> {
    token.challenge.validate(policy, now)?;
    let grant = &token.challenge.grant;
    if invocation.host_node_id != grant.host_node_id
        || invocation.caller_uid != grant.caller_uid
        || invocation.runas_uid != grant.runas_uid
        || invocation.nonce == grant.nonce
        || invocation.issued_at < grant.issued_at
        || invocation.expires_at > grant.expires_at
    {
        return Err(Error::Claims);
    }
    lifetime(invocation.issued_at, invocation.expires_at, now)?;
    verify_ed25519(
        &grant.requester_public_key,
        &invocation.proof_bytes(token)?,
        requester_proof,
    )?;
    let signature =
        frost::Signature::deserialize(&token.signature).map_err(|_| Error::Signature)?;
    policy
        .manifest
        .public_keys()?
        .verifying_key()
        .verify(&token.challenge.signing_bytes()?, &signature)
        .map_err(|_| Error::Signature)?;
    Ok(VerifiedSudoGrant {
        grant: grant.clone(),
        invocation: invocation.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Member;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    struct Fixture {
        policy: SudoPolicy,
        engines: Vec<SignerEngine>,
        host: SigningKey,
        requester: SigningKey,
        challenge: SudoChallenge,
    }

    fn fixture() -> Result<Fixture> {
        let mut rng = ChaCha20Rng::from_seed([37; 32]);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .map_err(|_| Error::Key)?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "sudo-core-test".into(),
            epoch: 7,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://signer-{identifier}.example/"),
                })
                .collect(),
            public_key_package: public.serialize().map_err(|_| Error::Key)?,
        };
        let host = SigningKey::from_bytes(&[11; 32]);
        let requester = SigningKey::from_bytes(&[12; 32]);
        let identity = SudoIdentity {
            issuer: "https://id.example/realms/owner".into(),
            subject: "owner-subject".into(),
        };
        let policy = SudoPolicy {
            schema_version: SUDO_SCHEMA_VERSION,
            manifest: manifest.clone(),
            hosts: BTreeMap::from([(
                "node-1".into(),
                SudoHostPolicy {
                    attestation_key_epoch: 3,
                    attestation_public_key: host.verifying_key().to_bytes(),
                    callers: BTreeMap::from([(1000, identity.clone())]),
                },
            )]),
        };
        let grant = SudoGrant {
            schema_version: SUDO_SCHEMA_VERSION,
            cluster_id: manifest.cluster_id.clone(),
            host_node_id: "node-1".into(),
            caller_uid: 1000,
            runas_uid: 0,
            identity,
            attestation_key_epoch: 3,
            requester_public_key: requester.verifying_key().to_bytes(),
            manifest_epoch: manifest.epoch,
            manifest_digest: manifest.digest()?,
            policy_digest: policy.digest()?,
            nonce: [13; 32],
            issued_at: 100,
            expires_at: 160,
        };
        let host_signature = host.sign(&grant.attestation_bytes()?).to_bytes().to_vec();
        let challenge = SudoChallenge {
            grant,
            host_signature,
        };
        let engines = manifest
            .members
            .iter()
            .map(|member| {
                let id = frost::Identifier::try_from(member.identifier).map_err(|_| Error::Key)?;
                let key =
                    frost::keys::KeyPackage::try_from(shares.get(&id).ok_or(Error::Key)?.clone())
                        .map_err(|_| Error::Key)?;
                SignerEngine::new(manifest.clone(), &member.node_id, key, 4, 30)
            })
            .collect::<Result<_>>()?;
        Ok(Fixture {
            policy,
            engines,
            host,
            requester,
            challenge,
        })
    }

    fn first(f: &Fixture, identifier: u16) -> Result<SudoRound1Request> {
        let mut request = SudoRound1Request {
            identifier,
            challenge: f.challenge.clone(),
            requester_proof: vec![],
        };
        request.requester_proof = f
            .requester
            .sign(&request.proof_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(request)
    }

    fn rounds(f: &mut Fixture) -> Result<(Round1Response, Round1Response, frost::SigningPackage)> {
        let a = first(f, 1)?;
        let b = first(f, 2)?;
        let identity = &f.challenge.grant.identity;
        let ra = f.engines[0].round1_sudo(&f.policy, identity, &a, 100)?;
        let rb = f.engines[1].round1_sudo(&f.policy, identity, &b, 100)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([
                (
                    frost::Identifier::try_from(ra.identifier).map_err(|_| Error::Key)?,
                    ra.commitments,
                ),
                (
                    frost::Identifier::try_from(rb.identifier).map_err(|_| Error::Key)?,
                    rb.commitments,
                ),
            ]),
            &f.challenge.signing_bytes()?,
        );
        Ok((ra, rb, package))
    }

    fn second(
        f: &Fixture,
        response: &Round1Response,
        package: &frost::SigningPackage,
    ) -> Result<SudoRound2Request> {
        let mut request = SudoRound2Request {
            identifier: response.identifier,
            session_id: response.session_id,
            challenge: f.challenge.clone(),
            signing_package: package.clone(),
            requester_proof: vec![],
        };
        request.requester_proof = f
            .requester
            .sign(&request.proof_bytes()?)
            .to_bytes()
            .to_vec();
        Ok(request)
    }

    fn issue(f: &mut Fixture) -> Result<SudoToken> {
        let (ra, rb, package) = rounds(f)?;
        let a = second(f, &ra, &package)?;
        let b = second(f, &rb, &package)?;
        let identity = &f.challenge.grant.identity;
        let sa = f.engines[0].round2_sudo(&f.policy, identity, &a, 101)?;
        let sb = f.engines[1].round2_sudo(&f.policy, identity, &b, 101)?;
        assert_eq!(
            f.engines[0].round2_sudo(&f.policy, identity, &a, 101),
            Err(Error::Session)
        );
        let signature = frost::aggregate(
            &package,
            &BTreeMap::from([
                (
                    frost::Identifier::try_from(1u16).map_err(|_| Error::Key)?,
                    sa,
                ),
                (
                    frost::Identifier::try_from(2u16).map_err(|_| Error::Key)?,
                    sb,
                ),
            ]),
            &f.policy.manifest.public_keys()?,
        )
        .map_err(|_| Error::Signature)?
        .serialize()
        .map_err(|_| Error::Signature)?;
        Ok(SudoToken {
            challenge: f.challenge.clone(),
            signature,
        })
    }

    #[test]
    fn majority_issuance_and_fresh_local_redemption() -> Result<()> {
        let mut f = fixture()?;
        let token = issue(&mut f)?;
        let invocation = SudoLocalInvocation {
            host_node_id: "node-1".into(),
            caller_uid: 1000,
            runas_uid: 0,
            nonce: [55; 32],
            issued_at: 102,
            expires_at: 150,
        };
        let proof = f
            .requester
            .sign(&invocation.proof_bytes(&token)?)
            .to_bytes();
        let verified = verify_sudo_redemption(&f.policy, &token, &invocation, &proof, 103)?;
        assert_eq!(verified.grant(), &token.challenge.grant);
        assert_eq!(verified.invocation(), &invocation);
        assert_eq!(verified.validate_at(150), Err(Error::Time));
        assert!(verify_sudo_redemption(&f.policy, &token, &invocation, &proof, 99).is_err());
        for mutation in 0..7 {
            let mut local = invocation.clone();
            match mutation {
                0 => local.nonce[0] ^= 1,
                1 => local.caller_uid = 1001,
                2 => local.host_node_id = "node-2".into(),
                3 => local.runas_uid = 1000,
                4 => local.nonce = token.challenge.grant.nonce,
                5 => local.expires_at = 161,
                _ => local.issued_at = 99,
            }
            assert!(verify_sudo_redemption(&f.policy, &token, &local, &proof, 103).is_err());
        }
        let mut bad = token.clone();
        bad.signature[0] ^= 1;
        let pop = f.requester.sign(&invocation.proof_bytes(&bad)?).to_bytes();
        assert_eq!(
            verify_sudo_redemption(&f.policy, &bad, &invocation, &pop, 103).err(),
            Some(Error::Signature)
        );
        // Round-one PoP is never a redemption proof, even for the same requester.
        assert!(verify_sudo_redemption(
            &f.policy,
            &token,
            &invocation,
            &first(&f, 1)?.requester_proof,
            103
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn policy_digest_pins_every_host_and_rejects_shared_or_foreign_keys() -> Result<()> {
        let f = fixture()?;
        let mut policy = f.policy.clone();
        let mut other = policy.hosts.get("node-1").ok_or(Error::Manifest)?.clone();
        policy.hosts.insert("node-2".into(), other.clone());
        assert_eq!(policy.validate(), Err(Error::Key));
        other.attestation_public_key = SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes();
        policy.hosts.insert("node-2".into(), other);
        policy.validate()?;
        let digest = policy.digest()?;
        policy.manifest.members.reverse();
        assert_eq!(policy.digest()?, digest);
        policy
            .hosts
            .get_mut("node-2")
            .ok_or(Error::Manifest)?
            .callers
            .get_mut(&1000)
            .ok_or(Error::Claims)?
            .subject
            .push('x');
        assert_ne!(policy.digest()?, digest);
        assert!(f.challenge.validate(&policy, 100).is_err());
        let host = policy.hosts.remove("node-2").ok_or(Error::Manifest)?;
        policy.hosts.insert("foreign-host".into(), host);
        assert_eq!(policy.validate(), Err(Error::Manifest));
        let mut policy = f.policy;
        policy
            .hosts
            .get_mut("node-1")
            .ok_or(Error::Manifest)?
            .attestation_public_key = [0; 32];
        assert_eq!(policy.validate(), Err(Error::Key));
        Ok(())
    }

    #[test]
    fn issuer_is_https_and_identity_is_exact_in_both_rounds() -> Result<()> {
        let mut f = fixture()?;
        let first = first(&f, 1)?;
        for issuer in [
            "http://127.0.0.1/realms/owner",
            "https://u:p@id.example/realm",
            "https://id.example/realm?x=1",
        ] {
            let mut identity = f.challenge.grant.identity.clone();
            identity.issuer = issuer.into();
            assert!(identity.validate().is_err());
        }
        for change in 0..2 {
            let mut identity = f.challenge.grant.identity.clone();
            if change == 0 {
                identity.issuer.push('/');
            } else {
                identity.subject.push('x');
            }
            assert_eq!(
                f.engines[0]
                    .round1_sudo(&f.policy, &identity, &first, 100)
                    .err(),
                Some(Error::Proof)
            );
            let (ra, _, package) = rounds(&mut f)?;
            let request = second(&f, &ra, &package)?;
            assert_eq!(
                f.engines[0].round2_sudo(&f.policy, &identity, &request, 101),
                Err(Error::Proof)
            );
            assert_eq!(
                f.engines[0].round2_sudo(&f.policy, &f.challenge.grant.identity, &request, 101),
                Err(Error::Session)
            );
        }
        Ok(())
    }

    #[test]
    fn host_attestation_binds_complete_grant_and_requester_key() -> Result<()> {
        let mut f = fixture()?;
        for change in 0..14 {
            let mut altered = f.challenge.clone();
            match change {
                0 => altered.grant.cluster_id.push('x'),
                1 => altered.grant.host_node_id = "node-2".into(),
                2 => altered.grant.caller_uid += 1,
                3 => altered.grant.runas_uid = 1,
                4 => altered.grant.identity.subject.push('x'),
                5 => altered.grant.attestation_key_epoch += 1,
                6 => {
                    altered.grant.requester_public_key =
                        SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes()
                }
                7 => altered.grant.manifest_epoch += 1,
                8 => altered.grant.policy_digest = "0".repeat(64),
                9 => altered.grant.nonce[0] ^= 1,
                10 => altered.grant.issued_at -= 1,
                11 => altered.grant.expires_at -= 1,
                12 => altered.grant.manifest_digest = "0".repeat(64),
                _ => altered.host_signature[0] ^= 1,
            }
            assert!(altered.validate(&f.policy, 100).is_err());
        }
        let mut request = first(&f, 1)?;
        request.requester_proof = f.host.sign(&request.proof_bytes()?).to_bytes().to_vec();
        assert_eq!(
            f.engines[0]
                .round1_sudo(&f.policy, &f.challenge.grant.identity, &request, 100)
                .err(),
            Some(Error::Proof)
        );
        let mut grant = f.challenge.grant.clone();
        grant.expires_at = 161;
        assert_eq!(grant.validate(&f.policy, 100), Err(Error::Time));
        grant.expires_at = 101;
        grant.validate(&f.policy, 100)?;
        assert_eq!(grant.validate(&f.policy, 101), Err(Error::Time));
        grant.requester_public_key = [0; 32];
        assert_eq!(grant.validate(&f.policy, 100), Err(Error::Key));
        Ok(())
    }

    #[test]
    fn round_two_transcript_and_policy_failures_burn_nonce() -> Result<()> {
        for change in 0..8 {
            let mut f = fixture()?;
            let (ra, _, package) = rounds(&mut f)?;
            let valid = second(&f, &ra, &package)?;
            let mut altered = valid.clone();
            let mut policy = f.policy.clone();
            match change {
                0 => altered.identifier = 2,
                1 => altered.requester_proof = first(&f, 1)?.requester_proof,
                2 => {
                    altered.signing_package = frost::SigningPackage::new(
                        package.signing_commitments().clone(),
                        b"other-domain",
                    );
                    // No new PoP: demonstrates binding of the exact round-two package.
                }
                3 => {
                    let mut commitments = package.signing_commitments().clone();
                    commitments.remove(&frost::Identifier::try_from(2u16).map_err(|_| Error::Key)?);
                    altered.signing_package =
                        frost::SigningPackage::new(commitments, &f.challenge.signing_bytes()?);
                    altered.requester_proof = f
                        .requester
                        .sign(&altered.proof_bytes()?)
                        .to_bytes()
                        .to_vec();
                }
                4 => {
                    policy
                        .hosts
                        .get_mut("node-1")
                        .ok_or(Error::Manifest)?
                        .attestation_key_epoch += 1
                }
                5 => altered.challenge.host_signature[0] ^= 1,
                6 => {
                    altered.challenge.grant.nonce[0] ^= 1;
                    altered.challenge.host_signature = f
                        .host
                        .sign(&altered.challenge.grant.attestation_bytes()?)
                        .to_bytes()
                        .to_vec();
                    altered.requester_proof = f
                        .requester
                        .sign(&altered.proof_bytes()?)
                        .to_bytes()
                        .to_vec();
                }
                _ => {
                    altered.session_id = [99; 32];
                    altered.requester_proof = f
                        .requester
                        .sign(&altered.proof_bytes()?)
                        .to_bytes()
                        .to_vec();
                    altered.session_id = valid.session_id;
                }
            }
            assert!(f.engines[0]
                .round2_sudo(&policy, &f.challenge.grant.identity, &altered, 101)
                .is_err());
            assert_eq!(
                f.engines[0].round2_sudo(&f.policy, &f.challenge.grant.identity, &valid, 101),
                Err(Error::Session)
            );
        }
        Ok(())
    }

    #[test]
    fn capacity_expiry_restart_and_round_one_target_binding() -> Result<()> {
        let mut f = fixture()?;
        f.engines[0].max_pending = 1;
        f.engines[0].pending_ttl_secs = 2;
        let request = first(&f, 1)?;
        assert_eq!(
            f.engines[1]
                .round1_sudo(&f.policy, &f.challenge.grant.identity, &request, 100)
                .err(),
            Some(Error::Proof)
        );
        let (ra, _, package) = rounds(&mut f)?;
        assert_eq!(
            f.engines[0]
                .round1_sudo(&f.policy, &f.challenge.grant.identity, &request, 100)
                .err(),
            Some(Error::Capacity)
        );
        let second = second(&f, &ra, &package)?;
        let mut restarted = SignerEngine::new(
            f.policy.manifest.clone(),
            "node-1",
            f.engines[0].key.clone(),
            1,
            2,
        )?;
        assert_eq!(
            restarted.round2_sudo(&f.policy, &f.challenge.grant.identity, &second, 101),
            Err(Error::Session)
        );
        assert_eq!(
            f.engines[0].round2_sudo(&f.policy, &f.challenge.grant.identity, &second, 102),
            Err(Error::Time)
        );
        assert_eq!(
            f.engines[0].round2_sudo(&f.policy, &f.challenge.grant.identity, &second, 102),
            Err(Error::Session)
        );
        let new =
            f.engines[0].round1_sudo(&f.policy, &f.challenge.grant.identity, &request, 102)?;
        assert_ne!(new.session_id, ra.session_id);
        assert_ne!(new.commitments, ra.commitments);
        Ok(())
    }
}
