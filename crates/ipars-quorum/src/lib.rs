//! Frozen-majority authorization for exact HeteroNetwork admin mutations.
//! Transport authentication, owner policy, trusted manifest installation and durable
//! execution replay protection belong to the embedding HTTP/CLI components.

pub use frost_ed25519 as frost;
pub use frost_ed25519::keys::dkg;
mod rotation;
pub use rotation::{verify_rotation, ManifestRotation, ManifestTransition, VerifiedRotation};

use ed25519_dalek::{Signature, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_CAPABILITY_TTL_SECS: u64 = 300;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid frozen manifest")]
    Manifest,
    #[error("invalid capability claims")]
    Claims,
    #[error("capability is not currently valid")]
    Time,
    #[error("requester proof is invalid")]
    Proof,
    #[error("signer key does not match manifest")]
    Key,
    #[error("pending signing capacity exhausted")]
    Capacity,
    #[error("unknown or consumed signing session")]
    Session,
    #[error("signing package does not match approved claims or majority")]
    Package,
    #[error("threshold signature is invalid")]
    Signature,
    #[error("secure randomness unavailable")]
    Random,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub node_id: String,
    pub identifier: u16,
    pub endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub cluster_id: String,
    pub epoch: u64,
    pub members: Vec<Member>,
    pub public_key_package: Vec<u8>,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|b| {
            [
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 15)]),
            ]
        })
        .collect()
}

impl Manifest {
    pub fn public_keys(&self) -> Result<frost::keys::PublicKeyPackage> {
        if self.public_key_package.len() > 262_144 {
            return Err(Error::Manifest);
        }
        frost::keys::PublicKeyPackage::deserialize(&self.public_key_package)
            .map_err(|_| Error::Manifest)
    }

    pub fn threshold(&self) -> u16 {
        (self.members.len() / 2 + 1) as u16
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION
            || self.epoch == 0
            || !valid_id(&self.cluster_id)
            || !(2..=1024).contains(&self.members.len())
        {
            return Err(Error::Manifest);
        }
        let keys = self.public_keys()?;
        if keys.min_signers() != Some(self.threshold())
            || keys.verifying_shares().len() != self.members.len()
        {
            return Err(Error::Manifest);
        }
        let mut nodes = BTreeSet::new();
        let mut identifiers = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for member in &self.members {
            let id = frost::Identifier::try_from(member.identifier).map_err(|_| Error::Manifest)?;
            let endpoint = url::Url::parse(&member.endpoint).map_err(|_| Error::Manifest)?;
            if !valid_id(&member.node_id)
                || !nodes.insert(&member.node_id)
                || !identifiers.insert(id)
                || !keys.verifying_shares().contains_key(&id)
                || !matches!(endpoint.scheme(), "http" | "https")
                || endpoint.host_str().is_none()
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
                || endpoint.query().is_some()
                || endpoint.fragment().is_some()
                || endpoint.path() != "/"
                || !endpoints.insert(endpoint.origin().ascii_serialization())
            {
                return Err(Error::Manifest);
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let mut out = b"heteronetwork-quorum-manifest-v1\0".to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        field(&mut out, self.cluster_id.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_by_key(|member| member.identifier);
        out.extend_from_slice(&(members.len() as u64).to_be_bytes());
        for member in members {
            field(&mut out, member.node_id.as_bytes());
            out.extend_from_slice(&member.identifier.to_be_bytes());
            field(&mut out, member.endpoint.as_bytes());
        }
        let canonical_keys = self
            .public_keys()?
            .serialize()
            .map_err(|_| Error::Manifest)?;
        field(&mut out, &canonical_keys);
        Ok(hex_digest(&out))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityClaims {
    pub schema_version: u32,
    pub cluster_id: String,
    pub epoch: u64,
    pub manifest_digest: String,
    pub method: String,
    pub path: String,
    pub body_sha256: [u8; 32],
    pub requester_public_key: [u8; 32],
    pub request_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl CapabilityClaims {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = b"heteronetwork-quorum-capability-v1\0".to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        field(&mut out, self.cluster_id.as_bytes());
        out.extend_from_slice(&self.epoch.to_be_bytes());
        field(&mut out, self.manifest_digest.as_bytes());
        field(&mut out, self.method.as_bytes());
        field(&mut out, self.path.as_bytes());
        out.extend_from_slice(&self.body_sha256);
        out.extend_from_slice(&self.requester_public_key);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    pub fn proof_bytes(&self) -> Vec<u8> {
        let mut out = b"heteronetwork-quorum-request-proof-v1\0".to_vec();
        field(&mut out, &self.signing_bytes());
        out
    }

    pub fn validate(&self, manifest: &Manifest, now: u64) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION
            || self.cluster_id != manifest.cluster_id
            || self.epoch != manifest.epoch
            || self.manifest_digest != manifest.digest()?
            || self.request_id == [0; 32]
            || !allowed_mutation(&self.method, &self.path)
        {
            return Err(Error::Claims);
        }
        if self.issued_at > now
            || self.expires_at <= now
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_CAPABILITY_TTL_SECS
        {
            return Err(Error::Time);
        }
        Ok(())
    }
}

/// Exact raw paths only: no percent decoding, query strings, or path normalization.
pub fn allowed_mutation(method: &str, path: &str) -> bool {
    let parts: Vec<_> = path.split('/').collect();
    match (method, parts.as_slice()) {
        ("POST", ["", "v1", "admin", "enrollment" | "client-enrollment"])
        | ("POST", ["", "v1", "admin", "quorum", "revocations"])
        | ("PUT", ["", "v1", "admin", "policy"]) => true,
        ("DELETE", ["", "v1", "admin", "nodes", node])
        | ("PUT", ["", "v1", "admin", "nodes", node, "display-name"]) => {
            valid_id(node) && *node != "." && *node != ".."
        }
        ("POST", ["", "v1", "admin", "paths", local, remote, "pin"]) => {
            valid_id(local)
                && valid_id(remote)
                && ![".", ".."].contains(local)
                && ![".", ".."].contains(remote)
        }
        _ => false,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestProof {
    pub signature: Vec<u8>,
}

impl RequestProof {
    pub fn verify(&self, claims: &CapabilityClaims) -> Result<()> {
        let key =
            VerifyingKey::from_bytes(&claims.requester_public_key).map_err(|_| Error::Proof)?;
        let signature = Signature::from_slice(&self.signature).map_err(|_| Error::Proof)?;
        if key.is_weak() {
            return Err(Error::Proof);
        }
        key.verify_strict(&claims.proof_bytes(), &signature)
            .map_err(|_| Error::Proof)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToken {
    pub claims: CapabilityClaims,
    pub signature: Vec<u8>,
}

pub fn verify_capability(
    manifest: &Manifest,
    token: &CapabilityToken,
    proof: &RequestProof,
    method: &str,
    path: &str,
    body: &[u8],
    now: u64,
) -> Result<()> {
    token.claims.validate(manifest, now)?;
    if token.claims.method != method
        || token.claims.path != path
        || token.claims.body_sha256 != <[u8; 32]>::from(Sha256::digest(body))
    {
        return Err(Error::Claims);
    }
    proof.verify(&token.claims)?;
    let signature =
        frost::Signature::deserialize(&token.signature).map_err(|_| Error::Signature)?;
    manifest
        .public_keys()?
        .verifying_key()
        .verify(&token.claims.signing_bytes(), &signature)
        .map_err(|_| Error::Signature)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round1Response {
    pub session_id: [u8; 32],
    pub identifier: u16,
    pub commitments: frost::round1::SigningCommitments,
}

// Secret-bearing structs intentionally have no Debug/Clone/Serialize implementation.
struct Pending {
    message: Vec<u8>,
    created_at: u64,
    expires_at: u64,
    nonces: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}

pub struct SignerEngine {
    manifest: Manifest,
    key: frost::keys::KeyPackage,
    identifier: u16,
    max_pending: usize,
    pending_ttl_secs: u64,
    pending: BTreeMap<[u8; 32], Pending>,
}

impl SignerEngine {
    pub fn new(
        manifest: Manifest,
        node_id: &str,
        key_package: frost::keys::KeyPackage,
        max_pending: usize,
        pending_ttl_secs: u64,
    ) -> Result<Self> {
        manifest.validate()?;
        if !(1..=1024).contains(&max_pending) || !(1..=300).contains(&pending_ttl_secs) {
            return Err(Error::Capacity);
        }
        let member = manifest
            .members
            .iter()
            .find(|member| member.node_id == node_id)
            .ok_or(Error::Key)?;
        let identifier = member.identifier;
        let id = frost::Identifier::try_from(identifier).map_err(|_| Error::Key)?;
        let public = manifest.public_keys()?;
        if key_package.identifier() != &id
            || *key_package.min_signers() != manifest.threshold()
            || key_package.verifying_key() != public.verifying_key()
            || public.verifying_shares().get(&id) != Some(key_package.verifying_share())
            || frost::keys::VerifyingShare::from(*key_package.signing_share())
                != *key_package.verifying_share()
        {
            return Err(Error::Key);
        }
        Ok(Self {
            manifest,
            key: key_package,
            identifier,
            max_pending,
            pending_ttl_secs,
            pending: BTreeMap::new(),
        })
    }

    /// Caller must authorize the configured owner before allocating a signing session.
    pub fn round1(
        &mut self,
        claims: &CapabilityClaims,
        proof: &RequestProof,
        now: u64,
    ) -> Result<Round1Response> {
        self.pending
            .retain(|_, pending| now >= pending.created_at && now < pending.expires_at);
        claims.validate(&self.manifest, now)?;
        proof.verify(claims)?;
        self.allocate_pending(claims.signing_bytes(), claims.expires_at, now)
    }

    fn allocate_pending(
        &mut self,
        message: Vec<u8>,
        expires_at: u64,
        now: u64,
    ) -> Result<Round1Response> {
        self.pending
            .retain(|_, pending| now >= pending.created_at && now < pending.expires_at);
        if self.pending.len() >= self.max_pending {
            return Err(Error::Capacity);
        }
        let mut session_id = [0; 32];
        OsRng
            .try_fill_bytes(&mut session_id)
            .map_err(|_| Error::Random)?;
        if session_id == [0; 32] || self.pending.contains_key(&session_id) {
            return Err(Error::Random);
        }
        let (nonces, commitments) = frost::round1::commit(self.key.signing_share(), &mut OsRng);
        self.pending.insert(
            session_id,
            Pending {
                message,
                created_at: now,
                expires_at: now.saturating_add(self.pending_ttl_secs).min(expires_at),
                nonces,
                commitments,
            },
        );
        Ok(Round1Response {
            session_id,
            identifier: self.identifier,
            commitments,
        })
    }

    pub fn round2(
        &mut self,
        session_id: [u8; 32],
        claims: &CapabilityClaims,
        signing_package: &frost::SigningPackage,
        now: u64,
    ) -> Result<frost::round2::SignatureShare> {
        // Consume first, including malformed submissions. Dropping SigningNonces zeroizes it.
        let pending = self.pending.remove(&session_id).ok_or(Error::Session)?;
        if now < pending.created_at || now >= pending.expires_at {
            return Err(Error::Time);
        }
        claims.validate(&self.manifest, now)?;
        self.sign_pending(pending, &claims.signing_bytes(), signing_package, now)
    }

    fn sign_pending(
        &self,
        pending: Pending,
        message: &[u8],
        signing_package: &frost::SigningPackage,
        now: u64,
    ) -> Result<frost::round2::SignatureShare> {
        if now < pending.created_at || now >= pending.expires_at {
            return Err(Error::Time);
        }
        let commitments = signing_package.signing_commitments();
        let public = self.manifest.public_keys()?;
        if pending.message != message
            || signing_package.message() != message
            || commitments.len() < usize::from(self.manifest.threshold())
            || commitments.len() > self.manifest.members.len()
            || commitments
                .keys()
                .any(|id| !public.verifying_shares().contains_key(id))
            || commitments.get(self.key.identifier()) != Some(&pending.commitments)
        {
            return Err(Error::Package);
        }
        frost::round2::sign(signing_package, &pending.nonces, &self.key).map_err(|_| Error::Package)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    fn fixture() -> Result<(Manifest, Vec<SignerEngine>, CapabilityClaims, RequestProof)> {
        let mut rng = ChaCha20Rng::from_seed([42; 32]);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .map_err(|_| Error::Key)?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "cluster".into(),
            epoch: 1,
            members: (1..=3)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://node-{identifier}.example/"),
                })
                .collect(),
            public_key_package: public.serialize().map_err(|_| Error::Key)?,
        };
        let mut engines = Vec::new();
        for member in &manifest.members {
            let id = frost::Identifier::try_from(member.identifier).map_err(|_| Error::Key)?;
            let share = shares.get(&id).ok_or(Error::Key)?.clone();
            let key = frost::keys::KeyPackage::try_from(share).map_err(|_| Error::Key)?;
            engines.push(SignerEngine::new(
                manifest.clone(),
                &member.node_id,
                key,
                2,
                30,
            )?);
        }
        let requester = SigningKey::from_bytes(&[7; 32]);
        let claims = CapabilityClaims {
            schema_version: 1,
            cluster_id: "cluster".into(),
            epoch: 1,
            manifest_digest: manifest.digest()?,
            method: "PUT".into(),
            path: "/v1/admin/policy".into(),
            body_sha256: Sha256::digest(b"{}").into(),
            requester_public_key: requester.verifying_key().to_bytes(),
            request_id: [9; 32],
            issued_at: 100,
            expires_at: 200,
        };
        let proof = RequestProof {
            signature: requester.sign(&claims.proof_bytes()).to_bytes().to_vec(),
        };
        Ok((manifest, engines, claims, proof))
    }

    #[test]
    fn majority_signs_exact_request_and_replay_consumed() -> Result<()> {
        let (manifest, mut engines, claims, proof) = fixture()?;
        let a = engines[0].round1(&claims, &proof, 100)?;
        let b = engines[1].round1(&claims, &proof, 100)?;
        let ida = frost::Identifier::try_from(a.identifier).map_err(|_| Error::Key)?;
        let idb = frost::Identifier::try_from(b.identifier).map_err(|_| Error::Key)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([(ida, a.commitments), (idb, b.commitments)]),
            &claims.signing_bytes(),
        );
        let sa = engines[0].round2(a.session_id, &claims, &package, 101)?;
        let sb = engines[1].round2(b.session_id, &claims, &package, 101)?;
        assert_eq!(
            engines[0].round2(a.session_id, &claims, &package, 101),
            Err(Error::Session)
        );
        let signature = frost::aggregate(
            &package,
            &BTreeMap::from([(ida, sa), (idb, sb)]),
            &manifest.public_keys()?,
        )
        .map_err(|_| Error::Signature)?;
        let token = CapabilityToken {
            claims: claims.clone(),
            signature: signature.serialize().map_err(|_| Error::Signature)?,
        };
        verify_capability(
            &manifest,
            &token,
            &proof,
            "PUT",
            "/v1/admin/policy",
            b"{}",
            101,
        )?;
        assert_eq!(
            verify_capability(
                &manifest,
                &token,
                &proof,
                "PUT",
                "/v1/admin/policy",
                b"[]",
                101
            ),
            Err(Error::Claims)
        );
        assert_eq!(
            verify_capability(
                &manifest,
                &token,
                &proof,
                "POST",
                "/v1/admin/policy",
                b"{}",
                101
            ),
            Err(Error::Claims)
        );
        assert_eq!(
            verify_capability(
                &manifest,
                &token,
                &proof,
                "PUT",
                "/v1/admin/policy",
                b"{}",
                200
            ),
            Err(Error::Time)
        );
        let mut other = manifest.clone();
        other.epoch += 1;
        assert_eq!(
            verify_capability(
                &other,
                &token,
                &proof,
                "PUT",
                "/v1/admin/policy",
                b"{}",
                101
            ),
            Err(Error::Claims)
        );
        Ok(())
    }

    #[test]
    fn minority_failure_burns_nonce() -> Result<()> {
        let (_, mut engines, claims, proof) = fixture()?;
        let a = engines[0].round1(&claims, &proof, 100)?;
        let id = frost::Identifier::try_from(a.identifier).map_err(|_| Error::Key)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([(id, a.commitments)]),
            &claims.signing_bytes(),
        );
        assert_eq!(
            engines[0].round2(a.session_id, &claims, &package, 101),
            Err(Error::Package)
        );
        assert_eq!(
            engines[0].round2(a.session_id, &claims, &package, 101),
            Err(Error::Session)
        );
        Ok(())
    }

    #[test]
    fn proof_capacity_expiry_and_restart_fail_closed() -> Result<()> {
        let (_, mut engines, claims, proof) = fixture()?;
        let mut changed = claims.clone();
        changed.request_id[0] ^= 1;
        assert!(matches!(
            engines[0].round1(&changed, &proof, 100),
            Err(Error::Proof)
        ));
        let a = engines[0].round1(&claims, &proof, 100)?;
        engines[0].round1(&claims, &proof, 100)?;
        assert!(matches!(
            engines[0].round1(&claims, &proof, 100),
            Err(Error::Capacity)
        ));
        let package = frost::SigningPackage::new(BTreeMap::new(), &claims.signing_bytes());
        assert_eq!(
            engines[0].round2(a.session_id, &claims, &package, 130),
            Err(Error::Time)
        );
        engines[0].round1(&claims, &proof, 130)?;
        let (_, mut restarted, _, _) = fixture()?;
        assert_eq!(
            restarted[0].round2(a.session_id, &claims, &package, 101),
            Err(Error::Session)
        );
        Ok(())
    }

    #[test]
    fn manifest_frozen_membership_threshold_and_canonical_digest() -> Result<()> {
        let (manifest, _, _, _) = fixture()?;
        let mut changed = manifest.clone();
        changed.epoch = 0;
        assert_eq!(changed.validate(), Err(Error::Manifest));
        changed.epoch = manifest.epoch;
        changed.members.reverse();
        assert_eq!(manifest.digest()?, changed.digest()?);
        changed.members[0].identifier = changed.members[1].identifier;
        assert_eq!(changed.validate(), Err(Error::Manifest));
        let public = manifest.public_keys()?;
        for threshold in [None, Some(1), Some(3)] {
            let mut bad = manifest.clone();
            bad.public_key_package = frost::keys::PublicKeyPackage::new(
                public.verifying_shares().clone(),
                *public.verifying_key(),
                threshold,
            )
            .serialize()
            .map_err(|_| Error::Manifest)?;
            assert_eq!(bad.validate(), Err(Error::Manifest));
        }
        Ok(())
    }

    #[test]
    fn allowlist_rejects_normalization_and_non_admin_routes() {
        assert!(allowed_mutation("POST", "/v1/admin/quorum/revocations"));
        assert!(!allowed_mutation("PUT", "/v1/admin/quorum/revocations"));
        for path in [
            "/v1/admin/quorum/revocations/",
            "/v1/admin/quorum/revocations?request_id=unsigned",
            "/v1/admin/policy?x=1",
            "/v1/admin/policy/",
            "/v1/admin/nodes/..",
            "/v1/admin/nodes/%2f",
            "/v1/nodes/node-1",
            "/v1/tokens/revoke",
        ] {
            assert!(!allowed_mutation("PUT", path));
            assert!(!allowed_mutation("DELETE", path));
            assert!(!allowed_mutation("POST", path));
        }
    }

    #[test]
    fn manifest_endpoints_are_unique_origins() -> Result<()> {
        let (manifest, _, _, _) = fixture()?;
        for endpoint in [
            "https://node-1.example/api",
            "https://node-1.example/?secret=x",
            "https://node-1.example/#x",
            "https://user@node-1.example/",
            "https://node-2.example:443/",
        ] {
            let mut bad = manifest.clone();
            bad.members[0].endpoint = endpoint.into();
            assert_eq!(bad.validate(), Err(Error::Manifest));
        }
        Ok(())
    }

    #[test]
    fn requester_proof_rejects_weak_key() -> Result<()> {
        let (_, mut engines, mut claims, _) = fixture()?;
        // Compressed Edwards identity is a weak public key.
        claims.requester_public_key = [0; 32];
        claims.requester_public_key[0] = 1;
        let proof = RequestProof {
            signature: vec![0; 64],
        };
        assert_eq!(proof.verify(&claims), Err(Error::Proof));
        assert!(matches!(
            engines[0].round1(&claims, &proof, 100),
            Err(Error::Proof)
        ));
        Ok(())
    }

    #[test]
    fn altered_claim_message_and_own_commitment_burn_sessions() -> Result<()> {
        for alteration in 0..3 {
            let (_, mut engines, claims, proof) = fixture()?;
            let a = engines[0].round1(&claims, &proof, 100)?;
            let b = engines[1].round1(&claims, &proof, 100)?;
            let ida = frost::Identifier::try_from(a.identifier).map_err(|_| Error::Key)?;
            let idb = frost::Identifier::try_from(b.identifier).map_err(|_| Error::Key)?;
            let mut altered = claims.clone();
            if alteration == 0 {
                altered.request_id[0] ^= 1;
            }
            let mut commitments = BTreeMap::from([(ida, a.commitments), (idb, b.commitments)]);
            if alteration == 1 {
                commitments.insert(ida, b.commitments);
            }
            let message = if alteration == 2 {
                b"wrong message".to_vec()
            } else {
                claims.signing_bytes()
            };
            let package = frost::SigningPackage::new(commitments, &message);
            assert_eq!(
                engines[0].round2(a.session_id, &altered, &package, 101),
                Err(Error::Package)
            );
            assert_eq!(
                engines[0].round2(a.session_id, &claims, &package, 101),
                Err(Error::Session)
            );
        }
        Ok(())
    }
}
