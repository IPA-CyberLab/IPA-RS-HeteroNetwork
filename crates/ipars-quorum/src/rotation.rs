use crate::{
    frost, Error, Manifest, Result, Round1Response, SignerEngine, MAX_CAPABILITY_TTL_SECS,
};
use serde::{Deserialize, Serialize};

/// Both frozen groups sign these exact bytes, including the proposed public roster.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestTransition {
    pub old_manifest_digest: String,
    pub new_manifest: Manifest,
    pub request_id: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

impl ManifestTransition {
    pub fn validate(&self, old: &Manifest, now: u64) -> Result<()> {
        if old.digest()? != self.old_manifest_digest
            || self.new_manifest.cluster_id != old.cluster_id
            || old.epoch.checked_add(1) != Some(self.new_manifest.epoch)
            || self.request_id == [0; 32]
        {
            return Err(Error::Manifest);
        }
        self.new_manifest.validate()?;
        // Rotation provisions a new group key, not a relabelled old signing group.
        if old.public_keys()?.verifying_key() == self.new_manifest.public_keys()?.verifying_key() {
            return Err(Error::Key);
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

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        let mut out = b"heteronetwork-quorum-manifest-transition-v1\0".to_vec();
        crate::field(&mut out, self.old_manifest_digest.as_bytes());
        crate::field(&mut out, self.new_manifest.digest()?.as_bytes());
        crate::field(&mut out, self.new_manifest.cluster_id.as_bytes());
        out.extend_from_slice(&self.new_manifest.epoch.to_be_bytes());
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(out)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManifestRotation {
    pub transition: ManifestTransition,
    pub old_signature: Vec<u8>,
    pub new_signature: Vec<u8>,
}

/// Cannot be constructed or deserialized without verifying both signatures.
#[derive(Clone, Debug)]
pub struct VerifiedRotation {
    old_manifest: Manifest,
    rotation: ManifestRotation,
}

impl VerifiedRotation {
    pub fn old_manifest(&self) -> &Manifest {
        &self.old_manifest
    }
    pub fn rotation(&self) -> &ManifestRotation {
        &self.rotation
    }
    pub fn validate_at(&self, now: u64) -> Result<()> {
        self.rotation.transition.validate(&self.old_manifest, now)
    }
}

pub fn verify_rotation(
    old: &Manifest,
    rotation: &ManifestRotation,
    now: u64,
) -> Result<VerifiedRotation> {
    rotation.transition.validate(old, now)?;
    let message = rotation.transition.signing_bytes()?;
    for (manifest, bytes) in [
        (old, &rotation.old_signature),
        (&rotation.transition.new_manifest, &rotation.new_signature),
    ] {
        let signature = frost::Signature::deserialize(bytes).map_err(|_| Error::Signature)?;
        manifest
            .public_keys()?
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|_| Error::Signature)?;
    }
    Ok(VerifiedRotation {
        old_manifest: old.clone(),
        rotation: rotation.clone(),
    })
}

impl SignerEngine {
    fn validate_rotation_group(
        &self,
        old: &Manifest,
        transition: &ManifestTransition,
        now: u64,
    ) -> Result<()> {
        transition.validate(old, now)?;
        let digest = self.manifest.digest()?;
        if digest != transition.old_manifest_digest && digest != transition.new_manifest.digest()? {
            return Err(Error::Manifest);
        }
        Ok(())
    }

    /// Owner authorization and trusted old-anchor installation are external prerequisites.
    pub fn round1_rotation(
        &mut self,
        old: &Manifest,
        transition: &ManifestTransition,
        now: u64,
    ) -> Result<Round1Response> {
        self.validate_rotation_group(old, transition, now)?;
        self.allocate_pending(transition.signing_bytes()?, transition.expires_at, now)
    }

    pub fn round2_rotation(
        &mut self,
        session_id: [u8; 32],
        old: &Manifest,
        transition: &ManifestTransition,
        package: &frost::SigningPackage,
        now: u64,
    ) -> Result<frost::round2::SignatureShare> {
        let pending = self.pending.remove(&session_id).ok_or(Error::Session)?;
        self.validate_rotation_group(old, transition, now)?;
        self.sign_pending(pending, &transition.signing_bytes()?, package, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Member;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
    use std::collections::BTreeMap;

    fn group(seed: u8, count: u16, epoch: u64) -> Result<(Manifest, Vec<SignerEngine>)> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let (shares, public) = frost::keys::generate_with_dealer(
            count,
            count / 2 + 1,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .map_err(|_| Error::Key)?;
        let manifest = Manifest {
            schema_version: 1,
            cluster_id: "rotation".into(),
            epoch,
            members: (1..=count)
                .map(|identifier| Member {
                    identifier,
                    node_id: format!("node-{identifier}"),
                    endpoint: format!("https://node-{identifier}.example/"),
                })
                .collect(),
            public_key_package: public.serialize().map_err(|_| Error::Key)?,
        };
        let engines = manifest
            .members
            .iter()
            .map(|member| {
                let id = frost::Identifier::try_from(member.identifier).map_err(|_| Error::Key)?;
                let key =
                    frost::keys::KeyPackage::try_from(shares.get(&id).ok_or(Error::Key)?.clone())
                        .map_err(|_| Error::Key)?;
                SignerEngine::new(manifest.clone(), &member.node_id, key, 2, 30)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((manifest, engines))
    }

    fn sign(
        engines: &mut [SignerEngine],
        old: &Manifest,
        group: &Manifest,
        transition: &ManifestTransition,
    ) -> Result<Vec<u8>> {
        let mut rounds = Vec::new();
        let mut commitments = BTreeMap::new();
        for engine in engines.iter_mut().take(usize::from(group.threshold())) {
            let response = engine.round1_rotation(old, transition, 100)?;
            commitments.insert(
                frost::Identifier::try_from(response.identifier).map_err(|_| Error::Key)?,
                response.commitments,
            );
            rounds.push(response);
        }
        let package = frost::SigningPackage::new(commitments, &transition.signing_bytes()?);
        let mut shares = BTreeMap::new();
        for (engine, response) in engines.iter_mut().zip(rounds) {
            let share =
                engine.round2_rotation(response.session_id, old, transition, &package, 101)?;
            assert_eq!(
                engine.round2_rotation(response.session_id, old, transition, &package, 101),
                Err(Error::Session)
            );
            shares.insert(
                frost::Identifier::try_from(response.identifier).map_err(|_| Error::Key)?,
                share,
            );
        }
        frost::aggregate(&package, &shares, &group.public_keys()?)
            .map_err(|_| Error::Signature)?
            .serialize()
            .map_err(|_| Error::Signature)
    }

    #[test]
    fn joint_majorities_rotate_membership_and_reject_changed_transition() -> Result<()> {
        let (old, mut old_signers) = group(1, 3, 8)?;
        let (new, mut new_signers) = group(2, 4, 9)?;
        let transition = ManifestTransition {
            old_manifest_digest: old.digest()?,
            new_manifest: new.clone(),
            request_id: [3; 32],
            issued_at: 100,
            expires_at: 200,
        };
        let rotation = ManifestRotation {
            old_signature: sign(&mut old_signers, &old, &old, &transition)?,
            new_signature: sign(&mut new_signers, &old, &new, &transition)?,
            transition,
        };
        let verified = verify_rotation(&old, &rotation, 101)?;
        assert_eq!(verified.rotation(), &rotation);
        assert_eq!(verified.validate_at(200), Err(Error::Time));
        let mut bad = rotation.clone();
        bad.new_signature = bad.old_signature.clone();
        assert!(matches!(
            verify_rotation(&old, &bad, 101),
            Err(Error::Signature)
        ));
        bad = rotation.clone();
        bad.transition.new_manifest.members[0].node_id = "substituted".into();
        assert!(matches!(
            verify_rotation(&old, &bad, 101),
            Err(Error::Signature)
        ));
        bad = rotation.clone();
        bad.transition.new_manifest.epoch += 1;
        assert!(matches!(
            verify_rotation(&old, &bad, 101),
            Err(Error::Manifest)
        ));
        bad = rotation.clone();
        bad.transition.request_id[0] ^= 1;
        assert!(matches!(
            verify_rotation(&old, &bad, 101),
            Err(Error::Signature)
        ));
        Ok(())
    }

    #[test]
    fn rotation_minority_and_cross_protocol_nonce_fail_closed() -> Result<()> {
        let (old, _) = group(4, 3, 1)?;
        let (new, mut engines) = group(5, 4, 2)?;
        let transition = ManifestTransition {
            old_manifest_digest: old.digest()?,
            new_manifest: new,
            request_id: [6; 32],
            issued_at: 100,
            expires_at: 200,
        };
        let a = engines[0].round1_rotation(&old, &transition, 100)?;
        let b = engines[1].round1_rotation(&old, &transition, 100)?;
        let package = frost::SigningPackage::new(
            BTreeMap::from([
                (
                    frost::Identifier::try_from(a.identifier).map_err(|_| Error::Key)?,
                    a.commitments,
                ),
                (
                    frost::Identifier::try_from(b.identifier).map_err(|_| Error::Key)?,
                    b.commitments,
                ),
            ]),
            &transition.signing_bytes()?,
        );
        assert_eq!(
            engines[0].round2_rotation(a.session_id, &old, &transition, &package, 101),
            Err(Error::Package)
        );
        assert_eq!(
            engines[0].round2_rotation(a.session_id, &old, &transition, &package, 101),
            Err(Error::Session)
        );
        let mut changed = transition.clone();
        changed.old_manifest_digest = "0".repeat(64);
        assert_eq!(
            engines[1].round2_rotation(b.session_id, &old, &changed, &package, 101),
            Err(Error::Manifest)
        );
        assert_eq!(
            engines[1].round2_rotation(b.session_id, &old, &transition, &package, 101),
            Err(Error::Session)
        );
        Ok(())
    }
}
