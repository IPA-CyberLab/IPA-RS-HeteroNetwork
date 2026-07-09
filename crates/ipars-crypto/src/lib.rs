use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ipars_types::api::{
    HeartbeatRequest, NodeRequestSignature, RemoveNodeRequest, RotateWireGuardKeyRequest,
};
use ipars_types::{ClusterId, JoinTokenClaims, NodeId, SignedJoinToken};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("base64 decoding failed")]
    Base64(#[from] base64::DecodeError),
    #[error("ed25519 key material is invalid")]
    InvalidEd25519Key,
    #[error("wireguard public key material is invalid")]
    InvalidWireGuardKey,
    #[error("ed25519 signature is invalid")]
    InvalidSignature,
    #[error("token serialization failed")]
    TokenSerialization(#[from] serde_json::Error),
    #[error("token is not valid at {0}")]
    TokenTime(DateTime<Utc>),
    #[error("token cluster mismatch: expected {expected}, got {actual}")]
    ClusterMismatch {
        expected: ClusterId,
        actual: ClusterId,
    },
}

#[derive(Clone)]
pub struct IdentityKeyPair {
    signing_key: SigningKey,
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_signing_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn from_signing_key_b64(value: &str) -> Result<Self, CryptoError> {
        Ok(Self::from_signing_bytes(decode_32(value)?))
    }

    pub fn signing_key_b64(&self) -> String {
        encode_bytes(&self.signing_key.to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn public_key_b64(&self) -> String {
        encode_bytes(self.verifying_key().as_bytes())
    }

    pub fn node_id(&self) -> NodeId {
        node_id_from_public_key(self.verifying_key().as_bytes())
    }

    pub fn sign_join_token(&self, claims: JoinTokenClaims) -> Result<SignedJoinToken, CryptoError> {
        let payload = serde_json::to_vec(&claims)?;
        let signature = self.signing_key.sign(&payload);
        Ok(SignedJoinToken {
            claims,
            signature: encode_bytes(&signature.to_bytes()),
        })
    }

    pub fn sign_heartbeat_request(
        &self,
        request: &HeartbeatRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeRequestSignature, CryptoError> {
        let payload = serde_json::to_vec(&request.signature_payload(signed_at))?;
        let signature = self.signing_key.sign(&payload);
        Ok(NodeRequestSignature {
            signed_at,
            signature: encode_bytes(&signature.to_bytes()),
        })
    }

    pub fn sign_wireguard_key_rotation_request(
        &self,
        request: &RotateWireGuardKeyRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeRequestSignature, CryptoError> {
        let payload = serde_json::to_vec(&request.signature_payload(signed_at))?;
        let signature = self.signing_key.sign(&payload);
        Ok(NodeRequestSignature {
            signed_at,
            signature: encode_bytes(&signature.to_bytes()),
        })
    }

    pub fn sign_remove_node_request(
        &self,
        request: &RemoveNodeRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeRequestSignature, CryptoError> {
        let payload = serde_json::to_vec(&request.signature_payload(signed_at))?;
        let signature = self.signing_key.sign(&payload);
        Ok(NodeRequestSignature {
            signed_at,
            signature: encode_bytes(&signature.to_bytes()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardKeyPair {
    pub private_key_b64: String,
    pub public_key_b64: String,
}

impl WireGuardKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            private_key_b64: encode_bytes(&secret.to_bytes()),
            public_key_b64: encode_bytes(public.as_bytes()),
        }
    }
}

pub fn verify_join_token(
    token: &SignedJoinToken,
    issuer_public_key_b64: &str,
    now: DateTime<Utc>,
    expected_cluster: &ClusterId,
) -> Result<(), CryptoError> {
    if !token.claims.is_time_valid(now) {
        return Err(CryptoError::TokenTime(now));
    }
    if &token.claims.cluster_id != expected_cluster {
        return Err(CryptoError::ClusterMismatch {
            expected: expected_cluster.clone(),
            actual: token.claims.cluster_id.clone(),
        });
    }

    let key_bytes = decode_32(issuer_public_key_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    let signature_bytes = STANDARD.decode(&token.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&token.claims)?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_heartbeat_request_signature(
    request: &HeartbeatRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let node_signature = request
        .node_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let key_bytes = decode_32(node_public_key_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    let signature_bytes = STANDARD.decode(&node_signature.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(node_signature.signed_at))?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_wireguard_key_rotation_signature(
    request: &RotateWireGuardKeyRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let node_signature = request
        .node_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let key_bytes = decode_32(node_public_key_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    let signature_bytes = STANDARD.decode(&node_signature.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(node_signature.signed_at))?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_remove_node_signature(
    request: &RemoveNodeRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let node_signature = request
        .node_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let key_bytes = decode_32(node_public_key_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    let signature_bytes = STANDARD.decode(&node_signature.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(node_signature.signed_at))?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn validate_identity_public_key_b64(value: &str) -> Result<(), CryptoError> {
    let key_bytes = decode_32(value)?;
    VerifyingKey::from_bytes(&key_bytes)
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidEd25519Key)
}

pub fn validate_wireguard_public_key_b64(value: &str) -> Result<(), CryptoError> {
    let bytes = STANDARD.decode(value)?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidWireGuardKey);
    }
    Ok(())
}

pub fn node_id_from_public_key_b64(value: &str) -> Result<NodeId, CryptoError> {
    let key_bytes = decode_32(value)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    Ok(node_id_from_public_key(&key_bytes))
}

pub fn node_id_from_public_key(public_key: &[u8]) -> NodeId {
    let digest = Sha256::digest(public_key);
    NodeId::from_string(format!("node-{}", hex::encode(&digest[..16])))
}

pub fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn decode_32(value: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = STANDARD.decode(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidEd25519Key)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use chrono::Duration;
    use ipars_types::api::{HeartbeatRequest, RemoveNodeRequest, RotateWireGuardKeyRequest};
    use ipars_types::{
        BootstrapEndpoint, BootstrapEndpointKind, HealthState, KeyId, NodeHealth, Role, Tag,
        TokenPolicy,
    };

    use super::*;

    #[test]
    fn signed_join_token_round_trips() -> Result<(), CryptoError> {
        let issuer = IdentityKeyPair::generate();
        let cluster_id = ClusterId::new();
        let now = Utc::now();
        let mut tags = BTreeSet::new();
        tags.insert(Tag::from_string("edge"));
        let claims = JoinTokenClaims {
            cluster_id: cluster_id.clone(),
            bootstrap_endpoints: vec![BootstrapEndpoint {
                url: "https://203.0.113.10:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            }],
            expires_at: now + Duration::hours(1),
            not_before: now - Duration::seconds(5),
            role: Role::edge(),
            tags,
            issuer: issuer.node_id(),
            key_id: KeyId::from_string("root"),
            policy: TokenPolicy::default(),
            nonce: "nonce-1".to_string(),
        };

        let token = issuer.sign_join_token(claims)?;
        verify_join_token(&token, &issuer.public_key_b64(), now, &cluster_id)
    }

    #[test]
    fn wireguard_keys_are_distinct() -> Result<(), CryptoError> {
        let first = WireGuardKeyPair::generate();
        let second = WireGuardKeyPair::generate();

        assert_ne!(first.private_key_b64, second.private_key_b64);
        assert_ne!(first.public_key_b64, second.public_key_b64);
        validate_wireguard_public_key_b64(&first.public_key_b64)?;
        assert!(matches!(
            validate_wireguard_public_key_b64("not-valid-base64"),
            Err(CryptoError::Base64(_))
        ));
        assert!(matches!(
            validate_wireguard_public_key_b64(&encode_bytes(&[1, 2, 3])),
            Err(CryptoError::InvalidWireGuardKey)
        ));
        Ok(())
    }

    #[test]
    fn identity_key_round_trips_from_private_key_b64() -> Result<(), CryptoError> {
        let key = IdentityKeyPair::generate();
        let restored = IdentityKeyPair::from_signing_key_b64(&key.signing_key_b64())?;

        assert_eq!(key.node_id(), restored.node_id());
        assert_eq!(key.public_key_b64(), restored.public_key_b64());
        validate_identity_public_key_b64(&key.public_key_b64())?;
        assert_eq!(
            node_id_from_public_key_b64(&key.public_key_b64())?,
            key.node_id()
        );
        assert!(matches!(
            validate_identity_public_key_b64("not-valid-base64"),
            Err(CryptoError::Base64(_))
        ));
        Ok(())
    }

    #[test]
    fn signed_heartbeat_request_round_trips() -> Result<(), CryptoError> {
        let key = IdentityKeyPair::generate();
        let now = Utc::now();
        let mut request = HeartbeatRequest {
            node_id: key.node_id(),
            health: NodeHealth {
                state: HealthState::Healthy,
                last_seen_at: now,
                latency_ms: Some(1.0),
                relay_load: None,
                message: Some("ok".to_string()),
            },
            candidates: Vec::new(),
            relay_capability: None,
            routes: None,
            path_state: Vec::new(),
            node_signature: None,
        };
        request.node_signature = Some(key.sign_heartbeat_request(&request, now)?);

        verify_heartbeat_request_signature(&request, &key.public_key_b64())?;
        request.health.message = Some("tampered".to_string());
        assert!(matches!(
            verify_heartbeat_request_signature(&request, &key.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn signed_wireguard_key_rotation_request_round_trips() -> Result<(), CryptoError> {
        let key = IdentityKeyPair::generate();
        let now = Utc::now();
        let old_wireguard = WireGuardKeyPair::generate();
        let next_wireguard = WireGuardKeyPair::generate();
        let mut request = RotateWireGuardKeyRequest {
            node_id: key.node_id(),
            previous_wireguard_public_key: old_wireguard.public_key_b64,
            next_wireguard_public_key: next_wireguard.public_key_b64,
            node_signature: None,
        };
        request.node_signature = Some(key.sign_wireguard_key_rotation_request(&request, now)?);

        verify_wireguard_key_rotation_signature(&request, &key.public_key_b64())?;
        request.next_wireguard_public_key = WireGuardKeyPair::generate().public_key_b64;
        assert!(matches!(
            verify_wireguard_key_rotation_signature(&request, &key.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn signed_remove_node_request_round_trips() -> Result<(), CryptoError> {
        let key = IdentityKeyPair::generate();
        let now = Utc::now();
        let mut request = RemoveNodeRequest {
            node_id: key.node_id(),
            node_signature: None,
        };
        request.node_signature = Some(key.sign_remove_node_request(&request, now)?);

        verify_remove_node_signature(&request, &key.public_key_b64())?;
        request.node_id = NodeId::from_string("node-tampered");
        assert!(matches!(
            verify_remove_node_signature(&request, &key.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }
}
