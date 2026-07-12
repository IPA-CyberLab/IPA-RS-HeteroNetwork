use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ipars_types::api::{
    AuthenticatedSignalPathRequest, ControlPlaneNodeQueryKind, ControlPlaneNodeQueryRequest,
    HeartbeatRequest, NodeApiRequestSignature, NodeRequestSignature, RemoveNodeRequest,
    RevokeTokenRequest, RotateWireGuardKeyRequest, SignalHolePunchPlanRequest,
    SignalNodeUpsertRequest, SignalPathRequest,
};
use ipars_types::{ClusterId, JoinTokenClaims, NodeId, SignedJoinToken};
use rand_core::{OsRng, RngCore};
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
    #[error("node API request nonce is invalid")]
    InvalidRequestNonce,
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

const NODE_API_REQUEST_NONCE_BYTES: usize = 24;

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

    pub fn sign_token_revocation_request(
        &self,
        request: &RevokeTokenRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeRequestSignature, CryptoError> {
        let payload = serde_json::to_vec(&request.signature_payload(signed_at))?;
        let signature = self.signing_key.sign(&payload);
        Ok(NodeRequestSignature {
            signed_at,
            signature: encode_bytes(&signature.to_bytes()),
        })
    }

    pub fn sign_signal_node_upsert_request(
        &self,
        request: &SignalNodeUpsertRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeApiRequestSignature, CryptoError> {
        let nonce = random_node_api_request_nonce();
        let payload = serde_json::to_vec(&request.signature_payload(signed_at, nonce.clone()))?;
        Ok(self.sign_node_api_payload(&payload, signed_at, nonce))
    }

    pub fn sign_control_plane_node_query_request(
        &self,
        request: &ControlPlaneNodeQueryRequest,
        kind: ControlPlaneNodeQueryKind,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeApiRequestSignature, CryptoError> {
        let nonce = random_node_api_request_nonce();
        let payload =
            serde_json::to_vec(&request.signature_payload(kind, signed_at, nonce.clone()))?;
        Ok(self.sign_node_api_payload(&payload, signed_at, nonce))
    }

    pub fn sign_signal_path_request(
        &self,
        request: &SignalPathRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeApiRequestSignature, CryptoError> {
        let nonce = random_node_api_request_nonce();
        let envelope = AuthenticatedSignalPathRequest {
            request: request.clone(),
            request_signature: None,
        };
        let payload = serde_json::to_vec(&envelope.signature_payload(signed_at, nonce.clone()))?;
        Ok(self.sign_node_api_payload(&payload, signed_at, nonce))
    }

    pub fn sign_signal_hole_punch_plan_request(
        &self,
        request: &SignalHolePunchPlanRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeApiRequestSignature, CryptoError> {
        let nonce = random_node_api_request_nonce();
        let payload = serde_json::to_vec(&request.signature_payload(signed_at, nonce.clone()))?;
        Ok(self.sign_node_api_payload(&payload, signed_at, nonce))
    }

    fn sign_node_api_payload(
        &self,
        payload: &[u8],
        signed_at: DateTime<Utc>,
        nonce: String,
    ) -> NodeApiRequestSignature {
        let signature = self.signing_key.sign(payload);
        NodeApiRequestSignature {
            signed_at,
            nonce,
            signature: encode_bytes(&signature.to_bytes()),
        }
    }
}

fn random_node_api_request_nonce() -> String {
    let mut nonce_bytes = [0_u8; NODE_API_REQUEST_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce_bytes);
    URL_SAFE_NO_PAD.encode(nonce_bytes)
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

pub fn verify_token_revocation_signature(
    request: &RevokeTokenRequest,
    issuer_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let issuer_signature = request
        .issuer_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let key_bytes = decode_32(issuer_public_key_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    let signature_bytes = STANDARD.decode(&issuer_signature.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(issuer_signature.signed_at))?;
    verifying_key
        .verify(&payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn verify_signal_node_upsert_signature(
    request: &SignalNodeUpsertRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let request_signature = request
        .request_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(
        &request.signature_payload(request_signature.signed_at, request_signature.nonce.clone()),
    )?;
    verify_node_api_payload(&payload, request_signature, node_public_key_b64)
}

pub fn verify_control_plane_node_query_signature(
    request: &ControlPlaneNodeQueryRequest,
    kind: ControlPlaneNodeQueryKind,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let request_signature = request
        .request_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(
        kind,
        request_signature.signed_at,
        request_signature.nonce.clone(),
    ))?;
    verify_node_api_payload(&payload, request_signature, node_public_key_b64)
}

pub fn verify_signal_path_signature(
    request: &AuthenticatedSignalPathRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let request_signature = request
        .request_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(
        &request.signature_payload(request_signature.signed_at, request_signature.nonce.clone()),
    )?;
    verify_node_api_payload(&payload, request_signature, node_public_key_b64)
}

pub fn verify_signal_hole_punch_plan_signature(
    request: &SignalHolePunchPlanRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let request_signature = request
        .request_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(
        &request.signature_payload(request_signature.signed_at, request_signature.nonce.clone()),
    )?;
    verify_node_api_payload(&payload, request_signature, node_public_key_b64)
}

fn verify_node_api_payload(
    payload: &[u8],
    request_signature: &NodeApiRequestSignature,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    validate_node_api_request_nonce(&request_signature.nonce)?;
    let key_bytes = decode_32(node_public_key_b64)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| CryptoError::InvalidEd25519Key)?;
    let signature_bytes = STANDARD.decode(&request_signature.signature)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| CryptoError::InvalidSignature)?;
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| CryptoError::InvalidSignature)
}

pub fn validate_node_api_request_nonce(value: &str) -> Result<(), CryptoError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidRequestNonce)?;
    if bytes.len() != NODE_API_REQUEST_NONCE_BYTES || URL_SAFE_NO_PAD.encode(bytes) != value {
        return Err(CryptoError::InvalidRequestNonce);
    }
    Ok(())
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
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Duration;
    use ipars_types::api::{
        AuthenticatedSignalPathRequest, ControlPlaneNodeQueryKind, ControlPlaneNodeQueryRequest,
        HeartbeatRequest, RemoveNodeRequest, RevokeTokenRequest, RotateWireGuardKeyRequest,
        SignalHolePunchPlanRequest, SignalNodeUpsertRequest, SignalPathRequest,
    };
    use ipars_types::{
        BootstrapEndpoint, BootstrapEndpointKind, HealthState, KeyId, NodeHealth, NodeRecord, Role,
        Tag, TokenPolicy, VpnIp,
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

    #[test]
    fn signed_token_revocation_request_round_trips() -> Result<(), CryptoError> {
        let issuer = IdentityKeyPair::generate();
        let now = Utc::now();
        let mut request = RevokeTokenRequest {
            cluster_id: ClusterId::new(),
            nonce: "token-nonce".to_string(),
            issuer: issuer.node_id(),
            key_id: KeyId::from_string("root"),
            issuer_signature: None,
        };
        request.issuer_signature = Some(issuer.sign_token_revocation_request(&request, now)?);

        verify_token_revocation_signature(&request, &issuer.public_key_b64())?;
        request.nonce = "tampered-nonce".to_string();
        assert!(matches!(
            verify_token_revocation_signature(&request, &issuer.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn signed_signal_node_upsert_request_round_trips() -> Result<(), CryptoError> {
        let identity = IdentityKeyPair::generate();
        let now = Utc::now();
        let mut request = SignalNodeUpsertRequest {
            node: NodeRecord {
                node_id: identity.node_id(),
                cluster_id: ClusterId::from_string("cluster-a"),
                vpn_ip: VpnIp(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
                identity_public_key: identity.public_key_b64(),
                wireguard_public_key: WireGuardKeyPair::generate().public_key_b64,
                role: Role::edge(),
                tags: BTreeSet::new(),
                endpoint_candidates: Vec::new(),
                relay_capability: None,
                token_policy: TokenPolicy::default(),
                routes: Vec::new(),
                registered_at: now,
            },
            nat_classification: None,
            health: None,
            request_signature: None,
        };
        request.request_signature = Some(identity.sign_signal_node_upsert_request(&request, now)?);

        verify_signal_node_upsert_signature(&request, &identity.public_key_b64())?;
        request.health = Some(NodeHealth {
            state: HealthState::Healthy,
            last_seen_at: now,
            latency_ms: None,
            relay_load: None,
            message: None,
        });
        assert!(matches!(
            verify_signal_node_upsert_signature(&request, &identity.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn signed_control_plane_node_query_is_operation_scoped() -> Result<(), CryptoError> {
        let identity = IdentityKeyPair::generate();
        let mut request = ControlPlaneNodeQueryRequest {
            node_id: identity.node_id(),
            request_signature: None,
        };
        request.request_signature = Some(identity.sign_control_plane_node_query_request(
            &request,
            ControlPlaneNodeQueryKind::PeerMap,
            Utc::now(),
        )?);

        verify_control_plane_node_query_signature(
            &request,
            ControlPlaneNodeQueryKind::PeerMap,
            &identity.public_key_b64(),
        )?;
        assert!(matches!(
            verify_control_plane_node_query_signature(
                &request,
                ControlPlaneNodeQueryKind::Paths,
                &identity.public_key_b64(),
            ),
            Err(CryptoError::InvalidSignature)
        ));
        request.node_id = NodeId::from_string("node-b");
        assert!(matches!(
            verify_control_plane_node_query_signature(
                &request,
                ControlPlaneNodeQueryKind::PeerMap,
                &identity.public_key_b64(),
            ),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }

    #[test]
    fn signed_signal_path_requests_round_trip() -> Result<(), CryptoError> {
        let identity = IdentityKeyPair::generate();
        let now = Utc::now();
        let path = SignalPathRequest {
            source: identity.node_id(),
            target: NodeId::from_string("node-b"),
            source_candidates: Vec::new(),
            source_nat_classification: None,
            desired_routes: Vec::new(),
        };
        let mut authenticated = AuthenticatedSignalPathRequest {
            request: path,
            request_signature: None,
        };
        authenticated.request_signature =
            Some(identity.sign_signal_path_request(&authenticated.request, now)?);
        verify_signal_path_signature(&authenticated, &identity.public_key_b64())?;
        authenticated.request.target = NodeId::from_string("node-c");
        assert!(matches!(
            verify_signal_path_signature(&authenticated, &identity.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));

        let mut hole_punch = SignalHolePunchPlanRequest {
            source: identity.node_id(),
            target: NodeId::from_string("node-b"),
            request_signature: None,
        };
        hole_punch.request_signature =
            Some(identity.sign_signal_hole_punch_plan_request(&hole_punch, now)?);
        verify_signal_hole_punch_plan_signature(&hole_punch, &identity.public_key_b64())?;
        hole_punch.target = NodeId::from_string("node-c");
        assert!(matches!(
            verify_signal_hole_punch_plan_signature(&hole_punch, &identity.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }
}
