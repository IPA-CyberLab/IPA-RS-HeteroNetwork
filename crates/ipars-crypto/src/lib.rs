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
use ipars_types::{
    ClusterId, Ed25519SignatureValidationError, JoinTokenClaims, JoinTokenClaimsValidationError,
    NodeId, SignedJoinToken, SignedJoinTokenValidationError,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("ed25519 key material is invalid: {0}")]
    InvalidEd25519Key(&'static str),
    #[error("wireguard key material is invalid: {0}")]
    InvalidWireGuardKey(&'static str),
    #[error("ed25519 signature is invalid")]
    InvalidSignature,
    #[error(transparent)]
    InvalidSignatureEnvelope(#[from] Ed25519SignatureValidationError),
    #[error("node API request nonce is invalid")]
    InvalidRequestNonce,
    #[error("token serialization failed")]
    TokenSerialization(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidJoinTokenClaims(#[from] JoinTokenClaimsValidationError),
    #[error(transparent)]
    InvalidSignedJoinToken(#[from] SignedJoinTokenValidationError),
    #[error("token is not valid at {0}")]
    TokenTime(DateTime<Utc>),
    #[error("token cluster mismatch: expected {expected}, got {actual}")]
    ClusterMismatch {
        expected: ClusterId,
        actual: ClusterId,
    },
}

const NODE_API_REQUEST_NONCE_BYTES: usize = 24;
pub const KEY_MATERIAL_BYTES: usize = 32;
pub const KEY_MATERIAL_BASE64_BYTES: usize = 44;

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
        let key = Self::from_signing_bytes(decode_ed25519_key_b64(value)?);
        if key.verifying_key().is_weak() {
            return Err(CryptoError::InvalidEd25519Key("derived public key is weak"));
        }
        Ok(key)
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
        claims.validate_shape()?;
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
        let envelope = AuthenticatedSignalPathRequest {
            request: request.clone(),
            path_observation: None,
            request_signature: None,
        };
        self.sign_authenticated_signal_path_request(&envelope, signed_at)
    }

    pub fn sign_authenticated_signal_path_request(
        &self,
        request: &AuthenticatedSignalPathRequest,
        signed_at: DateTime<Utc>,
    ) -> Result<NodeApiRequestSignature, CryptoError> {
        let nonce = random_node_api_request_nonce();
        let payload = serde_json::to_vec(&request.signature_payload(signed_at, nonce.clone()))?;
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

    pub fn from_private_key_b64(value: &str) -> Result<Self, CryptoError> {
        let secret = StaticSecret::from(decode_wireguard_private_key_b64(value)?);
        let public = X25519PublicKey::from(&secret);
        Ok(Self {
            private_key_b64: encode_bytes(&secret.to_bytes()),
            public_key_b64: encode_bytes(public.as_bytes()),
        })
    }
}

pub fn verify_join_token(
    token: &SignedJoinToken,
    issuer_public_key_b64: &str,
    now: DateTime<Utc>,
    expected_cluster: &ClusterId,
) -> Result<(), CryptoError> {
    let signature_bytes = token.signature_bytes()?;
    token.claims.validate_shape()?;
    if !token.claims.is_time_valid(now) {
        return Err(CryptoError::TokenTime(now));
    }
    if &token.claims.cluster_id != expected_cluster {
        return Err(CryptoError::ClusterMismatch {
            expected: expected_cluster.clone(),
            actual: token.claims.cluster_id.clone(),
        });
    }

    let verifying_key = verifying_key_from_b64(issuer_public_key_b64)?;
    let signature = Signature::from_bytes(&signature_bytes);
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
    let payload = serde_json::to_vec(&request.signature_payload(node_signature.signed_at))?;
    verify_node_request_payload(&payload, node_signature, node_public_key_b64)
}

pub fn verify_wireguard_key_rotation_signature(
    request: &RotateWireGuardKeyRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let node_signature = request
        .node_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(node_signature.signed_at))?;
    verify_node_request_payload(&payload, node_signature, node_public_key_b64)
}

pub fn verify_remove_node_signature(
    request: &RemoveNodeRequest,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let node_signature = request
        .node_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(node_signature.signed_at))?;
    verify_node_request_payload(&payload, node_signature, node_public_key_b64)
}

pub fn verify_token_revocation_signature(
    request: &RevokeTokenRequest,
    issuer_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let issuer_signature = request
        .issuer_signature
        .as_ref()
        .ok_or(CryptoError::InvalidSignature)?;
    let payload = serde_json::to_vec(&request.signature_payload(issuer_signature.signed_at))?;
    verify_node_request_payload(&payload, issuer_signature, issuer_public_key_b64)
}

fn verify_node_request_payload(
    payload: &[u8],
    request_signature: &NodeRequestSignature,
    node_public_key_b64: &str,
) -> Result<(), CryptoError> {
    let signature_bytes = request_signature.signature_bytes()?;
    verify_ed25519_payload(payload, signature_bytes, node_public_key_b64)
}

fn verify_ed25519_payload(
    payload: &[u8],
    signature_bytes: [u8; ipars_types::ED25519_SIGNATURE_BYTES],
    public_key_b64: &str,
) -> Result<(), CryptoError> {
    let verifying_key = verifying_key_from_b64(public_key_b64)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload, &signature)
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
    let signature_bytes = request_signature.signature_bytes()?;
    validate_node_api_request_nonce(&request_signature.nonce)?;
    verify_ed25519_payload(payload, signature_bytes, node_public_key_b64)
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
    verifying_key_from_b64(value).map(|_| ())
}

pub fn validate_wireguard_public_key_b64(value: &str) -> Result<(), CryptoError> {
    decode_wireguard_public_key_b64(value).map(|_| ())
}

pub fn node_id_from_public_key_b64(value: &str) -> Result<NodeId, CryptoError> {
    let verifying_key = verifying_key_from_b64(value)?;
    Ok(node_id_from_public_key(verifying_key.as_bytes()))
}

pub fn node_id_from_public_key(public_key: &[u8]) -> NodeId {
    let digest = Sha256::digest(public_key);
    NodeId::from_string(format!("node-{}", hex::encode(&digest[..16])))
}

pub fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode_wireguard_private_key_b64(
    value: &str,
) -> Result<[u8; KEY_MATERIAL_BYTES], CryptoError> {
    decode_canonical_key_material(value).map_err(CryptoError::InvalidWireGuardKey)
}

pub fn decode_wireguard_public_key_b64(
    value: &str,
) -> Result<[u8; KEY_MATERIAL_BYTES], CryptoError> {
    let bytes = decode_canonical_key_material(value).map_err(CryptoError::InvalidWireGuardKey)?;
    let probe_secret = StaticSecret::from([0x42; KEY_MATERIAL_BYTES]);
    let public_key = X25519PublicKey::from(bytes);
    if probe_secret
        .diffie_hellman(&public_key)
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(CryptoError::InvalidWireGuardKey("public key has low order"));
    }
    Ok(bytes)
}

fn decode_ed25519_key_b64(value: &str) -> Result<[u8; KEY_MATERIAL_BYTES], CryptoError> {
    decode_canonical_key_material(value).map_err(CryptoError::InvalidEd25519Key)
}

fn verifying_key_from_b64(value: &str) -> Result<VerifyingKey, CryptoError> {
    let key_bytes = decode_ed25519_key_b64(value)?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| CryptoError::InvalidEd25519Key("bytes do not encode a valid public key"))?;
    if verifying_key.is_weak() {
        return Err(CryptoError::InvalidEd25519Key("public key is weak"));
    }
    Ok(verifying_key)
}

fn decode_canonical_key_material(value: &str) -> Result<[u8; KEY_MATERIAL_BYTES], &'static str> {
    if value.len() != KEY_MATERIAL_BASE64_BYTES {
        return Err("must be exactly 44 bytes of standard base64");
    }
    let decoded = STANDARD
        .decode(value)
        .map_err(|_| "is not valid standard base64")?;
    let key: [u8; KEY_MATERIAL_BYTES] = decoded
        .try_into()
        .map_err(|_| "must decode to exactly 32 bytes")?;
    if STANDARD.encode(key) != value {
        return Err("is not canonical standard base64");
    }
    Ok(key)
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
        BootstrapEndpoint, BootstrapEndpointKind, HealthState, KeyId, NodeHealth, NodeRecord,
        PathMetrics, PathQualityObservation, PathState, Role, Tag, TokenPolicy, VpnIp,
        MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND, MAX_JOIN_TOKEN_IDENTIFIER_BYTES,
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
    fn token_signing_and_verification_reject_invalid_claim_shapes() -> Result<(), CryptoError> {
        let issuer = IdentityKeyPair::generate();
        let cluster_id = ClusterId::new();
        let now = Utc::now();
        let mut claims = JoinTokenClaims {
            cluster_id: cluster_id.clone(),
            bootstrap_endpoints: vec![BootstrapEndpoint {
                url: "https://control.example:8443".to_string(),
                kind: BootstrapEndpointKind::ControlPlane,
            }],
            expires_at: now + Duration::hours(1),
            not_before: now - Duration::seconds(5),
            role: Role::edge(),
            tags: BTreeSet::new(),
            issuer: issuer.node_id(),
            key_id: KeyId::from_string("root"),
            policy: TokenPolicy::default(),
            nonce: "nonce-bounded-bootstrap".to_string(),
        };
        let token = issuer.sign_join_token(claims.clone())?;
        let mut invalid_bootstrap = claims.clone();
        invalid_bootstrap.bootstrap_endpoints = (0..=MAX_JOIN_TOKEN_BOOTSTRAP_ENDPOINTS_PER_KIND)
            .map(|index| BootstrapEndpoint {
                url: format!("https://control-{index}.example:8443"),
                kind: BootstrapEndpointKind::ControlPlane,
            })
            .collect();
        assert!(matches!(
            issuer.sign_join_token(invalid_bootstrap.clone()),
            Err(CryptoError::InvalidJoinTokenClaims(_))
        ));

        let mut invalid_token = token.clone();
        invalid_token.claims = invalid_bootstrap;
        assert!(matches!(
            verify_join_token(&invalid_token, &issuer.public_key_b64(), now, &cluster_id),
            Err(CryptoError::InvalidJoinTokenClaims(_))
        ));

        claims.nonce = "x".repeat(MAX_JOIN_TOKEN_IDENTIFIER_BYTES + 1);
        assert!(matches!(
            issuer.sign_join_token(claims.clone()),
            Err(CryptoError::InvalidJoinTokenClaims(_))
        ));
        invalid_token.claims = claims;
        assert!(matches!(
            verify_join_token(&invalid_token, &issuer.public_key_b64(), now, &cluster_id),
            Err(CryptoError::InvalidJoinTokenClaims(_))
        ));
        Ok(())
    }

    #[test]
    fn token_verification_rejects_invalid_signature_envelopes_before_decode(
    ) -> Result<(), CryptoError> {
        let issuer = IdentityKeyPair::generate();
        let cluster_id = ClusterId::new();
        let now = Utc::now();
        let mut token = issuer.sign_join_token(JoinTokenClaims {
            cluster_id: cluster_id.clone(),
            bootstrap_endpoints: Vec::new(),
            expires_at: now + Duration::hours(1),
            not_before: now - Duration::seconds(5),
            role: Role::edge(),
            tags: BTreeSet::new(),
            issuer: issuer.node_id(),
            key_id: KeyId::from_string("root"),
            policy: TokenPolicy::default(),
            nonce: "nonce-signature-envelope".to_string(),
        })?;

        for invalid in [
            "short".to_string(),
            "!".repeat(ipars_types::ED25519_SIGNATURE_BASE64_BYTES),
            "A".repeat(64 * 1024),
        ] {
            token.signature = invalid;
            assert!(matches!(
                verify_join_token(&token, &issuer.public_key_b64(), now, &cluster_id),
                Err(CryptoError::InvalidSignedJoinToken(_))
            ));
        }
        Ok(())
    }

    #[test]
    fn wireguard_keys_are_distinct() -> Result<(), CryptoError> {
        let first = WireGuardKeyPair::generate();
        let second = WireGuardKeyPair::generate();
        let restored = WireGuardKeyPair::from_private_key_b64(&first.private_key_b64)?;

        assert_ne!(first.private_key_b64, second.private_key_b64);
        assert_ne!(first.public_key_b64, second.public_key_b64);
        assert_eq!(restored, first);
        assert_eq!(
            encode_bytes(&decode_wireguard_private_key_b64(&first.private_key_b64)?),
            first.private_key_b64
        );
        validate_wireguard_public_key_b64(&first.public_key_b64)?;
        for invalid in [
            "not-valid-base64".to_string(),
            encode_bytes(&[1, 2, 3]),
            "A".repeat(KEY_MATERIAL_BASE64_BYTES),
            format!("{}B=", "A".repeat(42)),
            "A".repeat(64 * 1024),
        ] {
            assert!(matches!(
                validate_wireguard_public_key_b64(&invalid),
                Err(CryptoError::InvalidWireGuardKey(_))
            ));
        }
        assert!(matches!(
            validate_wireguard_public_key_b64(&format!("{}=", "A".repeat(43))),
            Err(CryptoError::InvalidWireGuardKey("public key has low order"))
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
        for invalid in [
            "not-valid-base64".to_string(),
            encode_bytes(&[1, 2, 3]),
            "A".repeat(KEY_MATERIAL_BASE64_BYTES),
            format!("{}B=", "A".repeat(42)),
            "A".repeat(64 * 1024),
            format!("{}=", "A".repeat(43)),
        ] {
            assert!(matches!(
                validate_identity_public_key_b64(&invalid),
                Err(CryptoError::InvalidEd25519Key(_))
            ));
        }
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
        let valid_signature = request.node_signature.clone();
        if let Some(signature) = request.node_signature.as_mut() {
            signature.signature = "A".repeat(64 * 1024);
        }
        assert!(matches!(
            verify_heartbeat_request_signature(&request, &key.public_key_b64()),
            Err(CryptoError::InvalidSignatureEnvelope(_))
        ));
        request.node_signature = valid_signature;
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
        let valid_signature = request.request_signature.clone();
        if let Some(signature) = request.request_signature.as_mut() {
            signature.signature = "A".repeat(64 * 1024);
        }
        assert!(matches!(
            verify_signal_node_upsert_signature(&request, &identity.public_key_b64()),
            Err(CryptoError::InvalidSignatureEnvelope(_))
        ));
        request.request_signature = valid_signature;
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
            path_observation: None,
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

    #[test]
    fn signed_signal_path_observation_cannot_be_tampered() -> Result<(), CryptoError> {
        let identity = IdentityKeyPair::generate();
        let now = Utc::now();
        let mut authenticated = AuthenticatedSignalPathRequest {
            request: SignalPathRequest {
                source: identity.node_id(),
                target: NodeId::from_string("node-b"),
                source_candidates: Vec::new(),
                source_nat_classification: None,
                desired_routes: Vec::new(),
            },
            path_observation: Some(PathQualityObservation {
                selected_state: PathState::Relay,
                selected_candidate: None,
                relay_node: Some(NodeId::from_string("relay-a")),
                metrics: PathMetrics {
                    latency_ms: Some(10.0),
                    loss_ppm: 0,
                    jitter_ms: None,
                    relay_load: None,
                    stability: 1.0,
                },
                sample_count: 1,
                successful_sample_count: 1,
                observed_at: now,
            }),
            request_signature: None,
        };
        authenticated.request_signature =
            Some(identity.sign_authenticated_signal_path_request(&authenticated, now)?);
        verify_signal_path_signature(&authenticated, &identity.public_key_b64())?;

        let Some(observation) = authenticated.path_observation.as_mut() else {
            panic!("signed test request must contain a path observation");
        };
        observation.metrics.latency_ms = Some(1.0);
        assert!(matches!(
            verify_signal_path_signature(&authenticated, &identity.public_key_b64()),
            Err(CryptoError::InvalidSignature)
        ));
        Ok(())
    }
}
