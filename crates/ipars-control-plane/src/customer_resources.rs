use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipars_types::ClusterId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::InMemoryStore;

pub const MAX_CLUSTER_ID_BYTES: usize = 128;
pub const MAX_KEYCLOAK_ISSUER_BYTES: usize = 2_048;
pub const MAX_KEYCLOAK_SUBJECT_BYTES: usize = 255;
pub const MAX_KUBERNETES_NAME_BYTES: usize = 63;
pub const MAX_PUBLIC_ADDRESS_BYTES: usize = 253;
pub const MAX_PUBLIC_ADDRESSES: usize = 32;
pub const MAX_STATUS_MESSAGE_BYTES: usize = 2_048;
pub const MAX_INGRESS_REPLICAS: u16 = 64;
pub const MAX_PROJECT_QUOTA: u32 = 10_000;
pub const MAX_PUBLIC_SERVICE_QUOTA: u32 = 10_000;
pub const MAX_CUSTOMER_RESOURCE_PAGE_SIZE: usize = 1_000;
pub const MAX_CLUSTER_CUSTOMER_PROJECTS: usize = 10_000;
pub const MAX_CLUSTER_PUBLIC_SERVICES: usize = 10_000;
pub const MAX_STATUS_FUTURE_SKEW_SECONDS: i64 = 5 * 60;

const PERSONAL_ACCOUNT_ID_DOMAIN: &[u8] = b"heteronetwork-personal-account-v1";
const PROJECT_ID_DOMAIN: &[u8] = b"heteronetwork-customer-project-v1";
const PROJECT_NAMESPACE_DOMAIN: &[u8] = b"heteronetwork-project-namespace-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustomerResourceKind {
    Account,
    Project,
    PublicService,
}

impl Display for CustomerResourceKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Account => "account",
            Self::Project => "project",
            Self::PublicService => "public service",
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CustomerResourceError {
    #[error("invalid {field}: {reason}")]
    Validation { field: &'static str, reason: String },
    #[error("customer account {account_id} was not found in cluster {cluster_id}")]
    AccountNotFound {
        cluster_id: ClusterId,
        account_id: CustomerAccountId,
    },
    #[error("customer project {project_id} was not found in cluster {cluster_id}")]
    ProjectNotFound {
        cluster_id: ClusterId,
        project_id: CustomerProjectId,
    },
    #[error("public service {resource_id} was not found in cluster {cluster_id}")]
    PublicServiceNotFound {
        cluster_id: ClusterId,
        resource_id: PublicServiceId,
    },
    #[error("{kind} name `{name}` already exists in its owner scope")]
    DuplicateName {
        kind: CustomerResourceKind,
        name: KubernetesName,
    },
    #[error("{kind} quota of {limit} has been reached")]
    QuotaExceeded {
        kind: CustomerResourceKind,
        limit: u32,
    },
    #[error("cluster {kind} capacity of {limit} has been reached")]
    ClusterCapacityExceeded {
        kind: CustomerResourceKind,
        limit: usize,
    },
    #[error("{kind} {resource_id} is not owned by customer account {requested_account_id}")]
    OwnershipMismatch {
        kind: CustomerResourceKind,
        resource_id: String,
        requested_account_id: CustomerAccountId,
    },
    #[error(
        "public service {resource_id} generation conflict: expected {expected}, current {actual}"
    )]
    GenerationConflict {
        resource_id: PublicServiceId,
        expected: u64,
        actual: u64,
    },
    #[error(
        "public service {resource_id} status observation {observed_at} is older than current observation {current_observed_at}"
    )]
    StatusObservationConflict {
        resource_id: PublicServiceId,
        observed_at: DateTime<Utc>,
        current_observed_at: DateTime<Utc>,
    },
    #[error("{kind} identifier collision for {resource_id}")]
    IdentifierCollision {
        kind: CustomerResourceKind,
        resource_id: String,
    },
    #[error("customer resource store error: {0}")]
    Store(String),
}

macro_rules! generated_id {
    ($name:ident, $prefix:literal, $field:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, CustomerResourceError> {
                let value = value.into();
                let expected_length = $prefix.len() + 32;
                if value.len() != expected_length
                    || !value.starts_with($prefix)
                    || !value[$prefix.len()..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(validation_error(
                        $field,
                        format!(
                            "must be `{}` followed by exactly 32 lowercase hexadecimal characters",
                            $prefix
                        ),
                    ));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = CustomerResourceError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

generated_id!(CustomerAccountId, "acct_", "customer account ID");
generated_id!(CustomerProjectId, "prj_", "customer project ID");
generated_id!(PublicServiceId, "psvc_", "public service ID");

impl PublicServiceId {
    pub fn from_entropy(entropy: [u8; 16]) -> Self {
        let mut value = String::with_capacity(37);
        value.push_str("psvc_");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in entropy {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KubernetesName(String);

impl KubernetesName {
    pub fn parse(value: impl Into<String>) -> Result<Self, CustomerResourceError> {
        let value = value.into();
        validate_dns_label("Kubernetes name", &value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KubernetesName {
    type Error = CustomerResourceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl From<KubernetesName> for String {
    fn from(value: KubernetesName) -> Self {
        value.0
    }
}

impl Display for KubernetesName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "KeycloakIdentityWire")]
pub struct KeycloakIdentity {
    issuer: String,
    subject: String,
}

impl KeycloakIdentity {
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, CustomerResourceError> {
        let identity = Self {
            issuer: issuer.into(),
            subject: subject.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_issuer(&self.issuer)?;
        validate_bounded_opaque(
            "Keycloak subject",
            &self.subject,
            MAX_KEYCLOAK_SUBJECT_BYTES,
        )
    }
}

#[derive(Deserialize)]
struct KeycloakIdentityWire {
    issuer: String,
    subject: String,
}

impl TryFrom<KeycloakIdentityWire> for KeycloakIdentity {
    type Error = CustomerResourceError;

    fn try_from(value: KeycloakIdentityWire) -> Result<Self, Self::Error> {
        Self::new(value.issuer, value.subject)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CustomerQuotaWire")]
pub struct CustomerQuota {
    pub max_projects: u32,
    pub max_public_services: u32,
}

#[derive(Deserialize)]
struct CustomerQuotaWire {
    max_projects: u32,
    max_public_services: u32,
}

impl TryFrom<CustomerQuotaWire> for CustomerQuota {
    type Error = CustomerResourceError;

    fn try_from(value: CustomerQuotaWire) -> Result<Self, Self::Error> {
        Self::new(value.max_projects, value.max_public_services)
    }
}

impl CustomerQuota {
    pub fn new(max_projects: u32, max_public_services: u32) -> Result<Self, CustomerResourceError> {
        let quota = Self {
            max_projects,
            max_public_services,
        };
        quota.validate()?;
        Ok(quota)
    }

    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        if self.max_projects > MAX_PROJECT_QUOTA {
            return Err(validation_error(
                "max_projects",
                format!("must not exceed {MAX_PROJECT_QUOTA}"),
            ));
        }
        if self.max_public_services > MAX_PUBLIC_SERVICE_QUOTA {
            return Err(validation_error(
                "max_public_services",
                format!("must not exceed {MAX_PUBLIC_SERVICE_QUOTA}"),
            ));
        }
        Ok(())
    }
}

impl Default for CustomerQuota {
    fn default() -> Self {
        Self {
            max_projects: 10,
            max_public_services: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerAccount {
    pub cluster_id: ClusterId,
    pub account_id: CustomerAccountId,
    pub identity: KeycloakIdentity,
    pub quota: CustomerQuota,
    pub created_at: DateTime<Utc>,
}

impl CustomerAccount {
    pub fn deterministic_id(
        cluster_id: &ClusterId,
        identity: &KeycloakIdentity,
    ) -> Result<CustomerAccountId, CustomerResourceError> {
        validate_cluster_id(cluster_id)?;
        identity.validate()?;
        CustomerAccountId::parse(stable_identifier(
            "acct_",
            PERSONAL_ACCOUNT_ID_DOMAIN,
            &[cluster_id.as_str(), identity.issuer(), identity.subject()],
        ))
    }

    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_cluster_id(&self.cluster_id)?;
        self.identity.validate()?;
        self.quota.validate()?;
        let expected = Self::deterministic_id(&self.cluster_id, &self.identity)?;
        if self.account_id != expected {
            return Err(validation_error(
                "customer account ID",
                "does not match the cluster and Keycloak identity",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EnsurePersonalAccountWire")]
pub struct EnsurePersonalAccount {
    pub cluster_id: ClusterId,
    pub identity: KeycloakIdentity,
    pub quota: CustomerQuota,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct EnsurePersonalAccountWire {
    cluster_id: ClusterId,
    identity: KeycloakIdentity,
    quota: CustomerQuota,
    created_at: DateTime<Utc>,
}

impl TryFrom<EnsurePersonalAccountWire> for EnsurePersonalAccount {
    type Error = CustomerResourceError;

    fn try_from(value: EnsurePersonalAccountWire) -> Result<Self, Self::Error> {
        let request = Self {
            cluster_id: value.cluster_id,
            identity: value.identity,
            quota: value.quota,
            created_at: value.created_at,
        };
        request.validate()?;
        Ok(request)
    }
}

impl EnsurePersonalAccount {
    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_cluster_id(&self.cluster_id)?;
        self.identity.validate()?;
        self.quota.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomerProject {
    pub cluster_id: ClusterId,
    pub project_id: CustomerProjectId,
    pub account_id: CustomerAccountId,
    pub name: KubernetesName,
    pub kubernetes_namespace: KubernetesName,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CustomerProjectPage {
    pub projects: Vec<CustomerProject>,
    pub next_cursor: Option<CustomerProjectId>,
}

impl CustomerProject {
    pub fn generated_id(
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        name: &KubernetesName,
    ) -> Result<CustomerProjectId, CustomerResourceError> {
        validate_cluster_id(cluster_id)?;
        CustomerProjectId::parse(stable_identifier(
            "prj_",
            PROJECT_ID_DOMAIN,
            &[cluster_id.as_str(), account_id.as_str(), name.as_str()],
        ))
    }

    pub fn generated_namespace(
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        name: &KubernetesName,
    ) -> Result<KubernetesName, CustomerResourceError> {
        validate_cluster_id(cluster_id)?;
        let suffix = stable_hex(
            PROJECT_NAMESPACE_DOMAIN,
            &[cluster_id.as_str(), account_id.as_str(), name.as_str()],
            8,
        );
        let readable_length = name.as_str().len().min(36);
        let readable = name.as_str()[..readable_length].trim_end_matches('-');
        KubernetesName::parse(format!("hn-{readable}-{suffix}"))
    }

    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_cluster_id(&self.cluster_id)?;
        let expected_id = Self::generated_id(&self.cluster_id, &self.account_id, &self.name)?;
        if self.project_id != expected_id {
            return Err(validation_error(
                "customer project ID",
                "does not match the cluster, account, and project name",
            ));
        }
        let expected_namespace =
            Self::generated_namespace(&self.cluster_id, &self.account_id, &self.name)?;
        if self.kubernetes_namespace != expected_namespace {
            return Err(validation_error(
                "Kubernetes namespace",
                "does not match the generated project namespace",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CreateCustomerProjectWire")]
pub struct CreateCustomerProject {
    pub cluster_id: ClusterId,
    pub account_id: CustomerAccountId,
    pub name: KubernetesName,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct CreateCustomerProjectWire {
    cluster_id: ClusterId,
    account_id: CustomerAccountId,
    name: KubernetesName,
    created_at: DateTime<Utc>,
}

impl TryFrom<CreateCustomerProjectWire> for CreateCustomerProject {
    type Error = CustomerResourceError;

    fn try_from(value: CreateCustomerProjectWire) -> Result<Self, Self::Error> {
        let request = Self {
            cluster_id: value.cluster_id,
            account_id: value.account_id,
            name: value.name,
            created_at: value.created_at,
        };
        request.validate()?;
        Ok(request)
    }
}

impl CreateCustomerProject {
    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_cluster_id(&self.cluster_id)?;
        CustomerAccountId::parse(self.account_id.as_str())?;
        validate_dns_label("project name", self.name.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicServiceTrafficMode {
    Direct,
    Forwarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PublicServiceProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PublicServiceSpecWire")]
pub struct PublicServiceSpec {
    pub traffic_mode: PublicServiceTrafficMode,
    pub protocol: PublicServiceProtocol,
    pub public_port: u16,
    pub backend_service: KubernetesName,
    pub backend_port: u16,
    pub ingress_replicas: u16,
}

#[derive(Deserialize)]
struct PublicServiceSpecWire {
    traffic_mode: PublicServiceTrafficMode,
    protocol: PublicServiceProtocol,
    public_port: u16,
    backend_service: KubernetesName,
    backend_port: u16,
    ingress_replicas: u16,
}

impl TryFrom<PublicServiceSpecWire> for PublicServiceSpec {
    type Error = CustomerResourceError;

    fn try_from(value: PublicServiceSpecWire) -> Result<Self, Self::Error> {
        let spec = Self {
            traffic_mode: value.traffic_mode,
            protocol: value.protocol,
            public_port: value.public_port,
            backend_service: value.backend_service,
            backend_port: value.backend_port,
            ingress_replicas: value.ingress_replicas,
        };
        spec.validate()?;
        Ok(spec)
    }
}

impl PublicServiceSpec {
    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_nonzero_port("public_port", self.public_port)?;
        validate_dns_label("backend_service", self.backend_service.as_str())?;
        validate_nonzero_port("backend_port", self.backend_port)?;
        if !(1..=MAX_INGRESS_REPLICAS).contains(&self.ingress_replicas) {
            return Err(validation_error(
                "ingress_replicas",
                format!("must be between 1 and {MAX_INGRESS_REPLICAS}"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PublicServiceAddressWire")]
pub struct PublicServiceAddress {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize)]
struct PublicServiceAddressWire {
    host: String,
    port: u16,
}

impl TryFrom<PublicServiceAddressWire> for PublicServiceAddress {
    type Error = CustomerResourceError;

    fn try_from(value: PublicServiceAddressWire) -> Result<Self, Self::Error> {
        Self::new(value.host, value.port)
    }
}

impl PublicServiceAddress {
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self, CustomerResourceError> {
        let address = Self {
            host: host.into(),
            port,
        };
        address.validate()?;
        Ok(address)
    }

    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_public_host(&self.host)?;
        validate_nonzero_port("public address port", self.port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicServicePhase {
    Pending,
    Ready,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PublicServiceStatusWire")]
pub struct PublicServiceStatus {
    pub phase: PublicServicePhase,
    pub public_addresses: Vec<PublicServiceAddress>,
    pub message: Option<String>,
    pub observed_generation: u64,
    pub observed_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct PublicServiceStatusWire {
    phase: PublicServicePhase,
    public_addresses: Vec<PublicServiceAddress>,
    message: Option<String>,
    observed_generation: u64,
    observed_at: Option<DateTime<Utc>>,
}

impl TryFrom<PublicServiceStatusWire> for PublicServiceStatus {
    type Error = CustomerResourceError;

    fn try_from(value: PublicServiceStatusWire) -> Result<Self, Self::Error> {
        let status = Self {
            phase: value.phase,
            public_addresses: value.public_addresses,
            message: value.message,
            observed_generation: value.observed_generation,
            observed_at: value.observed_at,
        };
        status.validate()?;
        Ok(status)
    }
}

impl PublicServiceStatus {
    pub fn pending() -> Self {
        Self {
            phase: PublicServicePhase::Pending,
            public_addresses: Vec::new(),
            message: None,
            observed_generation: 0,
            observed_at: None,
        }
    }

    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        if self.public_addresses.len() > MAX_PUBLIC_ADDRESSES {
            return Err(validation_error(
                "public_addresses",
                format!("must contain at most {MAX_PUBLIC_ADDRESSES} entries"),
            ));
        }
        for address in &self.public_addresses {
            address.validate()?;
        }
        if let Some(message) = &self.message {
            validate_bounded_text("status message", message, MAX_STATUS_MESSAGE_BYTES)?;
        }
        if self.observed_generation == 0 && self.observed_at.is_some() {
            return Err(validation_error(
                "observed_at",
                "must be absent when observed_generation is zero",
            ));
        }
        if self.observed_generation > 0 && self.observed_at.is_none() {
            return Err(validation_error(
                "observed_at",
                "is required when observed_generation is nonzero",
            ));
        }
        match self.phase {
            PublicServicePhase::Pending if !self.public_addresses.is_empty() => {
                return Err(validation_error(
                    "public_addresses",
                    "must be empty while status is pending",
                ));
            }
            PublicServicePhase::Ready if self.public_addresses.is_empty() => {
                return Err(validation_error(
                    "public_addresses",
                    "must contain at least one entry while status is ready",
                ));
            }
            PublicServicePhase::Error
                if self
                    .message
                    .as_deref()
                    .is_none_or(|message| message.is_empty()) =>
            {
                return Err(validation_error(
                    "status message",
                    "is required while status is error",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn validate_for_update(
        &self,
        expected_generation: u64,
        public_port: u16,
        received_at: DateTime<Utc>,
    ) -> Result<(), CustomerResourceError> {
        self.validate()?;
        if self.observed_generation != expected_generation {
            return Err(validation_error(
                "observed_generation",
                format!("must equal expected generation {expected_generation}"),
            ));
        }
        if self.observed_at.is_none() {
            return Err(validation_error(
                "observed_at",
                "is required for a controller status update",
            ));
        }
        if self.observed_at.is_some_and(|observed_at| {
            observed_at > received_at + ChronoDuration::seconds(MAX_STATUS_FUTURE_SKEW_SECONDS)
        }) {
            return Err(validation_error(
                "observed_at",
                format!(
                    "must not be more than {MAX_STATUS_FUTURE_SKEW_SECONDS} seconds in the future"
                ),
            ));
        }
        if self
            .public_addresses
            .iter()
            .any(|address| address.port != public_port)
        {
            return Err(validation_error(
                "public address port",
                format!("must equal the desired public port {public_port}"),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicServiceResource {
    pub cluster_id: ClusterId,
    pub resource_id: PublicServiceId,
    pub account_id: CustomerAccountId,
    pub project_id: CustomerProjectId,
    pub name: KubernetesName,
    pub namespace: KubernetesName,
    pub spec: PublicServiceSpec,
    pub generation: u64,
    pub status: PublicServiceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicServicePage {
    pub public_services: Vec<PublicServiceResource>,
    pub next_cursor: Option<PublicServiceId>,
}

impl PublicServiceResource {
    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_cluster_id(&self.cluster_id)?;
        PublicServiceId::parse(self.resource_id.as_str())?;
        validate_dns_label("public service name", self.name.as_str())?;
        validate_dns_label("Kubernetes namespace", self.namespace.as_str())?;
        self.spec.validate()?;
        if self.generation == 0 {
            return Err(validation_error("generation", "must be at least 1"));
        }
        self.status.validate()?;
        if self.status.observed_generation > self.generation {
            return Err(validation_error(
                "observed_generation",
                "must not exceed the desired generation",
            ));
        }
        if self.updated_at < self.created_at {
            return Err(validation_error(
                "updated_at",
                "must not be earlier than created_at",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "CreatePublicServiceWire")]
pub struct CreatePublicService {
    pub cluster_id: ClusterId,
    pub resource_id: PublicServiceId,
    pub account_id: CustomerAccountId,
    pub project_id: CustomerProjectId,
    pub name: KubernetesName,
    pub spec: PublicServiceSpec,
    pub created_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct CreatePublicServiceWire {
    cluster_id: ClusterId,
    resource_id: PublicServiceId,
    account_id: CustomerAccountId,
    project_id: CustomerProjectId,
    name: KubernetesName,
    spec: PublicServiceSpec,
    created_at: DateTime<Utc>,
}

impl TryFrom<CreatePublicServiceWire> for CreatePublicService {
    type Error = CustomerResourceError;

    fn try_from(value: CreatePublicServiceWire) -> Result<Self, Self::Error> {
        let request = Self {
            cluster_id: value.cluster_id,
            resource_id: value.resource_id,
            account_id: value.account_id,
            project_id: value.project_id,
            name: value.name,
            spec: value.spec,
            created_at: value.created_at,
        };
        request.validate()?;
        Ok(request)
    }
}

impl CreatePublicService {
    pub fn validate(&self) -> Result<(), CustomerResourceError> {
        validate_cluster_id(&self.cluster_id)?;
        PublicServiceId::parse(self.resource_id.as_str())?;
        CustomerAccountId::parse(self.account_id.as_str())?;
        CustomerProjectId::parse(self.project_id.as_str())?;
        validate_dns_label("public service name", self.name.as_str())?;
        self.spec.validate()
    }
}

#[async_trait]
pub trait CustomerResourceStore: Send + Sync {
    async fn ensure_personal_account(
        &self,
        request: EnsurePersonalAccount,
    ) -> Result<CustomerAccount, CustomerResourceError>;

    async fn get_personal_account(
        &self,
        cluster_id: &ClusterId,
        identity: &KeycloakIdentity,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError>;

    async fn get_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError>;

    async fn delete_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<bool, CustomerResourceError>;

    async fn create_customer_project(
        &self,
        request: CreateCustomerProject,
    ) -> Result<CustomerProject, CustomerResourceError>;

    async fn get_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerProject>, CustomerResourceError>;

    async fn get_project_owner(
        &self,
        cluster_id: &ClusterId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError>;

    async fn list_customer_projects(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError>;

    async fn list_desired_customer_projects(
        &self,
        cluster_id: &ClusterId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError>;

    async fn delete_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<bool, CustomerResourceError>;

    async fn create_public_service(
        &self,
        request: CreatePublicService,
    ) -> Result<PublicServiceResource, CustomerResourceError>;

    async fn get_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<Option<PublicServiceResource>, CustomerResourceError>;

    async fn list_public_services(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError>;

    async fn delete_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<bool, CustomerResourceError>;

    async fn list_desired_public_services(
        &self,
        cluster_id: &ClusterId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError>;

    async fn update_public_service_status(
        &self,
        cluster_id: &ClusterId,
        resource_id: &PublicServiceId,
        expected_generation: u64,
        status: PublicServiceStatus,
    ) -> Result<PublicServiceResource, CustomerResourceError>;
}

#[derive(Debug, Default)]
pub(crate) struct InMemoryCustomerResourceState {
    accounts: BTreeMap<(ClusterId, CustomerAccountId), CustomerAccount>,
    identities: BTreeMap<(ClusterId, KeycloakIdentity), CustomerAccountId>,
    projects: BTreeMap<(ClusterId, CustomerProjectId), CustomerProject>,
    public_services: BTreeMap<(ClusterId, PublicServiceId), PublicServiceResource>,
}

#[async_trait]
impl CustomerResourceStore for InMemoryStore {
    async fn ensure_personal_account(
        &self,
        request: EnsurePersonalAccount,
    ) -> Result<CustomerAccount, CustomerResourceError> {
        request.validate()?;
        let mut state = self.customer_resources.lock().await;
        let identity_key = (request.cluster_id.clone(), request.identity.clone());
        if let Some(account_id) = state.identities.get(&identity_key) {
            return state
                .accounts
                .get(&(request.cluster_id, account_id.clone()))
                .cloned()
                .ok_or_else(|| {
                    CustomerResourceError::Store(
                        "identity index points to a missing customer account".to_string(),
                    )
                });
        }

        let account_id = CustomerAccount::deterministic_id(&request.cluster_id, &request.identity)?;
        let key = (request.cluster_id.clone(), account_id.clone());
        if state.accounts.contains_key(&key) {
            return Err(CustomerResourceError::IdentifierCollision {
                kind: CustomerResourceKind::Account,
                resource_id: account_id.to_string(),
            });
        }
        let account = CustomerAccount {
            cluster_id: request.cluster_id.clone(),
            account_id: account_id.clone(),
            identity: request.identity.clone(),
            quota: request.quota,
            created_at: request.created_at,
        };
        account.validate()?;
        state.identities.insert(identity_key, account_id);
        state.accounts.insert(key, account.clone());
        Ok(account)
    }

    async fn get_personal_account(
        &self,
        cluster_id: &ClusterId,
        identity: &KeycloakIdentity,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_cluster_id(cluster_id)?;
        identity.validate()?;
        let state = self.customer_resources.lock().await;
        let Some(account_id) = state
            .identities
            .get(&(cluster_id.clone(), identity.clone()))
        else {
            return Ok(None);
        };
        state
            .accounts
            .get(&(cluster_id.clone(), account_id.clone()))
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                CustomerResourceError::Store(
                    "identity index points to a missing customer account".to_string(),
                )
            })
    }

    async fn get_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_lookup_ids(cluster_id, Some(account_id), None, None)?;
        Ok(self
            .customer_resources
            .lock()
            .await
            .accounts
            .get(&(cluster_id.clone(), account_id.clone()))
            .cloned())
    }

    async fn delete_customer_account(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
    ) -> Result<bool, CustomerResourceError> {
        validate_lookup_ids(cluster_id, Some(account_id), None, None)?;
        let mut state = self.customer_resources.lock().await;
        let Some(account) = state
            .accounts
            .remove(&(cluster_id.clone(), account_id.clone()))
        else {
            return Ok(false);
        };
        state
            .identities
            .remove(&(cluster_id.clone(), account.identity));
        let project_ids = state
            .projects
            .values()
            .filter(|project| {
                &project.cluster_id == cluster_id && &project.account_id == account_id
            })
            .map(|project| project.project_id.clone())
            .collect::<Vec<_>>();
        state.projects.retain(|_, project| {
            &project.cluster_id != cluster_id || &project.account_id != account_id
        });
        state.public_services.retain(|_, resource| {
            &resource.cluster_id != cluster_id || !project_ids.contains(&resource.project_id)
        });
        Ok(true)
    }

    async fn create_customer_project(
        &self,
        request: CreateCustomerProject,
    ) -> Result<CustomerProject, CustomerResourceError> {
        request.validate()?;
        let mut state = self.customer_resources.lock().await;
        let account = require_account(&state, &request.cluster_id, &request.account_id)?;
        if state.projects.values().any(|project| {
            project.cluster_id == request.cluster_id
                && project.account_id == request.account_id
                && project.name == request.name
        }) {
            return Err(CustomerResourceError::DuplicateName {
                kind: CustomerResourceKind::Project,
                name: request.name,
            });
        }
        let project_count = state
            .projects
            .values()
            .filter(|project| {
                project.cluster_id == request.cluster_id && project.account_id == request.account_id
            })
            .count();
        if project_count >= account.quota.max_projects as usize {
            return Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: account.quota.max_projects,
            });
        }
        if state
            .projects
            .values()
            .filter(|project| project.cluster_id == request.cluster_id)
            .count()
            >= MAX_CLUSTER_CUSTOMER_PROJECTS
        {
            return Err(CustomerResourceError::ClusterCapacityExceeded {
                kind: CustomerResourceKind::Project,
                limit: MAX_CLUSTER_CUSTOMER_PROJECTS,
            });
        }
        let project_id =
            CustomerProject::generated_id(&request.cluster_id, &request.account_id, &request.name)?;
        let project = CustomerProject {
            cluster_id: request.cluster_id.clone(),
            project_id: project_id.clone(),
            account_id: request.account_id.clone(),
            kubernetes_namespace: CustomerProject::generated_namespace(
                &request.cluster_id,
                &request.account_id,
                &request.name,
            )?,
            name: request.name,
            created_at: request.created_at,
        };
        project.validate()?;
        let key = (request.cluster_id, project_id.clone());
        if state.projects.contains_key(&key) {
            return Err(CustomerResourceError::IdentifierCollision {
                kind: CustomerResourceKind::Project,
                resource_id: project_id.to_string(),
            });
        }
        if state.projects.values().any(|existing| {
            existing.cluster_id == project.cluster_id
                && existing.kubernetes_namespace == project.kubernetes_namespace
        }) {
            return Err(CustomerResourceError::IdentifierCollision {
                kind: CustomerResourceKind::Project,
                resource_id: project.kubernetes_namespace.to_string(),
            });
        }
        state.projects.insert(key, project.clone());
        Ok(project)
    }

    async fn get_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerProject>, CustomerResourceError> {
        validate_lookup_ids(cluster_id, Some(account_id), Some(project_id), None)?;
        let state = self.customer_resources.lock().await;
        let Some(project) = state
            .projects
            .get(&(cluster_id.clone(), project_id.clone()))
        else {
            return Ok(None);
        };
        ensure_project_owner(project, account_id)?;
        Ok(Some(project.clone()))
    }

    async fn get_project_owner(
        &self,
        cluster_id: &ClusterId,
        project_id: &CustomerProjectId,
    ) -> Result<Option<CustomerAccount>, CustomerResourceError> {
        validate_lookup_ids(cluster_id, None, Some(project_id), None)?;
        let state = self.customer_resources.lock().await;
        let Some(project) = state
            .projects
            .get(&(cluster_id.clone(), project_id.clone()))
        else {
            return Ok(None);
        };
        state
            .accounts
            .get(&(cluster_id.clone(), project.account_id.clone()))
            .cloned()
            .map(Some)
            .ok_or_else(|| {
                CustomerResourceError::Store(
                    "customer project points to a missing account".to_string(),
                )
            })
    }

    async fn list_customer_projects(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError> {
        validate_lookup_ids(cluster_id, Some(account_id), None, None)?;
        validate_page_limit(limit)?;
        let state = self.customer_resources.lock().await;
        require_account(&state, cluster_id, account_id)?;
        let projects = state
            .projects
            .values()
            .filter(|project| {
                &project.cluster_id == cluster_id && &project.account_id == account_id
            })
            .filter(|project| after.is_none_or(|cursor| &project.project_id > cursor))
            .take(limit + 1)
            .cloned()
            .collect();
        Ok(customer_project_page(projects, limit))
    }

    async fn list_desired_customer_projects(
        &self,
        cluster_id: &ClusterId,
        after: Option<&CustomerProjectId>,
        limit: usize,
    ) -> Result<CustomerProjectPage, CustomerResourceError> {
        validate_cluster_id(cluster_id)?;
        validate_page_limit(limit)?;
        let projects = self
            .customer_resources
            .lock()
            .await
            .projects
            .values()
            .filter(|project| &project.cluster_id == cluster_id)
            .filter(|project| after.is_none_or(|cursor| &project.project_id > cursor))
            .take(limit + 1)
            .cloned()
            .collect();
        Ok(customer_project_page(projects, limit))
    }

    async fn delete_customer_project(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
    ) -> Result<bool, CustomerResourceError> {
        validate_lookup_ids(cluster_id, Some(account_id), Some(project_id), None)?;
        let mut state = self.customer_resources.lock().await;
        let key = (cluster_id.clone(), project_id.clone());
        let Some(project) = state.projects.get(&key) else {
            return Ok(false);
        };
        ensure_project_owner(project, account_id)?;
        state.projects.remove(&key);
        state.public_services.retain(|_, resource| {
            &resource.cluster_id != cluster_id || &resource.project_id != project_id
        });
        Ok(true)
    }

    async fn create_public_service(
        &self,
        request: CreatePublicService,
    ) -> Result<PublicServiceResource, CustomerResourceError> {
        request.validate()?;
        let mut state = self.customer_resources.lock().await;
        let account = require_account(&state, &request.cluster_id, &request.account_id)?;
        let project = state
            .projects
            .get(&(request.cluster_id.clone(), request.project_id.clone()))
            .ok_or_else(|| CustomerResourceError::ProjectNotFound {
                cluster_id: request.cluster_id.clone(),
                project_id: request.project_id.clone(),
            })?;
        ensure_project_owner(project, &request.account_id)?;
        if state.public_services.values().any(|resource| {
            resource.cluster_id == request.cluster_id
                && resource.project_id == request.project_id
                && resource.name == request.name
        }) {
            return Err(CustomerResourceError::DuplicateName {
                kind: CustomerResourceKind::PublicService,
                name: request.name,
            });
        }
        let resource_count = state
            .public_services
            .values()
            .filter(|resource| {
                resource.cluster_id == request.cluster_id
                    && resource.account_id == request.account_id
            })
            .count();
        if resource_count >= account.quota.max_public_services as usize {
            return Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: account.quota.max_public_services,
            });
        }
        if state
            .public_services
            .values()
            .filter(|resource| resource.cluster_id == request.cluster_id)
            .count()
            >= MAX_CLUSTER_PUBLIC_SERVICES
        {
            return Err(CustomerResourceError::ClusterCapacityExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: MAX_CLUSTER_PUBLIC_SERVICES,
            });
        }
        let resource_id = request.resource_id.clone();
        let resource = PublicServiceResource {
            cluster_id: request.cluster_id.clone(),
            resource_id: resource_id.clone(),
            account_id: request.account_id,
            project_id: request.project_id,
            name: request.name,
            namespace: project.kubernetes_namespace.clone(),
            spec: request.spec,
            generation: 1,
            status: PublicServiceStatus::pending(),
            created_at: request.created_at,
            updated_at: request.created_at,
        };
        resource.validate()?;
        let key = (request.cluster_id, resource_id.clone());
        if state.public_services.contains_key(&key) {
            return Err(CustomerResourceError::IdentifierCollision {
                kind: CustomerResourceKind::PublicService,
                resource_id: resource_id.to_string(),
            });
        }
        state.public_services.insert(key, resource.clone());
        Ok(resource)
    }

    async fn get_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<Option<PublicServiceResource>, CustomerResourceError> {
        validate_lookup_ids(
            cluster_id,
            Some(account_id),
            Some(project_id),
            Some(resource_id),
        )?;
        let state = self.customer_resources.lock().await;
        if let Some(project) = state
            .projects
            .get(&(cluster_id.clone(), project_id.clone()))
        {
            ensure_project_owner(project, account_id)?;
        }
        let Some(resource) = state
            .public_services
            .get(&(cluster_id.clone(), resource_id.clone()))
        else {
            return Ok(None);
        };
        ensure_public_service_owner(resource, account_id, project_id)?;
        Ok(Some(resource.clone()))
    }

    async fn list_public_services(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError> {
        validate_lookup_ids(cluster_id, Some(account_id), Some(project_id), None)?;
        validate_page_limit(limit)?;
        let state = self.customer_resources.lock().await;
        let project = state
            .projects
            .get(&(cluster_id.clone(), project_id.clone()))
            .ok_or_else(|| CustomerResourceError::ProjectNotFound {
                cluster_id: cluster_id.clone(),
                project_id: project_id.clone(),
            })?;
        ensure_project_owner(project, account_id)?;
        let public_services = state
            .public_services
            .values()
            .filter(|resource| {
                &resource.cluster_id == cluster_id && &resource.project_id == project_id
            })
            .filter(|resource| after.is_none_or(|cursor| &resource.resource_id > cursor))
            .take(limit + 1)
            .cloned()
            .collect();
        Ok(public_service_page(public_services, limit))
    }

    async fn delete_public_service(
        &self,
        cluster_id: &ClusterId,
        account_id: &CustomerAccountId,
        project_id: &CustomerProjectId,
        resource_id: &PublicServiceId,
    ) -> Result<bool, CustomerResourceError> {
        validate_lookup_ids(
            cluster_id,
            Some(account_id),
            Some(project_id),
            Some(resource_id),
        )?;
        let mut state = self.customer_resources.lock().await;
        let key = (cluster_id.clone(), resource_id.clone());
        let Some(resource) = state.public_services.get(&key) else {
            return Ok(false);
        };
        ensure_public_service_owner(resource, account_id, project_id)?;
        state.public_services.remove(&key);
        Ok(true)
    }

    async fn list_desired_public_services(
        &self,
        cluster_id: &ClusterId,
        after: Option<&PublicServiceId>,
        limit: usize,
    ) -> Result<PublicServicePage, CustomerResourceError> {
        validate_cluster_id(cluster_id)?;
        validate_page_limit(limit)?;
        let public_services = self
            .customer_resources
            .lock()
            .await
            .public_services
            .values()
            .filter(|resource| &resource.cluster_id == cluster_id)
            .filter(|resource| after.is_none_or(|cursor| &resource.resource_id > cursor))
            .take(limit + 1)
            .cloned()
            .collect();
        Ok(public_service_page(public_services, limit))
    }

    async fn update_public_service_status(
        &self,
        cluster_id: &ClusterId,
        resource_id: &PublicServiceId,
        expected_generation: u64,
        status: PublicServiceStatus,
    ) -> Result<PublicServiceResource, CustomerResourceError> {
        validate_lookup_ids(cluster_id, None, None, Some(resource_id))?;
        let mut state = self.customer_resources.lock().await;
        let resource = state
            .public_services
            .get_mut(&(cluster_id.clone(), resource_id.clone()))
            .ok_or_else(|| CustomerResourceError::PublicServiceNotFound {
                cluster_id: cluster_id.clone(),
                resource_id: resource_id.clone(),
            })?;
        if resource.generation != expected_generation {
            return Err(CustomerResourceError::GenerationConflict {
                resource_id: resource_id.clone(),
                expected: expected_generation,
                actual: resource.generation,
            });
        }
        status.validate_for_update(expected_generation, resource.spec.public_port, Utc::now())?;
        let observed_at = status.observed_at.ok_or_else(|| {
            validation_error("observed_at", "is required for a controller status update")
        })?;
        reject_stale_status_observation(resource, resource_id, observed_at)?;
        resource.updated_at = observed_at;
        resource.status = status;
        resource.validate()?;
        Ok(resource.clone())
    }
}

fn require_account<'a>(
    state: &'a InMemoryCustomerResourceState,
    cluster_id: &ClusterId,
    account_id: &CustomerAccountId,
) -> Result<&'a CustomerAccount, CustomerResourceError> {
    state
        .accounts
        .get(&(cluster_id.clone(), account_id.clone()))
        .ok_or_else(|| CustomerResourceError::AccountNotFound {
            cluster_id: cluster_id.clone(),
            account_id: account_id.clone(),
        })
}

fn ensure_project_owner(
    project: &CustomerProject,
    account_id: &CustomerAccountId,
) -> Result<(), CustomerResourceError> {
    if &project.account_id != account_id {
        return Err(CustomerResourceError::OwnershipMismatch {
            kind: CustomerResourceKind::Project,
            resource_id: project.project_id.to_string(),
            requested_account_id: account_id.clone(),
        });
    }
    Ok(())
}

fn ensure_public_service_owner(
    resource: &PublicServiceResource,
    account_id: &CustomerAccountId,
    project_id: &CustomerProjectId,
) -> Result<(), CustomerResourceError> {
    if &resource.account_id != account_id || &resource.project_id != project_id {
        return Err(CustomerResourceError::OwnershipMismatch {
            kind: CustomerResourceKind::PublicService,
            resource_id: resource.resource_id.to_string(),
            requested_account_id: account_id.clone(),
        });
    }
    Ok(())
}

pub fn reject_stale_status_observation(
    resource: &PublicServiceResource,
    resource_id: &PublicServiceId,
    observed_at: DateTime<Utc>,
) -> Result<(), CustomerResourceError> {
    if let Some(current_observed_at) = resource.status.observed_at {
        if observed_at < current_observed_at {
            return Err(CustomerResourceError::StatusObservationConflict {
                resource_id: resource_id.clone(),
                observed_at,
                current_observed_at,
            });
        }
    }
    Ok(())
}

pub fn validate_customer_resource_page_limit(limit: usize) -> Result<(), CustomerResourceError> {
    validate_page_limit(limit)
}

fn validate_page_limit(limit: usize) -> Result<(), CustomerResourceError> {
    if !(1..=MAX_CUSTOMER_RESOURCE_PAGE_SIZE).contains(&limit) {
        return Err(validation_error(
            "page limit",
            format!("must be between 1 and {MAX_CUSTOMER_RESOURCE_PAGE_SIZE}"),
        ));
    }
    Ok(())
}

pub fn customer_project_page(
    mut projects: Vec<CustomerProject>,
    limit: usize,
) -> CustomerProjectPage {
    let has_more = projects.len() > limit;
    projects.truncate(limit);
    let next_cursor = has_more
        .then(|| projects.last().map(|project| project.project_id.clone()))
        .flatten();
    CustomerProjectPage {
        projects,
        next_cursor,
    }
}

pub fn public_service_page(
    mut public_services: Vec<PublicServiceResource>,
    limit: usize,
) -> PublicServicePage {
    let has_more = public_services.len() > limit;
    public_services.truncate(limit);
    let next_cursor = has_more
        .then(|| {
            public_services
                .last()
                .map(|resource| resource.resource_id.clone())
        })
        .flatten();
    PublicServicePage {
        public_services,
        next_cursor,
    }
}

pub(crate) fn validate_cluster_id(cluster_id: &ClusterId) -> Result<(), CustomerResourceError> {
    let value = cluster_id.as_str();
    if value.is_empty() || value.len() > MAX_CLUSTER_ID_BYTES {
        return Err(validation_error(
            "cluster_id",
            format!("must contain between 1 and {MAX_CLUSTER_ID_BYTES} bytes"),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(validation_error(
            "cluster_id",
            "may contain only ASCII letters, digits, hyphens, underscores, and periods",
        ));
    }
    Ok(())
}

pub fn validate_customer_resource_cluster_id(
    cluster_id: &ClusterId,
) -> Result<(), CustomerResourceError> {
    validate_cluster_id(cluster_id)
}

fn validate_lookup_ids(
    cluster_id: &ClusterId,
    account_id: Option<&CustomerAccountId>,
    project_id: Option<&CustomerProjectId>,
    resource_id: Option<&PublicServiceId>,
) -> Result<(), CustomerResourceError> {
    validate_cluster_id(cluster_id)?;
    if let Some(account_id) = account_id {
        CustomerAccountId::parse(account_id.as_str())?;
    }
    if let Some(project_id) = project_id {
        CustomerProjectId::parse(project_id.as_str())?;
    }
    if let Some(resource_id) = resource_id {
        PublicServiceId::parse(resource_id.as_str())?;
    }
    Ok(())
}

fn validate_issuer(value: &str) -> Result<(), CustomerResourceError> {
    validate_bounded_opaque("Keycloak issuer", value, MAX_KEYCLOAK_ISSUER_BYTES)?;
    let authority_and_path = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| {
            validation_error(
                "Keycloak issuer",
                "must be an absolute HTTP or HTTPS issuer URL",
            )
        })?;
    let authority = authority_and_path
        .split_once('/')
        .map_or(authority_and_path, |(authority, _)| authority);
    if authority.is_empty()
        || authority.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.ends_with('/')
    {
        return Err(validation_error(
            "Keycloak issuer",
            "must contain an authority, no credentials/query/fragment, and no trailing slash",
        ));
    }
    Ok(())
}

fn validate_bounded_opaque(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), CustomerResourceError> {
    if value.is_empty() || value.len() > max_bytes {
        return Err(validation_error(
            field,
            format!("must contain between 1 and {max_bytes} bytes"),
        ));
    }
    if value.trim() != value || value.chars().any(char::is_control) {
        return Err(validation_error(
            field,
            "must not contain surrounding whitespace or control characters",
        ));
    }
    Ok(())
}

fn validate_bounded_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), CustomerResourceError> {
    if value.len() > max_bytes {
        return Err(validation_error(
            field,
            format!("must not exceed {max_bytes} bytes"),
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(validation_error(
            field,
            "contains unsupported control characters",
        ));
    }
    Ok(())
}

fn validate_dns_label(field: &'static str, value: &str) -> Result<(), CustomerResourceError> {
    if value.is_empty() || value.len() > MAX_KUBERNETES_NAME_BYTES {
        return Err(validation_error(
            field,
            format!("must contain between 1 and {MAX_KUBERNETES_NAME_BYTES} bytes"),
        ));
    }
    let starts_and_ends_with_alphanumeric = value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if !starts_and_ends_with_alphanumeric
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(validation_error(
            field,
            "must be a lowercase DNS label using letters, digits, or internal hyphens",
        ));
    }
    Ok(())
}

fn validate_public_host(value: &str) -> Result<(), CustomerResourceError> {
    if value.is_empty() || value.len() > MAX_PUBLIC_ADDRESS_BYTES {
        return Err(validation_error(
            "public address host",
            format!("must contain between 1 and {MAX_PUBLIC_ADDRESS_BYTES} bytes"),
        ));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if value.ends_with('.') {
        return Err(validation_error(
            "public address host",
            "must not have a trailing DNS root dot",
        ));
    }
    for label in value.split('.') {
        validate_dns_label("public address host", label)?;
    }
    Ok(())
}

fn validate_nonzero_port(field: &'static str, port: u16) -> Result<(), CustomerResourceError> {
    if port == 0 {
        return Err(validation_error(field, "must be between 1 and 65535"));
    }
    Ok(())
}

fn validation_error(field: &'static str, reason: impl Into<String>) -> CustomerResourceError {
    CustomerResourceError::Validation {
        field,
        reason: reason.into(),
    }
}

fn stable_identifier(prefix: &str, domain: &[u8], parts: &[&str]) -> String {
    format!("{prefix}{}", stable_hex(domain, parts, 16))
}

fn stable_hex(domain: &[u8], parts: &[&str], bytes: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    let mut result = String::with_capacity(bytes * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &digest[..bytes] {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn identity(issuer: &str, subject: &str) -> KeycloakIdentity {
        KeycloakIdentity::new(issuer, subject).expect("test identity must be valid")
    }

    fn account_request(
        cluster_id: &ClusterId,
        identity: KeycloakIdentity,
        quota: CustomerQuota,
    ) -> EnsurePersonalAccount {
        EnsurePersonalAccount {
            cluster_id: cluster_id.clone(),
            identity,
            quota,
            created_at: Utc::now(),
        }
    }

    fn project_request(account: &CustomerAccount, name: &str) -> CreateCustomerProject {
        CreateCustomerProject {
            cluster_id: account.cluster_id.clone(),
            account_id: account.account_id.clone(),
            name: KubernetesName::parse(name).expect("test project name must be valid"),
            created_at: Utc::now(),
        }
    }

    fn service_request(
        account: &CustomerAccount,
        project: &CustomerProject,
        name: &str,
    ) -> CreatePublicService {
        CreatePublicService {
            cluster_id: account.cluster_id.clone(),
            resource_id: test_public_service_id(name),
            account_id: account.account_id.clone(),
            project_id: project.project_id.clone(),
            name: KubernetesName::parse(name).expect("test service name must be valid"),
            spec: PublicServiceSpec {
                traffic_mode: PublicServiceTrafficMode::Forwarded,
                protocol: PublicServiceProtocol::Udp,
                public_port: 7882,
                backend_service: KubernetesName::parse("livekit")
                    .expect("test backend name must be valid"),
                backend_port: 7882,
                ingress_replicas: 2,
            },
            created_at: Utc::now(),
        }
    }

    fn test_public_service_id(name: &str) -> PublicServiceId {
        let mut entropy = [0_u8; 16];
        for (target, source) in entropy.iter_mut().zip(name.bytes()) {
            *target = source;
        }
        PublicServiceId::from_entropy(entropy)
    }

    #[tokio::test]
    async fn personal_accounts_are_isolated_by_cluster_issuer_and_subject(
    ) -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_a = ClusterId::from_string("cluster-a");
        let cluster_b = ClusterId::from_string("cluster-b");
        let first = store
            .ensure_personal_account(account_request(
                &cluster_a,
                identity("https://id-a.example/realms/customers", "subject-a"),
                CustomerQuota::default(),
            ))
            .await?;
        let other_issuer = store
            .ensure_personal_account(account_request(
                &cluster_a,
                identity("https://id-b.example/realms/customers", "subject-a"),
                CustomerQuota::default(),
            ))
            .await?;
        let other_cluster = store
            .ensure_personal_account(account_request(
                &cluster_b,
                first.identity.clone(),
                CustomerQuota::default(),
            ))
            .await?;

        assert_ne!(first.account_id, other_issuer.account_id);
        assert_ne!(first.account_id, other_cluster.account_id);
        assert_eq!(
            store
                .get_personal_account(&cluster_a, &first.identity)
                .await?,
            Some(first.clone())
        );
        let repeated = store
            .ensure_personal_account(account_request(
                &cluster_a,
                first.identity.clone(),
                CustomerQuota::new(99, 999)?,
            ))
            .await?;
        assert_eq!(repeated, first);
        Ok(())
    }

    #[tokio::test]
    async fn project_creation_enforces_quota_and_unique_names_atomically(
    ) -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_id = ClusterId::from_string("cluster-a");
        let account = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::new(1, 10)?,
            ))
            .await?;
        store
            .create_customer_project(project_request(&account, "first"))
            .await?;

        assert!(matches!(
            store
                .create_customer_project(project_request(&account, "first"))
                .await,
            Err(CustomerResourceError::DuplicateName {
                kind: CustomerResourceKind::Project,
                ..
            })
        ));
        assert!(matches!(
            store
                .create_customer_project(project_request(&account, "second"))
                .await,
            Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::Project,
                limit: 1
            })
        ));
        assert_eq!(
            store
                .list_customer_projects(
                    &cluster_id,
                    &account.account_id,
                    None,
                    MAX_CUSTOMER_RESOURCE_PAGE_SIZE,
                )
                .await?
                .projects
                .len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn public_service_creation_enforces_account_wide_quota_and_names(
    ) -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_id = ClusterId::from_string("cluster-a");
        let account = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::new(2, 1)?,
            ))
            .await?;
        let first_project = store
            .create_customer_project(project_request(&account, "first"))
            .await?;
        let second_project = store
            .create_customer_project(project_request(&account, "second"))
            .await?;
        store
            .create_public_service(service_request(&account, &first_project, "livekit"))
            .await?;

        assert!(matches!(
            store
                .create_public_service(service_request(&account, &first_project, "livekit"))
                .await,
            Err(CustomerResourceError::DuplicateName {
                kind: CustomerResourceKind::PublicService,
                ..
            })
        ));
        assert!(matches!(
            store
                .create_public_service(service_request(&account, &second_project, "agones"))
                .await,
            Err(CustomerResourceError::QuotaExceeded {
                kind: CustomerResourceKind::PublicService,
                limit: 1
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn resource_pages_are_bounded_and_advance_by_stable_id(
    ) -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_id = ClusterId::from_string("cluster-a");
        let account = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::new(5, 5)?,
            ))
            .await?;
        let mut projects = Vec::new();
        for name in ["first", "second", "third"] {
            projects.push(
                store
                    .create_customer_project(project_request(&account, name))
                    .await?,
            );
        }
        projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));

        let first_page = store
            .list_customer_projects(&cluster_id, &account.account_id, None, 2)
            .await?;
        assert_eq!(first_page.projects.as_slice(), &projects[..2]);
        assert_eq!(
            first_page.next_cursor.as_ref(),
            Some(&projects[1].project_id)
        );
        let second_page = store
            .list_customer_projects(
                &cluster_id,
                &account.account_id,
                first_page.next_cursor.as_ref(),
                2,
            )
            .await?;
        assert_eq!(second_page.projects.as_slice(), &projects[2..]);
        assert!(second_page.next_cursor.is_none());
        assert!(matches!(
            store
                .list_customer_projects(&cluster_id, &account.account_id, None, 0)
                .await,
            Err(CustomerResourceError::Validation {
                field: "page limit",
                ..
            })
        ));

        let mut services = Vec::new();
        for (project, name) in projects.iter().zip(["one", "two", "three"]) {
            services.push(
                store
                    .create_public_service(service_request(&account, project, name))
                    .await?,
            );
        }
        services.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        let first_page = store
            .list_desired_public_services(&cluster_id, None, 2)
            .await?;
        assert_eq!(first_page.public_services.as_slice(), &services[..2]);
        let second_page = store
            .list_desired_public_services(&cluster_id, first_page.next_cursor.as_ref(), 2)
            .await?;
        assert_eq!(second_page.public_services.as_slice(), &services[2..]);
        assert!(second_page.next_cursor.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn ownership_checks_reject_cross_account_access() -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_id = ClusterId::from_string("cluster-a");
        let owner = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "owner"),
                CustomerQuota::default(),
            ))
            .await?;
        let stranger = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "stranger"),
                CustomerQuota::default(),
            ))
            .await?;
        let project = store
            .create_customer_project(project_request(&owner, "games"))
            .await?;
        let resource = store
            .create_public_service(service_request(&owner, &project, "agones"))
            .await?;

        assert!(matches!(
            store
                .get_customer_project(&cluster_id, &stranger.account_id, &project.project_id)
                .await,
            Err(CustomerResourceError::OwnershipMismatch {
                kind: CustomerResourceKind::Project,
                ..
            })
        ));
        assert!(matches!(
            store
                .get_public_service(
                    &cluster_id,
                    &stranger.account_id,
                    &project.project_id,
                    &resource.resource_id
                )
                .await,
            Err(CustomerResourceError::OwnershipMismatch { .. })
        ));
        assert_eq!(
            store
                .get_project_owner(&cluster_id, &project.project_id)
                .await?,
            Some(owner)
        );
        Ok(())
    }

    #[tokio::test]
    async fn project_and_account_deletion_remove_owned_resources(
    ) -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_id = ClusterId::from_string("cluster-a");
        let account = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::default(),
            ))
            .await?;
        let project = store
            .create_customer_project(project_request(&account, "media"))
            .await?;
        let resource = store
            .create_public_service(service_request(&account, &project, "livekit"))
            .await?;
        assert!(
            store
                .delete_public_service(
                    &cluster_id,
                    &account.account_id,
                    &project.project_id,
                    &resource.resource_id,
                )
                .await?
        );
        assert!(
            !store
                .delete_public_service(
                    &cluster_id,
                    &account.account_id,
                    &project.project_id,
                    &resource.resource_id,
                )
                .await?
        );
        store
            .create_public_service(service_request(&account, &project, "livekit"))
            .await?;

        assert!(
            store
                .delete_customer_project(&cluster_id, &account.account_id, &project.project_id)
                .await?
        );
        assert!(store
            .list_desired_public_services(&cluster_id, None, MAX_CUSTOMER_RESOURCE_PAGE_SIZE)
            .await?
            .public_services
            .is_empty());
        let second = store
            .create_customer_project(project_request(&account, "games"))
            .await?;
        store
            .create_public_service(service_request(&account, &second, "agones"))
            .await?;
        assert!(
            store
                .delete_customer_account(&cluster_id, &account.account_id)
                .await?
        );
        assert!(store
            .get_customer_account(&cluster_id, &account.account_id)
            .await?
            .is_none());
        assert!(store
            .list_desired_public_services(&cluster_id, None, MAX_CUSTOMER_RESOURCE_PAGE_SIZE)
            .await?
            .public_services
            .is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn status_update_rejects_stale_generation() -> Result<(), CustomerResourceError> {
        let store = InMemoryStore::default();
        let cluster_id = ClusterId::from_string("cluster-a");
        let account = store
            .ensure_personal_account(account_request(
                &cluster_id,
                identity("https://id.example/realms/customers", "subject-a"),
                CustomerQuota::default(),
            ))
            .await?;
        let project = store
            .create_customer_project(project_request(&account, "media"))
            .await?;
        let resource = store
            .create_public_service(service_request(&account, &project, "livekit"))
            .await?;
        let observed_at = Utc::now() + Duration::seconds(1);
        let ready = PublicServiceStatus {
            phase: PublicServicePhase::Ready,
            public_addresses: vec![PublicServiceAddress::new(
                "203.0.113.10",
                resource.spec.public_port,
            )?],
            message: None,
            observed_generation: resource.generation,
            observed_at: Some(observed_at),
        };

        assert!(matches!(
            store
                .update_public_service_status(&cluster_id, &resource.resource_id, 0, ready.clone())
                .await,
            Err(CustomerResourceError::GenerationConflict {
                expected: 0,
                actual: 1,
                ..
            })
        ));
        let updated = store
            .update_public_service_status(
                &cluster_id,
                &resource.resource_id,
                resource.generation,
                ready.clone(),
            )
            .await?;
        assert_eq!(updated.status.phase, PublicServicePhase::Ready);
        assert_eq!(updated.updated_at, observed_at);

        let mut stale = ready;
        stale.observed_at = Some(observed_at - Duration::seconds(1));
        assert!(matches!(
            store
                .update_public_service_status(
                    &cluster_id,
                    &resource.resource_id,
                    resource.generation,
                    stale,
                )
                .await,
            Err(CustomerResourceError::StatusObservationConflict { .. })
        ));
        let mut future = updated.status.clone();
        future.observed_at =
            Some(Utc::now() + Duration::seconds(MAX_STATUS_FUTURE_SKEW_SECONDS + 1));
        assert!(matches!(
            store
                .update_public_service_status(
                    &cluster_id,
                    &resource.resource_id,
                    resource.generation,
                    future,
                )
                .await,
            Err(CustomerResourceError::Validation {
                field: "observed_at",
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn bounded_models_reject_oversized_deserialization() {
        let oversized_subject = "s".repeat(MAX_KEYCLOAK_SUBJECT_BYTES + 1);
        let identity_json = serde_json::json!({
            "issuer": "https://id.example/realms/customers",
            "subject": oversized_subject,
        });
        assert!(serde_json::from_value::<KeycloakIdentity>(identity_json).is_err());

        let addresses = (0..=MAX_PUBLIC_ADDRESSES)
            .map(|index| {
                serde_json::json!({
                    "host": format!("node-{index}.example"),
                    "port": 443,
                })
            })
            .collect::<Vec<_>>();
        let status_json = serde_json::json!({
            "phase": "ready",
            "public_addresses": addresses,
            "message": null,
            "observed_generation": 1,
            "observed_at": Utc::now(),
        });
        assert!(serde_json::from_value::<PublicServiceStatus>(status_json).is_err());
    }
}
