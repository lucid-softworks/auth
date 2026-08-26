#[cfg(feature = "axum")]
mod axum;
pub(crate) mod message;
mod model;
#[cfg(feature = "axum")]
mod request_origin;
mod store;

pub use model::{SiweIdentityWrite, SiweIdentityWriteOutcome, WalletAddress, WalletAddressOwner};
pub use store::SiweStore;

use crate::{
    AdditionalField, AdditionalFieldReference, AdditionalFieldType, AuthError, AuthPlugin,
    PluginClientMetadata, PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginSchemaTable,
};
use async_trait::async_trait;
use std::sync::Arc;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint("/siwe/nonce", "siwe.nonce"),
    endpoint("/siwe/get-nonce", "siwe.getNonce"),
    endpoint("/siwe/verify", "siwe.verify"),
];

const fn endpoint(path: &'static str, client_method: &'static str) -> PluginEndpoint {
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed(path),
        client_method,
    }
}

#[async_trait]
pub trait SiweNonceGenerator: Send + Sync {
    async fn generate(&self) -> Result<String, AuthError>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiweCacao {
    pub header_type: String,
    pub domain: String,
    pub audience: String,
    pub nonce: String,
    pub issuer: String,
    pub version: String,
    pub signature_type: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiweVerificationRequest {
    pub message: String,
    pub signature: String,
    pub address: String,
    pub chain_id: f64,
    pub cacao: SiweCacao,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SiweVerificationResult {
    pub token: String,
    pub user_id: uuid::Uuid,
    pub wallet_address: String,
    pub chain_id: f64,
}

#[async_trait]
pub trait SiweMessageVerifier: Send + Sync {
    async fn verify(&self, request: SiweVerificationRequest) -> Result<bool, AuthError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiweEnsProfile {
    pub name: Option<String>,
    pub avatar: Option<String>,
}

#[async_trait]
pub trait SiweEnsLookup: Send + Sync {
    async fn lookup(&self, wallet_address: &str) -> Result<SiweEnsProfile, AuthError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SiweSchema {
    pub model_name: Option<String>,
    pub user_id_field_name: Option<String>,
    pub address_field_name: Option<String>,
    pub chain_id_field_name: Option<String>,
    pub is_primary_field_name: Option<String>,
    pub created_at_field_name: Option<String>,
}

#[derive(Clone)]
pub struct SiweConfig {
    pub domain: String,
    pub email_domain_name: Option<String>,
    pub anonymous: bool,
    pub get_nonce: Arc<dyn SiweNonceGenerator>,
    pub verify_message: Arc<dyn SiweMessageVerifier>,
    pub ens_lookup: Option<Arc<dyn SiweEnsLookup>>,
    pub schema: SiweSchema,
}

impl std::fmt::Debug for SiweConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SiweConfig")
            .field("domain", &self.domain)
            .field("email_domain_name", &self.email_domain_name)
            .field("anonymous", &self.anonymous)
            .field("ens_lookup", &self.ens_lookup.is_some())
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

impl SiweConfig {
    pub fn new(
        domain: impl Into<String>,
        get_nonce: Arc<dyn SiweNonceGenerator>,
        verify_message: Arc<dyn SiweMessageVerifier>,
    ) -> Self {
        Self {
            domain: domain.into(),
            email_domain_name: None,
            anonymous: true,
            get_nonce,
            verify_message,
            ens_lookup: None,
            schema: SiweSchema::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SiweError {
    #[error("SIWE getNonce callback failed: {0}")]
    NonceCallback(String),
    #[error("SIWE getNonce must return an ERC-4361 nonce: 8-250 alphanumeric characters.")]
    InvalidGeneratedNonce,
    #[error(
        "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID"
    )]
    MessageMismatch,
    #[error("Unauthorized: Invalid or expired nonce")]
    InvalidOrExpiredNonce,
    #[error("Unauthorized: SIWE message has expired")]
    MessageExpired,
    #[error("Unauthorized: SIWE message is not yet valid")]
    MessageNotYetValid,
    #[error("Unauthorized: Invalid SIWE signature")]
    InvalidSignature,
    #[error("Email is required when anonymous is disabled.")]
    EmailRequired,
    #[error("Something went wrong. Please try again later.")]
    Unexpected(String),
}

#[derive(Clone)]
pub struct SiwePlugin {
    pub(crate) store: Arc<dyn SiweStore>,
    pub(crate) config: Arc<SiweConfig>,
}

impl SiwePlugin {
    pub fn new(store: Arc<dyn SiweStore>, config: SiweConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for SiwePlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "siwe",
            display_name: "Better Auth Sign In With Ethereum",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("siwe"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "siweClient",
            )),
        }
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        vec![wallet_schema(&self.config.schema)]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}

fn wallet_schema(schema: &SiweSchema) -> PluginSchemaTable {
    let mut table = PluginSchemaTable::new("walletAddress");
    if let Some(model_name) = &schema.model_name {
        table = table.model_name(model_name.clone());
    }
    let mut user_id = AdditionalField::new(AdditionalFieldType::String)
        .references(AdditionalFieldReference {
            model: "user".into(),
            field: "id".into(),
            on_delete: None,
        })
        .index(true);
    if let Some(name) = schema
        .user_id_field_name
        .as_ref()
        .filter(|name| !name.is_empty())
    {
        user_id = user_id.field_name(name.clone());
    }
    table = table.field("userId", user_id);
    for (logical, field_type, physical) in [
        (
            "address",
            AdditionalFieldType::String,
            &schema.address_field_name,
        ),
        (
            "chainId",
            AdditionalFieldType::Number,
            &schema.chain_id_field_name,
        ),
        (
            "createdAt",
            AdditionalFieldType::Date,
            &schema.created_at_field_name,
        ),
    ] {
        let mut field = AdditionalField::new(field_type);
        if let Some(name) = physical.as_ref().filter(|name| !name.is_empty()) {
            field = field.field_name(name.clone());
        }
        table = table.field(logical, field);
    }
    let mut primary =
        AdditionalField::new(AdditionalFieldType::Boolean).default_value(serde_json::json!(false));
    if let Some(name) = schema
        .is_primary_field_name
        .as_ref()
        .filter(|name| !name.is_empty())
    {
        primary = primary.field_name(name.clone());
    }
    table.field("isPrimary", primary)
}
