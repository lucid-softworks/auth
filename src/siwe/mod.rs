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
    AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginMigration,
};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

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

impl SiweSchema {
    pub(crate) fn table(&self) -> &str {
        configured_name(&self.model_name, "lucid_auth_wallet_addresses")
    }

    pub(crate) fn user_id(&self) -> &str {
        configured_name(&self.user_id_field_name, "user_id")
    }

    pub(crate) fn address(&self) -> &str {
        configured_name(&self.address_field_name, "address")
    }

    pub(crate) fn chain_id(&self) -> &str {
        configured_name(&self.chain_id_field_name, "chain_id")
    }

    pub(crate) fn is_primary(&self) -> &str {
        configured_name(&self.is_primary_field_name, "is_primary")
    }

    pub(crate) fn created_at(&self) -> &str {
        configured_name(&self.created_at_field_name, "created_at")
    }

    fn migration_sql(&self) -> String {
        let table = quote_identifier(self.table());
        let user_id = quote_identifier(self.user_id());
        let address = quote_identifier(self.address());
        let chain_id = quote_identifier(self.chain_id());
        let is_primary = quote_identifier(self.is_primary());
        let created_at = quote_identifier(self.created_at());
        format!(
            "CREATE TABLE IF NOT EXISTS {table} (\n\
               id UUID PRIMARY KEY,\n\
               {user_id} UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,\n\
               {address} TEXT NOT NULL,\n\
               {chain_id} DOUBLE PRECISION NOT NULL,\n\
               {is_primary} BOOLEAN NOT NULL DEFAULT FALSE,\n\
               {created_at} TIMESTAMPTZ NOT NULL\n\
             );\n\n\
             CREATE INDEX IF NOT EXISTS lucid_auth_siwe_user_id_idx\n\
               ON {table} ({user_id});\n\n\
             CREATE UNIQUE INDEX IF NOT EXISTS lucid_auth_siwe_identity_unique_idx\n\
               ON {table} (lower({address}), {chain_id});\n"
        )
    }
}

fn configured_name<'a>(configured: &'a Option<String>, default: &'a str) -> &'a str {
    configured
        .as_deref()
        .filter(|name| !name.is_empty())
        .unwrap_or(default)
}

pub(crate) fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
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
    migrations: Vec<PluginMigration>,
}

impl SiwePlugin {
    pub fn new(store: Arc<dyn SiweStore>, config: SiweConfig) -> Self {
        let migration = PluginMigration::owned(
            "better-auth-siwe-schema",
            "Better Auth 1.7.1 SIWE wallet-address schema",
            config.schema.migration_sql(),
        );
        Self {
            store,
            config: Arc::new(config),
            migrations: vec![migration],
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

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        Cow::Borrowed(&self.migrations)
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
