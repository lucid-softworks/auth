use super::{JwtAdapterConfig, StoredJwk};
use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum JwkAlgorithm {
    #[default]
    EdDsa,
    Es256,
    Es512,
    Ps256 {
        modulus_length: Option<u32>,
    },
    Rs256 {
        modulus_length: Option<u32>,
    },
}

impl JwkAlgorithm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::EdDsa => "EdDSA",
            Self::Es256 => "ES256",
            Self::Es512 => "ES512",
            Self::Ps256 { .. } => "PS256",
            Self::Rs256 { .. } => "RS256",
        }
    }

    pub const fn curve(self) -> Option<&'static str> {
        match self {
            Self::EdDsa => Some("Ed25519"),
            Self::Es256 => Some("P-256"),
            Self::Es512 => Some("P-521"),
            Self::Ps256 { .. } | Self::Rs256 { .. } => None,
        }
    }

    pub const fn rsa_modulus_length(self) -> Option<u32> {
        match self {
            Self::Ps256 { modulus_length } | Self::Rs256 { modulus_length } => modulus_length,
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtAudience {
    One(String),
    Many(Vec<String>),
}

impl JwtAudience {
    pub(crate) fn values(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }

    pub(crate) fn value(&self) -> Value {
        match self {
            Self::One(value) => Value::String(value.clone()),
            Self::Many(values) => Value::Array(values.iter().cloned().map(Value::String).collect()),
        }
    }
}

impl From<String> for JwtAudience {
    fn from(value: String) -> Self {
        Self::One(value)
    }
}

impl From<&str> for JwtAudience {
    fn from(value: &str) -> Self {
        Self::One(value.into())
    }
}

impl From<Vec<String>> for JwtAudience {
    fn from(value: Vec<String>) -> Self {
        Self::Many(value)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum JwtExpiration {
    NumericDate(f64),
    Date(DateTime<Utc>),
    Duration(String),
}

impl Default for JwtExpiration {
    fn default() -> Self {
        Self::Duration("15m".into())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtProtectedHeader {
    pub typ: Option<String>,
    pub cty: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtSigningOverrides {
    pub signing_key_id: Option<String>,
    pub signing_algorithm: Option<JwkAlgorithm>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct JwtSession {
    pub user: Value,
    pub session: Value,
}

#[async_trait]
pub trait JwtPayloadDefinition: Send + Sync {
    async fn define_payload(&self, session: &JwtSession) -> Result<Map<String, Value>, AuthError>;
}

#[async_trait]
pub trait JwtSubjectResolver: Send + Sync {
    async fn get_subject(&self, session: &JwtSession) -> Result<Option<String>, AuthError>;
}

#[async_trait]
pub trait JwtRemoteSigner: Send + Sync {
    async fn sign(
        &self,
        payload: Map<String, Value>,
        header: Option<JwtProtectedHeader>,
        signing: Option<JwtSigningOverrides>,
    ) -> Result<String, AuthError>;
}

#[derive(Clone, Default)]
pub struct JwtClaimsConfig {
    pub issuer: Option<String>,
    pub audience: Option<JwtAudience>,
    pub expiration_time: JwtExpiration,
    pub define_payload: Option<Arc<dyn JwtPayloadDefinition>>,
    pub get_subject: Option<Arc<dyn JwtSubjectResolver>>,
    pub sign: Option<Arc<dyn JwtRemoteSigner>>,
}

impl std::fmt::Debug for JwtClaimsConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwtClaimsConfig")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("expiration_time", &self.expiration_time)
            .field("define_payload", &self.define_payload.is_some())
            .field("get_subject", &self.get_subject.is_some())
            .field("sign", &self.sign.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtSchema {
    pub model_name: Option<String>,
    pub public_key_field_name: Option<String>,
    pub private_key_field_name: Option<String>,
    pub created_at_field_name: Option<String>,
    pub expires_at_field_name: Option<String>,
    pub alg_field_name: Option<String>,
    pub crv_field_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JwtJwksConfig {
    pub remote_url: Option<String>,
    pub key_pair_config: Option<JwkAlgorithm>,
    pub key_pair_configs: Vec<JwkAlgorithm>,
    pub disable_private_key_encryption: bool,
    pub rotation_interval: Option<Duration>,
    pub grace_period: Option<Duration>,
    pub jwks_path: String,
}

impl Default for JwtJwksConfig {
    fn default() -> Self {
        Self {
            remote_url: None,
            key_pair_config: None,
            key_pair_configs: Vec::new(),
            disable_private_key_encryption: false,
            rotation_interval: None,
            grace_period: None,
            jwks_path: "/jwks".into(),
        }
    }
}

#[derive(Clone, Default)]
pub struct JwtConfig {
    pub session_cookie_cache: bool,
    pub disable_setting_jwt_header: bool,
    pub jwks: JwtJwksConfig,
    pub jwt: JwtClaimsConfig,
    pub schema: JwtSchema,
    pub adapter: JwtAdapterConfig,
}

/// Shallow top-level JWT plugin overrides used by Better Auth's server-only
/// `signJWT` operation. Each present field replaces the corresponding plugin
/// option as a whole.
#[derive(Clone, Default)]
pub struct JwtOverrideOptions {
    pub session_cookie_cache: Option<bool>,
    pub disable_setting_jwt_header: Option<bool>,
    pub jwks: Option<JwtJwksConfig>,
    pub jwt: Option<JwtClaimsConfig>,
    pub schema: Option<JwtSchema>,
    pub adapter: Option<JwtAdapterConfig>,
}

impl JwtOverrideOptions {
    pub(crate) fn apply_to(&self, config: &JwtConfig) -> JwtConfig {
        let mut merged = config.clone();
        if let Some(value) = self.session_cookie_cache {
            merged.session_cookie_cache = value;
        }
        if let Some(value) = self.disable_setting_jwt_header {
            merged.disable_setting_jwt_header = value;
        }
        if let Some(value) = &self.jwks {
            merged.jwks = value.clone();
        }
        if let Some(value) = &self.jwt {
            merged.jwt = value.clone();
        }
        if let Some(value) = &self.schema {
            merged.schema = value.clone();
        }
        if let Some(value) = &self.adapter {
            merged.adapter = value.clone();
        }
        merged
    }
}

impl std::fmt::Debug for JwtOverrideOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwtOverrideOptions")
            .field("session_cookie_cache", &self.session_cookie_cache)
            .field(
                "disable_setting_jwt_header",
                &self.disable_setting_jwt_header,
            )
            .field("jwks", &self.jwks)
            .field("jwt", &self.jwt)
            .field("schema", &self.schema)
            .field("adapter", &self.adapter)
            .finish()
    }
}

impl std::fmt::Debug for JwtConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwtConfig")
            .field("session_cookie_cache", &self.session_cookie_cache)
            .field(
                "disable_setting_jwt_header",
                &self.disable_setting_jwt_header,
            )
            .field("jwks", &self.jwks)
            .field("jwt", &self.jwt)
            .field("schema", &self.schema)
            .field("adapter", &self.adapter)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JwtAdapterContext {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct ResolvedSigningKey {
    pub alg: String,
    pub kid: String,
    pub(crate) key: StoredJwk,
}
