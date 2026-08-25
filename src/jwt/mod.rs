mod config;
#[cfg(feature = "axum")]
mod cookie_cache;
mod crypto;
mod duration;
mod keyring;
mod model;
mod schema;
mod store;
mod token;

#[cfg(feature = "axum")]
mod axum;

pub use config::{
    JwkAlgorithm, JwtAdapterContext, JwtAudience, JwtClaimsConfig, JwtConfig, JwtExpiration,
    JwtJwksConfig, JwtOverrideOptions, JwtPayloadDefinition, JwtProtectedHeader, JwtRemoteSigner,
    JwtSchema, JwtSession, JwtSigningOverrides, JwtSubjectResolver, ResolvedSigningKey,
};
pub use crypto::{ExportedKeyPair, generate_exported_key_pair};
pub use duration::to_exp_jwt;
pub use model::{NewJwk, StoredJwk};
pub use store::{JwkStore, JwtAdapterConfig, JwtJwkCreator, JwtJwksReader};
pub use token::JwtService;

#[cfg(feature = "axum")]
pub(crate) use cookie_cache::{decode as decode_cookie_cache, encode as encode_cookie_cache};

use crate::{
    AuthConfig, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginMigration,
};
use async_trait::async_trait;
use std::{borrow::Cow, sync::Arc};

#[derive(Clone)]
pub struct JwtPlugin {
    config: Arc<JwtConfig>,
    migrations: Vec<PluginMigration>,
}

impl JwtPlugin {
    pub fn new(config: JwtConfig) -> Self {
        let migration = PluginMigration::owned(
            "better-auth-jwt-schema",
            "Better Auth 1.7.1 JWT JWKS schema",
            config.schema.migration_sql(),
        );
        Self {
            config: Arc::new(config),
            migrations: vec![migration],
        }
    }

    pub fn config(&self) -> &JwtConfig {
        &self.config
    }
}

impl Default for JwtPlugin {
    fn default() -> Self {
        Self::new(JwtConfig::default())
    }
}

#[async_trait]
impl AuthPlugin for JwtPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "jwt",
            display_name: "Better Auth JWT",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("jwt"),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(vec![
                PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Owned(self.config.jwks.jwks_path.clone()),
                    client_method: "jwks",
                },
                PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Borrowed("/token"),
                    client_method: "token",
                },
            ]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "jwtClient",
            )),
        }
    }

    fn validate(&self, auth: &AuthConfig) -> Result<(), crate::AuthError> {
        let remote = self
            .config
            .jwks
            .remote_url
            .as_deref()
            .is_some_and(|value| !value.is_empty());
        if self.config.jwt.sign.is_some() && !remote {
            return invalid("options.jwks.remoteUrl must be set when using options.jwt.sign");
        }
        if remote && self.config.jwks.key_pair_config.is_none() {
            return invalid(
                "options.jwks.keyPairConfig.alg must be specified when options.jwks.remoteUrl is used for OpenID metadata",
            );
        }
        let path = &self.config.jwks.jwks_path;
        if path.is_empty() || !path.starts_with('/') || path.contains("..") {
            return invalid(
                "options.jwks.jwksPath must be a non-empty string starting with '/' and not contain '..'",
            );
        }
        if self.config.session_cookie_cache {
            if auth.session.cookie_cache.strategy != crate::CookieCacheStrategy::Jwt {
                return invalid(
                    "`jwt({ sessionCookieCache: true })` requires `session.cookieCache.strategy = \"jwt\"`.",
                );
            }
            if self.config.jwt.sign.is_some() {
                return invalid(
                    "`jwt({ sessionCookieCache: true })` requires locally managed JWT plugin keys and does not support `jwt.sign`.",
                );
            }
            if let Some(grace_period) = self.config.jwks.grace_period
                && auth.session.cookie_cache.max_age > grace_period
            {
                tracing::warn!(
                    cookie_max_age_seconds = auth.session.cookie_cache.max_age.num_seconds(),
                    grace_period_seconds = grace_period.num_seconds(),
                    "session cookie-cache max age exceeds the JWT JWKS grace period; rotated keys may stop being published before cached sessions expire"
                );
            }
        }
        Ok(())
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        Cow::Borrowed(&self.migrations)
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::after_response(service, &self.config, request, response).await
    }
}

fn invalid<T>(message: &str) -> Result<T, crate::AuthError> {
    Err(crate::AuthError::InvalidConfiguration(message.into()))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtError {
    #[error("invalid JWT expiration time: {0}")]
    InvalidExpiration(String),
    #[error("JWT key generation failed")]
    KeyGeneration,
    #[error("JWT private-key encryption failed")]
    KeyEncryption,
    #[error(
        "JWT private-key decryption failed; verify that the configured secret matches the key store"
    )]
    KeyDecryption,
    #[error("JWT signing failed")]
    Signing,
    #[error("JWT key configuration is invalid: {0}")]
    KeyConfiguration(String),
    #[error("no JWT key sets were found after lazy provisioning")]
    NoKeySets,
}
