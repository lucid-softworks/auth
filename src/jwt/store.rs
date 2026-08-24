use super::{JwtAdapterContext, JwtSchema, NewJwk, StoredJwk};
use crate::AuthError;
use async_trait::async_trait;

/// Default persistence boundary used by the core authentication adapter.
#[async_trait]
pub trait JwkStore: Send + Sync {
    async fn list_jwks(&self, schema: &JwtSchema) -> Result<Vec<StoredJwk>, AuthError>;

    async fn create_jwk(&self, schema: &JwtSchema, jwk: NewJwk) -> Result<StoredJwk, AuthError>;
}

/// Better Auth JWT custom `getJwks` callback.
#[async_trait]
pub trait JwtJwksReader: Send + Sync {
    async fn get_jwks(
        &self,
        context: &JwtAdapterContext,
    ) -> Result<Option<Vec<StoredJwk>>, AuthError>;
}

/// Better Auth JWT custom `createJwk(data, context)` callback.
#[async_trait]
pub trait JwtJwkCreator: Send + Sync {
    async fn create_jwk(
        &self,
        data: NewJwk,
        context: &JwtAdapterContext,
    ) -> Result<StoredJwk, AuthError>;
}

#[derive(Clone, Default)]
pub struct JwtAdapterConfig {
    pub get_jwks: Option<std::sync::Arc<dyn JwtJwksReader>>,
    pub create_jwk: Option<std::sync::Arc<dyn JwtJwkCreator>>,
}

impl std::fmt::Debug for JwtAdapterConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JwtAdapterConfig")
            .field("get_jwks", &self.get_jwks.is_some())
            .field("create_jwk", &self.create_jwk.is_some())
            .finish()
    }
}
