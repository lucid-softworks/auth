use super::MemoryStore;
use crate::{AuthError, JwkStore, JwtSchema, NewJwk, StoredJwk};
use async_trait::async_trait;

#[async_trait]
impl JwkStore for MemoryStore {
    async fn list_jwks(&self, schema: &JwtSchema) -> Result<Vec<StoredJwk>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .jwks
            .get(schema.table())
            .cloned()
            .unwrap_or_default())
    }

    async fn create_jwk(&self, schema: &JwtSchema, jwk: NewJwk) -> Result<StoredJwk, AuthError> {
        let stored = StoredJwk {
            id: uuid::Uuid::new_v4().to_string(),
            public_key: jwk.public_key,
            private_key: jwk.private_key,
            created_at: jwk.created_at,
            expires_at: jwk.expires_at,
            alg: jwk.alg,
            crv: jwk.crv,
        };
        self.state
            .write()
            .await
            .jwks
            .entry(schema.table().into())
            .or_default()
            .push(stored.clone());
        Ok(stored)
    }
}
