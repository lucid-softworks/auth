use super::MemoryStore;
use crate::{AuthError, JwkStore, JwtSchema, NewJwk, StoredJwk};
use async_trait::async_trait;

#[async_trait]
impl JwkStore for MemoryStore {
    async fn list_jwks(&self, _schema: &JwtSchema) -> Result<Vec<StoredJwk>, AuthError> {
        Ok(self.state.read().await.jwks.clone())
    }

    async fn create_jwk(&self, _schema: &JwtSchema, jwk: NewJwk) -> Result<StoredJwk, AuthError> {
        let stored = StoredJwk {
            id: uuid::Uuid::new_v4().to_string(),
            public_key: jwk.public_key,
            private_key: jwk.private_key,
            created_at: jwk.created_at,
            expires_at: jwk.expires_at,
            alg: jwk.alg,
            crv: jwk.crv,
        };
        self.state.write().await.jwks.push(stored.clone());
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_physical_names_do_not_partition_canonical_memory_records() {
        let store = MemoryStore::default();
        let configured = JwtSchema {
            model_name: Some("tenant signing keys".into()),
            ..JwtSchema::default()
        };
        store
            .create_jwk(
                &configured,
                NewJwk {
                    public_key: "public".into(),
                    private_key: "private".into(),
                    created_at: chrono::Utc::now(),
                    expires_at: None,
                    alg: None,
                    crv: None,
                },
            )
            .await
            .unwrap();

        let records = store.list_jwks(&JwtSchema::default()).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].public_key, "public");
    }
}
