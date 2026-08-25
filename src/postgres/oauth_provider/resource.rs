use super::{
    super::storage_error,
    PostgresOAuthProviderStore,
    rows::{LINK_FIELDS, LinkRow, RESOURCE_FIELDS, ResourceRow},
};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthClientResourceLinkOutcome, OAuthProviderClientResource, OAuthProviderResource,
        OAuthProviderResourceStore, schema::OAuthProviderModel,
    },
};
use async_trait::async_trait;
#[async_trait]
impl OAuthProviderResourceStore for PostgresOAuthProviderStore {
    async fn find_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Resource);
        sqlx::query_as::<_, ResourceRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1",
            model.projection(RESOURCE_FIELDS),
            model.table(),
            model.column("identifier")
        ))
        .bind(identifier)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn list_oauth_resources(&self) -> Result<Vec<OAuthProviderResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Resource);
        sqlx::query_as::<_, ResourceRow>(&format!(
            "SELECT {} FROM {} ORDER BY {}",
            model.projection(RESOURCE_FIELDS),
            model.table(),
            model.column("identifier")
        ))
        .fetch_all(self.pool())
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(storage_error)
    }

    async fn create_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Resource);
        sqlx::query_as::<_, ResourceRow>(&format!(
            "INSERT INTO {} ({}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
             ON CONFLICT ({}) DO NOTHING RETURNING {}",
            model.table(),
            model.columns(RESOURCE_FIELDS),
            model.column("identifier"),
            model.projection(RESOURCE_FIELDS)
        ))
        .bind(resource.id)
        .bind(resource.identifier)
        .bind(resource.name)
        .bind(resource.access_token_ttl)
        .bind(resource.refresh_token_ttl)
        .bind(resource.signing_algorithm)
        .bind(resource.signing_key_id)
        .bind(resource.allowed_scopes)
        .bind(resource.custom_claims)
        .bind(resource.dpop_bound_access_tokens_required)
        .bind(resource.disabled)
        .bind(resource.created_at)
        .bind(resource.updated_at)
        .bind(resource.policy_version)
        .bind(resource.metadata)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn update_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Resource);
        sqlx::query_as::<_, ResourceRow>(&format!(
            "UPDATE {} SET {}=$3, {}=$4, {}=$5, {}=$6, {}=$7, {}=$8, {}=$9, {}=$10, \
             {}=$11, {}=$12, {}=$13, {}=$14, {}=$15 WHERE \"id\"=$1 AND {}=$2 RETURNING {}",
            model.table(),
            model.column("name"),
            model.column("accessTokenTtl"),
            model.column("refreshTokenTtl"),
            model.column("signingAlgorithm"),
            model.column("signingKeyId"),
            model.column("allowedScopes"),
            model.column("customClaims"),
            model.column("dpopBoundAccessTokensRequired"),
            model.column("disabled"),
            model.column("createdAt"),
            model.column("updatedAt"),
            model.column("policyVersion"),
            model.column("metadata"),
            model.column("identifier"),
            model.projection(RESOURCE_FIELDS)
        ))
        .bind(resource.id)
        .bind(resource.identifier)
        .bind(resource.name)
        .bind(resource.access_token_ttl)
        .bind(resource.refresh_token_ttl)
        .bind(resource.signing_algorithm)
        .bind(resource.signing_key_id)
        .bind(resource.allowed_scopes)
        .bind(resource.custom_claims)
        .bind(resource.dpop_bound_access_tokens_required)
        .bind(resource.disabled)
        .bind(resource.created_at)
        .bind(resource.updated_at)
        .bind(resource.policy_version)
        .bind(resource.metadata)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn delete_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Resource);
        sqlx::query_as::<_, ResourceRow>(&format!(
            "DELETE FROM {} WHERE {}=$1 RETURNING {}",
            model.table(),
            model.column("identifier"),
            model.projection(RESOURCE_FIELDS)
        ))
        .bind(identifier)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthProviderClientResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::ClientResource);
        sqlx::query_as::<_, LinkRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1 ORDER BY {}",
            model.projection(LINK_FIELDS),
            model.table(),
            model.column("clientId"),
            model.column("resourceId")
        ))
        .bind(client_id)
        .fetch_all(self.pool())
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(storage_error)
    }

    async fn link_oauth_client_resource(
        &self,
        link: OAuthProviderClientResource,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError> {
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(serde_json::json!([&link.client_id, &link.resource_id]).to_string())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;

        let client = self.schema.model(OAuthProviderModel::Client);
        let client_exists = sqlx::query_scalar::<_, i32>(&format!(
            "SELECT 1 FROM {} WHERE {}=$1 FOR KEY SHARE",
            client.table(),
            client.column("clientId")
        ))
        .bind(&link.client_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .is_some();
        if !client_exists {
            return Ok(OAuthClientResourceLinkOutcome::ClientNotFound);
        }
        let resource = self.schema.model(OAuthProviderModel::Resource);
        let resource_exists = sqlx::query_scalar::<_, i32>(&format!(
            "SELECT 1 FROM {} WHERE {}=$1 FOR KEY SHARE",
            resource.table(),
            resource.column("identifier")
        ))
        .bind(&link.resource_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?
        .is_some();
        if !resource_exists {
            return Ok(OAuthClientResourceLinkOutcome::ResourceNotFound);
        }

        let model = self.schema.model(OAuthProviderModel::ClientResource);
        let inserted = sqlx::query_as::<_, LinkRow>(&format!(
            "INSERT INTO {} ({}) VALUES ($1,$2,$3,$4,$5) ON CONFLICT ({}, {}) DO NOTHING RETURNING {}",
            model.table(),
            model.columns(LINK_FIELDS),
            model.column("clientId"),
            model.column("resourceId"),
            model.projection(LINK_FIELDS)
        ))
        .bind(link.id)
        .bind(&link.client_id)
        .bind(&link.resource_id)
        .bind(&link.metadata)
        .bind(link.created_at)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;
        let outcome = if let Some(inserted) = inserted {
            OAuthClientResourceLinkOutcome::Linked(inserted.into())
        } else {
            let existing = sqlx::query_as::<_, LinkRow>(&format!(
                "SELECT {} FROM {} WHERE {}=$1 AND {}=$2",
                model.projection(LINK_FIELDS),
                model.table(),
                model.column("clientId"),
                model.column("resourceId")
            ))
            .bind(&link.client_id)
            .bind(&link.resource_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
            OAuthClientResourceLinkOutcome::AlreadyLinked(existing.into())
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }

    async fn unlink_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::ClientResource);
        sqlx::query_as::<_, LinkRow>(&format!(
            "DELETE FROM {} WHERE {}=$1 AND {}=$2 RETURNING {}",
            model.table(),
            model.column("clientId"),
            model.column("resourceId"),
            model.projection(LINK_FIELDS)
        ))
        .bind(client_id)
        .bind(resource_id)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }
}
