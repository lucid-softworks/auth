use super::{
    super::storage_error,
    PostgresOAuthProviderStore,
    rows::{CONSENT_FIELDS, ConsentRow},
};
use crate::{
    AuthError,
    oauth_provider::{OAuthProviderConsent, OAuthProviderConsentStore, schema::OAuthProviderModel},
};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl OAuthProviderConsentStore for PostgresOAuthProviderStore {
    async fn find_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Consent);
        sqlx::query_as::<_, ConsentRow>(&format!(
            "SELECT {} FROM {} WHERE \"id\"=$1",
            model.projection(CONSENT_FIELDS),
            model.table()
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn find_oauth_consent_for_grant(
        &self,
        client_id: &str,
        user_id: Uuid,
        reference_id: Option<&str>,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Consent);
        sqlx::query_as::<_, ConsentRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1 AND {}=$2 AND {} IS NOT DISTINCT FROM $3 \
             ORDER BY {} DESC, \"id\" LIMIT 1",
            model.projection(CONSENT_FIELDS),
            model.table(),
            model.column("clientId"),
            model.column("userId"),
            model.column("referenceId"),
            model.column("updatedAt")
        ))
        .bind(client_id)
        .bind(user_id)
        .bind(reference_id)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn list_oauth_consents(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthProviderConsent>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Consent);
        sqlx::query_as::<_, ConsentRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1 ORDER BY {}, \"id\"",
            model.projection(CONSENT_FIELDS),
            model.table(),
            model.column("userId"),
            model.column("createdAt")
        ))
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(storage_error)
    }

    async fn upsert_oauth_consent(
        &self,
        consent: OAuthProviderConsent,
    ) -> Result<OAuthProviderConsent, AuthError> {
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(
                serde_json::json!([&consent.client_id, consent.user_id, &consent.reference_id])
                    .to_string(),
            )
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let model = self.schema.model(OAuthProviderModel::Consent);
        let existing_id = sqlx::query_scalar::<_, Uuid>(&format!(
            "SELECT \"id\" FROM {} WHERE {}=$1 AND {} IS NOT DISTINCT FROM $2 \
             AND {} IS NOT DISTINCT FROM $3 ORDER BY {} DESC, \"id\" LIMIT 1 FOR UPDATE",
            model.table(),
            model.column("clientId"),
            model.column("userId"),
            model.column("referenceId"),
            model.column("updatedAt")
        ))
        .bind(&consent.client_id)
        .bind(consent.user_id)
        .bind(&consent.reference_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(storage_error)?;

        let stored = if let Some(id) = existing_id {
            sqlx::query_as::<_, ConsentRow>(&format!(
                "UPDATE {} SET {}=$2, {}=$3, {}=$4, {}=$5, {}=$6 WHERE \"id\"=$1 RETURNING {}",
                model.table(),
                model.column("resources"),
                model.column("requestedUserInfoClaims"),
                model.column("scopes"),
                model.column("createdAt"),
                model.column("updatedAt"),
                model.projection(CONSENT_FIELDS)
            ))
            .bind(id)
            .bind(&consent.resources)
            .bind(&consent.requested_user_info_claims)
            .bind(&consent.scopes)
            .bind(consent.created_at)
            .bind(consent.updated_at)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?
        } else {
            sqlx::query_as::<_, ConsentRow>(&format!(
                "INSERT INTO {} ({}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING {}",
                model.table(),
                model.columns(CONSENT_FIELDS),
                model.projection(CONSENT_FIELDS)
            ))
            .bind(consent.id)
            .bind(&consent.client_id)
            .bind(consent.user_id)
            .bind(&consent.reference_id)
            .bind(&consent.resources)
            .bind(&consent.requested_user_info_claims)
            .bind(&consent.scopes)
            .bind(consent.created_at)
            .bind(consent.updated_at)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(stored.into())
    }

    async fn delete_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Consent);
        sqlx::query_as::<_, ConsentRow>(&format!(
            "DELETE FROM {} WHERE \"id\"=$1 RETURNING {}",
            model.table(),
            model.projection(CONSENT_FIELDS)
        ))
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }
}
