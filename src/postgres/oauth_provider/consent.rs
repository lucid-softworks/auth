use super::{
    super::{
        PostgresModel,
        rows::{insert_query_prefix, update_query},
        storage_error,
    },
    PostgresOAuthProviderStore,
    rows::{self, ConsentRow},
};
use crate::{
    AuthError, DatabaseIdSupplier,
    oauth_provider::{OAuthProviderConsent, OAuthProviderConsentStore},
};
use async_trait::async_trait;
use serde_json::json;
use sqlx::QueryBuilder;

fn select_consents(
    model: &PostgresModel<'_>,
) -> Result<QueryBuilder<'static, sqlx::Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(rows::consent_projection(model)?)
        .push(" FROM ")
        .push(model.quoted_table());
    Ok(query)
}

#[async_trait]
impl OAuthProviderConsentStore for PostgresOAuthProviderStore {
    async fn find_oauth_consent(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        let model = self.model("oauthConsent")?;
        let mut query = select_consents(&model)?;
        query.push(" WHERE \"id\" = ");
        model.encode("id", json!(id))?.push_bind(&mut query);
        fetch_optional(query, self.pool()).await
    }

    async fn find_oauth_consent_for_grant(
        &self,
        client_id: &str,
        user_id: &str,
        reference_id: Option<&str>,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        let model = self.model("oauthConsent")?;
        let mut query = select_consents(&model)?;
        query
            .push(" WHERE ")
            .push(model.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned())
            .push(" AND ")
            .push(model.quoted_column("userId")?)
            .push(" = ");
        model
            .encode("userId", serde_json::json!(user_id))?
            .push_bind(&mut query);
        query
            .push(" AND ")
            .push(model.quoted_column("referenceId")?)
            .push(" IS NOT DISTINCT FROM ")
            .push_bind(reference_id.map(str::to_owned))
            .push(" ORDER BY ")
            .push(model.quoted_column("updatedAt")?)
            .push(" DESC, \"id\" LIMIT 1");
        fetch_optional(query, self.pool()).await
    }

    async fn list_oauth_consents(
        &self,
        user_id: &str,
    ) -> Result<Vec<OAuthProviderConsent>, AuthError> {
        let model = self.model("oauthConsent")?;
        let mut query = select_consents(&model)?;
        query
            .push(" WHERE ")
            .push(model.quoted_column("userId")?)
            .push(" = ");
        model
            .encode("userId", serde_json::json!(user_id))?
            .push_bind(&mut query);
        query
            .push(" ORDER BY ")
            .push(model.quoted_column("createdAt")?)
            .push(", \"id\"");
        query
            .build_query_as::<ConsentRow>()
            .fetch_all(self.pool())
            .await
            .map(|rows| rows.into_iter().map(Into::into).collect())
            .map_err(storage_error)
    }

    async fn upsert_oauth_consent(
        &self,
        id: &dyn DatabaseIdSupplier,
        consent: OAuthProviderConsent,
    ) -> Result<OAuthProviderConsent, AuthError> {
        let model = self.model("oauthConsent")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(
                serde_json::json!([&consent.client_id, consent.user_id, &consent.reference_id])
                    .to_string(),
            )
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let existing_id = find_existing_id(&mut transaction, &model, &consent).await?;
        let mut query = if let Some(existing_id) = existing_id {
            let writes = rows::writes(&model, &consent, [])?;
            let writes = writes
                .into_iter()
                .filter(|write| {
                    matches!(
                        write.logical(),
                        "resources"
                            | "requestedUserInfoClaims"
                            | "scopes"
                            | "createdAt"
                            | "updatedAt"
                    )
                })
                .collect();
            let mut query = update_query(&model, writes);
            query.push(" WHERE \"id\" = ");
            model
                .encode("id", json!(existing_id))?
                .push_bind(&mut query);
            query
        } else {
            let prepared_id = id.prepare()?;
            insert_query_prefix(
                &model,
                rows::insert_writes(&model, &consent, &prepared_id, [])?,
            )
        };
        query
            .push(" RETURNING ")
            .push(rows::consent_projection(&model)?);
        let stored = query
            .build_query_as::<ConsentRow>()
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(stored.into())
    }

    async fn delete_oauth_consent(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        let model = self.model("oauthConsent")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query.push(model.quoted_table()).push(" WHERE \"id\" = ");
        model.encode("id", json!(id))?.push_bind(&mut query);
        query
            .push(" RETURNING ")
            .push(rows::consent_projection(&model)?);
        fetch_optional(query, self.pool()).await
    }
}

async fn find_existing_id(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    consent: &OAuthProviderConsent,
) -> Result<Option<String>, AuthError> {
    let mut query = QueryBuilder::new("SELECT \"id\"::TEXT FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("clientId")?)
        .push(" = ")
        .push_bind(consent.client_id.clone())
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" IS NOT DISTINCT FROM ");
    model
        .encode("userId", json!(consent.user_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("referenceId")?)
        .push(" IS NOT DISTINCT FROM ")
        .push_bind(consent.reference_id.clone())
        .push(" ORDER BY ")
        .push(model.quoted_column("updatedAt")?)
        .push(" DESC, \"id\" LIMIT 1 FOR UPDATE");
    query
        .build_query_scalar::<String>()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)
}

async fn fetch_optional<'e, E>(
    mut query: QueryBuilder<'static, sqlx::Postgres>,
    executor: E,
) -> Result<Option<OAuthProviderConsent>, AuthError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    query
        .build_query_as::<ConsentRow>()
        .fetch_optional(executor)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
}
