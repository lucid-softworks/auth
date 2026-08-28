use super::{codec, eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthProviderConsent, OAuthProviderConsentStore,
    sqlite::{
        SqliteFilter, SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteStore,
        query::execute,
    },
};
use async_trait::async_trait;
use serde_json::json;

#[async_trait]
impl OAuthProviderConsentStore for SqliteStore {
    async fn find_oauth_consent(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        find(self, &[eq("id", id)]).await
    }

    async fn find_oauth_consent_for_grant(
        &self,
        client_id: &str,
        user_id: &str,
        reference_id: Option<&str>,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        find(
            self,
            &[
                eq("clientId", client_id),
                eq("userId", user_id),
                SqliteFilter::equal("referenceId", json!(reference_id)),
            ],
        )
        .await
    }

    async fn list_oauth_consents(
        &self,
        user_id: &str,
    ) -> Result<Vec<OAuthProviderConsent>, AuthError> {
        self.find_records(
            "oauthConsent",
            &[eq("userId", user_id)],
            &SqliteFindOptions {
                sort: Some(SqliteSort {
                    field: "createdAt".into(),
                    direction: SqliteSortDirection::Ascending,
                }),
                ..SqliteFindOptions::default()
            },
        )
        .await?
        .into_iter()
        .map(|row| codec::decode("oauthConsent", row))
        .collect()
    }

    async fn upsert_oauth_consent(
        &self,
        id: &dyn DatabaseIdSupplier,
        consent: OAuthProviderConsent,
    ) -> Result<OAuthProviderConsent, AuthError> {
        let schema = self.physical_schema()?;
        let filters = [
            eq("clientId", &consent.client_id),
            SqliteFilter::equal("userId", json!(consent.user_id)),
            SqliteFilter::equal("referenceId", json!(consent.reference_id)),
        ];
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        if let Some(existing) =
            execute::find_one(&mut transaction, schema, "oauthConsent", &filters, &[]).await?
        {
            let existing_id = existing
                .get("id")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| AuthError::Storage("invalid SQLite oauthConsent row: id".into()))?;
            let values = record(self, "oauthConsent", &consent, None, [])?;
            let updated = execute::update_one(
                &mut transaction,
                schema,
                "oauthConsent",
                &[eq("id", existing_id)],
                values,
            )
            .await?
            .ok_or_else(|| AuthError::Storage("OAuth consent disappeared".into()))?;
            transaction.commit().await.map_err(super::storage)?;
            return codec::decode("oauthConsent", updated);
        }
        let values = record(self, "oauthConsent", &consent, Some(id.prepare()?), [])?;
        let inserted = execute::insert(&mut transaction, schema, "oauthConsent", values).await?;
        transaction.commit().await.map_err(super::storage)?;
        codec::decode("oauthConsent", inserted)
    }

    async fn delete_oauth_consent(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        self.consume_record("oauthConsent", &[eq("id", id)])
            .await?
            .map(|row| codec::decode("oauthConsent", row))
            .transpose()
    }
}

async fn find(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<Option<OAuthProviderConsent>, AuthError> {
    store
        .find_record("oauthConsent", filters, &[])
        .await?
        .map(|row| codec::decode("oauthConsent", row))
        .transpose()
}
