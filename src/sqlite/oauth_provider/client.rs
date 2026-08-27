use super::{codec, eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthClientRegistrationMode, OAuthClientRegistrationOutcome,
    OAuthClientRegistrationWrite, OAuthProviderClient, OAuthProviderClientResource,
    OAuthProviderClientStore,
    sqlite::{SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteStore, query::execute},
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;

#[async_trait]
impl OAuthProviderClientStore for SqliteStore {
    async fn find_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        find(self, client_id).await
    }

    async fn list_oauth_clients(
        &self,
        user_id: Option<&str>,
        reference_id: Option<&str>,
    ) -> Result<Vec<OAuthProviderClient>, AuthError> {
        let clients = self
            .find_records(
                "oauthClient",
                &[],
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
            .map(codec::decode_client)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(clients
            .into_iter()
            .filter(|client| {
                user_id.is_some_and(|id| client.user_id.as_deref() == Some(id))
                    || reference_id.is_some_and(|id| client.reference_id.as_deref() == Some(id))
                    || user_id.is_none() && reference_id.is_none()
            })
            .collect())
    }

    async fn persist_oauth_client_registration(
        &self,
        client_id: &dyn DatabaseIdSupplier,
        link_id: &dyn DatabaseIdSupplier,
        write: OAuthClientRegistrationWrite,
    ) -> Result<OAuthClientRegistrationOutcome, AuthError> {
        persist(self, client_id, link_id, write).await
    }

    async fn update_oauth_client(
        &self,
        client: OAuthProviderClient,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let values = client_record(self, &client, None)?;
        self.update_record(
            "oauthClient",
            &[eq("id", &client.id), eq("clientId", &client.client_id)],
            values,
        )
        .await?
        .map(codec::decode_client)
        .transpose()
    }

    async fn delete_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(super::storage)?;
        for model in ["oauthAccessToken", "oauthRefreshToken", "oauthConsent"] {
            if execute::count(
                &mut transaction,
                schema,
                model,
                &[eq("clientId", client_id)],
            )
            .await?
                > 0
            {
                transaction.rollback().await.map_err(super::storage)?;
                return Err(AuthError::Storage(
                    "OAuth client is still referenced by grants or tokens".into(),
                ));
            }
        }
        execute::delete_many(
            &mut transaction,
            schema,
            "oauthClientResource",
            &[eq("clientId", client_id)],
        )
        .await?;
        let deleted = execute::consume_one(
            &mut transaction,
            schema,
            "oauthClient",
            &[eq("clientId", client_id)],
        )
        .await?
        .map(codec::decode_client)
        .transpose()?;
        transaction.commit().await.map_err(super::storage)?;
        Ok(deleted)
    }
}

async fn persist(
    store: &SqliteStore,
    client_id: &dyn DatabaseIdSupplier,
    link_id: &dyn DatabaseIdSupplier,
    mut write: OAuthClientRegistrationWrite,
) -> Result<OAuthClientRegistrationOutcome, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(super::storage)?;
    for resource in &write.resource_ids {
        if execute::find_one(
            &mut transaction,
            schema,
            "oauthResource",
            &[eq("identifier", resource)],
            &[],
        )
        .await?
        .is_none()
        {
            transaction.rollback().await.map_err(super::storage)?;
            return Ok(OAuthClientRegistrationOutcome::ResourceNotFound(
                resource.clone(),
            ));
        }
    }
    let existing = execute::find_one(
        &mut transaction,
        schema,
        "oauthClient",
        &[eq("clientId", &write.client.client_id)],
        &[],
    )
    .await?
    .map(codec::decode_client)
    .transpose()?;
    let outcome = match (&write.mode, existing.as_ref()) {
        (OAuthClientRegistrationMode::Create, Some(_)) => {
            return Ok(OAuthClientRegistrationOutcome::ClientIdTaken);
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, Some(existing))
            if existing.client_discovery_id.as_deref() != Some(discovery_id) =>
        {
            return Ok(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged);
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, None)
            if write.client.client_discovery_id.as_deref() != Some(discovery_id) =>
        {
            return Ok(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged);
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { .. }, Some(existing)) => {
            write.client.id = existing.id.clone();
            let values = client_record(store, &write.client, None)?;
            execute::update_one(
                &mut transaction,
                schema,
                "oauthClient",
                &[eq("id", &existing.id)],
                values,
            )
            .await?
            .ok_or_else(|| AuthError::Storage("OAuth client disappeared".into()))?;
            OAuthClientRegistrationOutcome::Updated(write.client.clone())
        }
        (_, None) => {
            let values = client_record(store, &write.client, Some(client_id.prepare()?))?;
            write.client = codec::decode_client(
                execute::insert(&mut transaction, schema, "oauthClient", values).await?,
            )?;
            OAuthClientRegistrationOutcome::Created(write.client.clone())
        }
    };
    for resource_id in write.resource_ids {
        let filters = [
            eq("clientId", &write.client.client_id),
            eq("resourceId", &resource_id),
        ];
        if execute::find_one(
            &mut transaction,
            schema,
            "oauthClientResource",
            &filters,
            &[],
        )
        .await?
        .is_some()
        {
            continue;
        }
        let link = OAuthProviderClientResource {
            id: String::new(),
            client_id: write.client.client_id.clone(),
            resource_id,
            metadata: None,
            created_at: Some(Utc::now()),
        };
        let values = record(
            store,
            "oauthClientResource",
            &link,
            Some(link_id.prepare()?),
            [],
        )?;
        execute::insert(&mut transaction, schema, "oauthClientResource", values).await?;
    }
    transaction.commit().await.map_err(super::storage)?;
    Ok(outcome)
}

fn client_record(
    store: &SqliteStore,
    client: &OAuthProviderClient,
    id: Option<crate::PreparedDatabaseId>,
) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
    record(
        store,
        "oauthClient",
        client,
        id,
        [("clientSecret", json!(client.client_secret))],
    )
}
async fn find(
    store: &SqliteStore,
    client_id: &str,
) -> Result<Option<OAuthProviderClient>, AuthError> {
    store
        .find_record("oauthClient", &[eq("clientId", client_id)], &[])
        .await?
        .map(codec::decode_client)
        .transpose()
}
