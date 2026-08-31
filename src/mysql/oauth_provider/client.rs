use super::{client_registration, codec, eq};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite,
    OAuthProviderClient, OAuthProviderClientStore,
    mysql::{MySqlFindOptions, MySqlSort, MySqlSortDirection, MySqlStore, query::execute},
};
use async_trait::async_trait;

#[async_trait]
impl OAuthProviderClientStore for MySqlStore {
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
                &MySqlFindOptions {
                    sort: Some(MySqlSort {
                        field: "createdAt".into(),
                        direction: MySqlSortDirection::Ascending,
                    }),
                    ..MySqlFindOptions::default()
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
        client_registration::persist(self, client_id, link_id, write).await
    }

    async fn update_oauth_client(
        &self,
        client: OAuthProviderClient,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let values = client_registration::client_record(self, &client, None)?;
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

async fn find(
    store: &MySqlStore,
    client_id: &str,
) -> Result<Option<OAuthProviderClient>, AuthError> {
    store
        .find_record("oauthClient", &[eq("clientId", client_id)], &[])
        .await?
        .map(codec::decode_client)
        .transpose()
}
