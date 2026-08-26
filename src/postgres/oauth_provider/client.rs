use super::{
    super::{
        PostgresModel,
        rows::{insert_query_prefix, update_query},
        storage_error,
    },
    PostgresOAuthProviderStore,
    rows::{self, ClientRow},
};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthClientRegistrationMode, OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite,
        OAuthProviderClient, OAuthProviderClientResource, OAuthProviderClientStore,
    },
};
use async_trait::async_trait;
use chrono::Utc;
use serde_json::json;
use sqlx::{PgConnection, Postgres, QueryBuilder};
use uuid::Uuid;

fn decode(row: ClientRow) -> OAuthProviderClient {
    row.into()
}

async fn insert_client(
    connection: &mut PgConnection,
    client: &OAuthProviderClient,
    model: &PostgresModel<'_>,
) -> Result<OAuthProviderClient, AuthError> {
    let writes = rows::writes(
        model,
        client,
        [("clientSecret", serde_json::json!(client.client_secret))],
    )?;
    let mut query = insert_query_prefix(model, writes);
    query
        .push(" RETURNING ")
        .push(rows::client_projection(model)?);
    query
        .build_query_as::<ClientRow>()
        .fetch_one(connection)
        .await
        .map(decode)
        .map_err(storage_error)
}

async fn update_client(
    connection: &mut PgConnection,
    client: &OAuthProviderClient,
    model: &PostgresModel<'_>,
) -> Result<Option<OAuthProviderClient>, AuthError> {
    let writes = rows::writes(
        model,
        client,
        [("clientSecret", serde_json::json!(client.client_secret))],
    )?
    .into_iter()
    .filter(|write| !matches!(write.logical(), "id" | "clientId"))
    .collect();
    let mut query = update_query(model, writes);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(client.id)
        .push(" AND ")
        .push(model.quoted_column("clientId")?)
        .push(" = ")
        .push_bind(client.client_id.clone())
        .push(" RETURNING ")
        .push(rows::client_projection(model)?);
    query
        .build_query_as::<ClientRow>()
        .fetch_optional(connection)
        .await
        .map(|row| row.map(decode))
        .map_err(storage_error)
}

async fn lock_registration(
    connection: &mut PgConnection,
    client_id: &str,
    resource_ids: &[String],
    resource: &PostgresModel<'_>,
) -> Result<Option<String>, AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(client_id)
        .execute(&mut *connection)
        .await
        .map_err(storage_error)?;
    let mut query = QueryBuilder::new("SELECT requested FROM unnest(");
    query
        .push_bind(resource_ids.to_vec())
        .push("::TEXT[]) AS requested LEFT JOIN ")
        .push(resource.quoted_table())
        .push(" resource ON resource.")
        .push(resource.quoted_column("identifier")?)
        .push(" = requested WHERE resource.")
        .push(resource.quoted_column("identifier")?)
        .push(" IS NULL LIMIT 1");
    query
        .build_query_scalar::<String>()
        .fetch_optional(connection)
        .await
        .map_err(storage_error)
}

enum RegistrationWrite {
    Stored {
        client: OAuthProviderClient,
        updated: bool,
    },
    Rejected(OAuthClientRegistrationOutcome),
}

async fn write_registered_client(
    connection: &mut PgConnection,
    write: &OAuthClientRegistrationWrite,
    model: &PostgresModel<'_>,
) -> Result<RegistrationWrite, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(rows::client_projection(model)?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("clientId")?)
        .push(" = ")
        .push_bind(write.client.client_id.clone())
        .push(" FOR UPDATE");
    let existing = query
        .build_query_as::<ClientRow>()
        .fetch_optional(&mut *connection)
        .await
        .map_err(storage_error)?
        .map(decode);
    let rejected = |outcome| Ok(RegistrationWrite::Rejected(outcome));
    match (&write.mode, existing) {
        (OAuthClientRegistrationMode::Create, Some(_)) => {
            rejected(OAuthClientRegistrationOutcome::ClientIdTaken)
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, Some(current))
            if current.client_discovery_id.as_deref() != Some(discovery_id.as_str()) =>
        {
            rejected(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged)
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, None)
            if write.client.client_discovery_id.as_deref() != Some(discovery_id.as_str()) =>
        {
            rejected(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged)
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { .. }, Some(_)) => {
            let client = update_client(connection, &write.client, model)
                .await?
                .ok_or_else(|| {
                    AuthError::Storage("OAuth client disappeared while locked".into())
                })?;
            Ok(RegistrationWrite::Stored {
                client,
                updated: true,
            })
        }
        (_, None) => Ok(RegistrationWrite::Stored {
            client: insert_client(connection, &write.client, model).await?,
            updated: false,
        }),
    }
}

async fn link_registration_resources(
    connection: &mut PgConnection,
    client_id: &str,
    resource_ids: Vec<String>,
    model: &PostgresModel<'_>,
) -> Result<(), AuthError> {
    for resource_id in resource_ids {
        let link = OAuthProviderClientResource {
            id: Uuid::new_v4(),
            client_id: client_id.to_owned(),
            resource_id,
            metadata: None,
            created_at: Some(Utc::now()),
        };
        let writes = rows::writes(model, &link, [])?;
        let mut query = insert_query_prefix(model, writes);
        query
            .push(" ON CONFLICT (")
            .push(model.quoted_column("clientId")?)
            .push(", ")
            .push(model.quoted_column("resourceId")?)
            .push(") DO NOTHING");
        query
            .build()
            .execute(&mut *connection)
            .await
            .map_err(storage_error)?;
    }
    Ok(())
}

#[async_trait]
impl OAuthProviderClientStore for PostgresOAuthProviderStore {
    async fn find_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let model = self.model("oauthClient")?;
        let mut query = QueryBuilder::new("SELECT ");
        query
            .push(rows::client_projection(&model)?)
            .push(" FROM ")
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned());
        query
            .build_query_as::<ClientRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode))
            .map_err(storage_error)
    }

    async fn list_oauth_clients(
        &self,
        user_id: Option<&str>,
        reference_id: Option<&str>,
    ) -> Result<Vec<OAuthProviderClient>, AuthError> {
        let model = self.model("oauthClient")?;
        let mut query = QueryBuilder::new("SELECT ");
        query
            .push(rows::client_projection(&model)?)
            .push(" FROM ")
            .push(model.quoted_table());
        push_client_filter(&mut query, &model, user_id, reference_id)?;
        query
            .push(" ORDER BY ")
            .push(model.quoted_column("createdAt")?)
            .push(" NULLS FIRST, ")
            .push(model.quoted_column("clientId")?);
        query
            .build_query_as::<ClientRow>()
            .fetch_all(self.pool())
            .await
            .map(|rows| rows.into_iter().map(decode).collect())
            .map_err(storage_error)
    }

    async fn persist_oauth_client_registration(
        &self,
        mut write: OAuthClientRegistrationWrite,
    ) -> Result<OAuthClientRegistrationOutcome, AuthError> {
        let mut resource_ids = std::mem::take(&mut write.resource_ids);
        resource_ids.sort_unstable();
        resource_ids.dedup();
        let client = self.model("oauthClient")?;
        let resource = self.model("oauthResource")?;
        let link = self.model("oauthClientResource")?;
        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        if let Some(identifier) = lock_registration(
            &mut transaction,
            &write.client.client_id,
            &resource_ids,
            &resource,
        )
        .await?
        {
            return Ok(OAuthClientRegistrationOutcome::ResourceNotFound(identifier));
        }
        let (stored, updated) =
            match write_registered_client(&mut transaction, &write, &client).await? {
                RegistrationWrite::Stored { client, updated } => (client, updated),
                RegistrationWrite::Rejected(outcome) => return Ok(outcome),
            };
        link_registration_resources(&mut transaction, &stored.client_id, resource_ids, &link)
            .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(if updated {
            OAuthClientRegistrationOutcome::Updated(stored)
        } else {
            OAuthClientRegistrationOutcome::Created(stored)
        })
    }

    async fn update_oauth_client(
        &self,
        client: OAuthProviderClient,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let model = self.model("oauthClient")?;
        let mut connection = self.pool().acquire().await.map_err(storage_error)?;
        update_client(&mut connection, &client, &model).await
    }

    async fn delete_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let model = self.model("oauthClient")?;
        let mut query = QueryBuilder::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("clientId")?)
            .push(" = ")
            .push_bind(client_id.to_owned())
            .push(" RETURNING ")
            .push(rows::client_projection(&model)?);
        query
            .build_query_as::<ClientRow>()
            .fetch_optional(self.pool())
            .await
            .map(|row| row.map(decode))
            .map_err(storage_error)
    }
}

fn push_client_filter(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    user_id: Option<&str>,
    reference_id: Option<&str>,
) -> Result<(), AuthError> {
    let mut separator = " WHERE ";
    if let Some(user_id) = user_id {
        query
            .push(separator)
            .push(model.quoted_column("userId")?)
            .push(" = ");
        model.encode("userId", json!(user_id))?.push_bind(query);
        separator = " OR ";
    }
    if let Some(reference_id) = reference_id {
        query
            .push(separator)
            .push(model.quoted_column("referenceId")?)
            .push(" = ");
        model
            .encode("referenceId", json!(reference_id))?
            .push_bind(query);
    }
    Ok(())
}
