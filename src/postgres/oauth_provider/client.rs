use super::{
    super::storage_error,
    PostgresOAuthProviderStore,
    rows::{CLIENT_FIELDS, ClientRow, LINK_FIELDS},
};
use crate::{
    AuthError,
    oauth_provider::{
        OAuthClientRegistrationMode, OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite,
        OAuthProviderClient, OAuthProviderClientStore,
        schema::{OAuthProviderModel, ResolvedModel, ResolvedOAuthProviderSchema},
    },
};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgConnection;
use uuid::Uuid;

async fn insert_client(
    connection: &mut PgConnection,
    client: &OAuthProviderClient,
    model: &ResolvedModel,
) -> Result<OAuthProviderClient, AuthError> {
    sqlx::query_as::<_, ClientRow>(&format!(
        "INSERT INTO {} ({}) VALUES \
         ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,\
          $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37) \
         RETURNING {}",
        model.table(),
        model.columns(CLIENT_FIELDS),
        model.projection(CLIENT_FIELDS)
    ))
    .bind(client.id)
    .bind(&client.client_id)
    .bind(&client.client_secret)
    .bind(&client.client_discovery_id)
    .bind(client.disabled)
    .bind(client.skip_consent)
    .bind(client.enable_end_session)
    .bind(&client.subject_type)
    .bind(&client.scopes)
    .bind(&client.client_credentials_scopes)
    .bind(client.user_id)
    .bind(client.created_at)
    .bind(client.updated_at)
    .bind(client.expires_at)
    .bind(&client.name)
    .bind(&client.uri)
    .bind(&client.icon)
    .bind(&client.contacts)
    .bind(&client.tos)
    .bind(&client.policy)
    .bind(&client.software_id)
    .bind(&client.software_version)
    .bind(&client.software_statement)
    .bind(&client.redirect_uris)
    .bind(&client.post_logout_redirect_uris)
    .bind(&client.backchannel_logout_uri)
    .bind(client.backchannel_logout_session_required)
    .bind(&client.token_endpoint_auth_method)
    .bind(&client.application_type)
    .bind(&client.jwks)
    .bind(&client.jwks_uri)
    .bind(&client.grant_types)
    .bind(&client.response_types)
    .bind(client.require_pkce)
    .bind(client.dpop_bound_access_tokens)
    .bind(&client.reference_id)
    .bind(&client.metadata)
    .fetch_one(connection)
    .await
    .map(Into::into)
    .map_err(storage_error)
}

async fn update_client(
    connection: &mut PgConnection,
    client: &OAuthProviderClient,
    model: &ResolvedModel,
) -> Result<Option<OAuthProviderClient>, AuthError> {
    sqlx::query_as::<_, ClientRow>(&client_update_sql(model))
        .bind(client.id)
        .bind(&client.client_id)
        .bind(&client.client_secret)
        .bind(&client.client_discovery_id)
        .bind(client.disabled)
        .bind(client.skip_consent)
        .bind(client.enable_end_session)
        .bind(&client.subject_type)
        .bind(&client.scopes)
        .bind(&client.client_credentials_scopes)
        .bind(client.user_id)
        .bind(client.created_at)
        .bind(client.updated_at)
        .bind(client.expires_at)
        .bind(&client.name)
        .bind(&client.uri)
        .bind(&client.icon)
        .bind(&client.contacts)
        .bind(&client.tos)
        .bind(&client.policy)
        .bind(&client.software_id)
        .bind(&client.software_version)
        .bind(&client.software_statement)
        .bind(&client.redirect_uris)
        .bind(&client.post_logout_redirect_uris)
        .bind(&client.backchannel_logout_uri)
        .bind(client.backchannel_logout_session_required)
        .bind(&client.token_endpoint_auth_method)
        .bind(&client.application_type)
        .bind(&client.jwks)
        .bind(&client.jwks_uri)
        .bind(&client.grant_types)
        .bind(&client.response_types)
        .bind(client.require_pkce)
        .bind(client.dpop_bound_access_tokens)
        .bind(&client.reference_id)
        .bind(&client.metadata)
        .fetch_optional(connection)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
}

fn client_update_sql(model: &ResolvedModel) -> String {
    let assignments = CLIENT_FIELDS
        .iter()
        .skip(2)
        .enumerate()
        .map(|(offset, (logical, _))| format!("{}=${}", model.column(logical), offset + 3))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "UPDATE {} SET {assignments} WHERE \"id\"=$1 AND {}=$2 RETURNING {}",
        model.table(),
        model.column("clientId"),
        model.projection(CLIENT_FIELDS)
    )
}

async fn lock_registration(
    connection: &mut PgConnection,
    client_id: &str,
    resource_ids: &[String],
    schema: &ResolvedOAuthProviderSchema,
) -> Result<Option<String>, AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(client_id)
        .execute(&mut *connection)
        .await
        .map_err(storage_error)?;
    let resource = schema.model(OAuthProviderModel::Resource);
    sqlx::query_scalar::<_, String>(&format!(
        "SELECT requested FROM unnest($1::TEXT[]) AS requested LEFT JOIN {} resource \
         ON resource.{}=requested WHERE resource.{} IS NULL LIMIT 1",
        resource.table(),
        resource.column("identifier"),
        resource.column("identifier")
    ))
    .bind(resource_ids)
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
    schema: &ResolvedOAuthProviderSchema,
) -> Result<RegistrationWrite, AuthError> {
    let model = schema.model(OAuthProviderModel::Client);
    let existing = sqlx::query_as::<_, ClientRow>(&format!(
        "SELECT {} FROM {} WHERE {}=$1 FOR UPDATE",
        model.projection(CLIENT_FIELDS),
        model.table(),
        model.column("clientId")
    ))
    .bind(&write.client.client_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(storage_error)?
    .map(OAuthProviderClient::from);
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
    schema: &ResolvedOAuthProviderSchema,
) -> Result<(), AuthError> {
    let model = schema.model(OAuthProviderModel::ClientResource);
    for resource_id in resource_ids {
        sqlx::query(&format!(
            "INSERT INTO {} ({}) VALUES ($1,$2,$3,NULL,$4) ON CONFLICT ({}, {}) DO NOTHING",
            model.table(),
            model.columns(LINK_FIELDS),
            model.column("clientId"),
            model.column("resourceId")
        ))
        .bind(Uuid::new_v4())
        .bind(client_id)
        .bind(resource_id)
        .bind(Utc::now())
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
        let model = self.schema.model(OAuthProviderModel::Client);
        sqlx::query_as::<_, ClientRow>(&format!(
            "SELECT {} FROM {} WHERE {}=$1",
            model.projection(CLIENT_FIELDS),
            model.table(),
            model.column("clientId")
        ))
        .bind(client_id)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn list_oauth_clients(
        &self,
        user_id: Option<Uuid>,
        reference_id: Option<&str>,
    ) -> Result<Vec<OAuthProviderClient>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Client);
        sqlx::query_as::<_, ClientRow>(&format!(
            "SELECT {} FROM {} WHERE ($1::UUID IS NULL AND $2::TEXT IS NULL) OR {}=$1 OR {}=$2 \
             ORDER BY {} NULLS FIRST, {}",
            model.projection(CLIENT_FIELDS),
            model.table(),
            model.column("userId"),
            model.column("referenceId"),
            model.column("createdAt"),
            model.column("clientId")
        ))
        .bind(user_id)
        .bind(reference_id)
        .fetch_all(self.pool())
        .await
        .map(|rows| rows.into_iter().map(Into::into).collect())
        .map_err(storage_error)
    }

    async fn persist_oauth_client_registration(
        &self,
        mut write: OAuthClientRegistrationWrite,
    ) -> Result<OAuthClientRegistrationOutcome, AuthError> {
        let mut resource_ids = std::mem::take(&mut write.resource_ids);
        resource_ids.sort_unstable();
        resource_ids.dedup();

        let mut transaction = self.pool().begin().await.map_err(storage_error)?;
        if let Some(identifier) = lock_registration(
            &mut transaction,
            &write.client.client_id,
            &resource_ids,
            &self.schema,
        )
        .await?
        {
            return Ok(OAuthClientRegistrationOutcome::ResourceNotFound(identifier));
        }
        let (stored, updated) =
            match write_registered_client(&mut transaction, &write, &self.schema).await? {
                RegistrationWrite::Stored { client, updated } => (client, updated),
                RegistrationWrite::Rejected(outcome) => return Ok(outcome),
            };
        link_registration_resources(
            &mut transaction,
            &stored.client_id,
            resource_ids,
            &self.schema,
        )
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
        let mut connection = self.pool().acquire().await.map_err(storage_error)?;
        update_client(
            &mut connection,
            &client,
            self.schema.model(OAuthProviderModel::Client),
        )
        .await
    }

    async fn delete_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let model = self.schema.model(OAuthProviderModel::Client);
        sqlx::query_as::<_, ClientRow>(&format!(
            "DELETE FROM {} WHERE {}=$1 RETURNING {}",
            model.table(),
            model.column("clientId"),
            model.projection(CLIENT_FIELDS)
        ))
        .bind(client_id)
        .fetch_optional(self.pool())
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }
}
