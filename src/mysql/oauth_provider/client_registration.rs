use super::{codec, eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthClientRegistrationMode, OAuthClientRegistrationOutcome,
    OAuthClientRegistrationWrite, OAuthProviderClient, OAuthProviderClientResource,
    PreparedDatabaseId,
    mysql::{MySqlStore, query::execute, schema::MySqlSchema},
};
use chrono::Utc;
use serde_json::{Map, Value, json};
use sqlx::{MySql, Transaction};

pub(super) async fn persist(
    store: &MySqlStore,
    client_id: &dyn DatabaseIdSupplier,
    link_id: &dyn DatabaseIdSupplier,
    mut write: OAuthClientRegistrationWrite,
) -> Result<OAuthClientRegistrationOutcome, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(super::storage)?;
    if let Some(resource) = missing_resource(&mut transaction, schema, &write.resource_ids).await? {
        return Ok(OAuthClientRegistrationOutcome::ResourceNotFound(resource));
    }
    let existing = existing_client(&mut transaction, schema, &write.client.client_id).await?;
    let outcome = write_client(
        store,
        &mut transaction,
        schema,
        client_id,
        &mut write,
        existing,
    )
    .await?;
    if is_terminal(&outcome) {
        return Ok(outcome);
    }
    link_resources(store, &mut transaction, schema, link_id, &write).await?;
    transaction.commit().await.map_err(super::storage)?;
    Ok(outcome)
}

async fn missing_resource(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    resources: &[String],
) -> Result<Option<String>, AuthError> {
    for resource in resources {
        if execute::find_one(
            transaction,
            schema,
            "oauthResource",
            &[eq("identifier", resource)],
            &[],
        )
        .await?
        .is_none()
        {
            return Ok(Some(resource.clone()));
        }
    }
    Ok(None)
}

async fn existing_client(
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    client_id: &str,
) -> Result<Option<OAuthProviderClient>, AuthError> {
    execute::find_one(
        transaction,
        schema,
        "oauthClient",
        &[eq("clientId", client_id)],
        &[],
    )
    .await?
    .map(codec::decode_client)
    .transpose()
}

async fn write_client(
    store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    id: &dyn DatabaseIdSupplier,
    write: &mut OAuthClientRegistrationWrite,
    existing: Option<OAuthProviderClient>,
) -> Result<OAuthClientRegistrationOutcome, AuthError> {
    match (&write.mode, existing) {
        (OAuthClientRegistrationMode::Create, Some(_)) => {
            Ok(OAuthClientRegistrationOutcome::ClientIdTaken)
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, Some(existing))
            if existing.client_discovery_id.as_deref() != Some(discovery_id) =>
        {
            Ok(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged)
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, None)
            if write.client.client_discovery_id.as_deref() != Some(discovery_id) =>
        {
            Ok(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged)
        }
        (OAuthClientRegistrationMode::RefreshDiscovered { .. }, Some(existing)) => {
            write.client.id = existing.id.clone();
            let values = client_record(store, &write.client, None)?;
            execute::update_one(
                transaction,
                schema,
                "oauthClient",
                &[eq("id", &existing.id)],
                values,
            )
            .await?
            .ok_or_else(|| AuthError::Storage("OAuth client disappeared".into()))?;
            Ok(OAuthClientRegistrationOutcome::Updated(
                write.client.clone(),
            ))
        }
        (_, None) => {
            let values = client_record(store, &write.client, Some(id.prepare()?))?;
            write.client = codec::decode_client(
                execute::insert_required(transaction, schema, "oauthClient", values).await?,
            )?;
            Ok(OAuthClientRegistrationOutcome::Created(
                write.client.clone(),
            ))
        }
    }
}

async fn link_resources(
    store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &MySqlSchema,
    id: &dyn DatabaseIdSupplier,
    write: &OAuthClientRegistrationWrite,
) -> Result<(), AuthError> {
    for resource_id in &write.resource_ids {
        let filters = [
            eq("clientId", &write.client.client_id),
            eq("resourceId", resource_id),
        ];
        if execute::find_one(transaction, schema, "oauthClientResource", &filters, &[])
            .await?
            .is_some()
        {
            continue;
        }
        let link = OAuthProviderClientResource {
            id: String::new(),
            client_id: write.client.client_id.clone(),
            resource_id: resource_id.clone(),
            metadata: None,
            created_at: Some(Utc::now()),
        };
        let values = record(store, "oauthClientResource", &link, Some(id.prepare()?), [])?;
        execute::insert_required(transaction, schema, "oauthClientResource", values).await?;
    }
    Ok(())
}

fn is_terminal(outcome: &OAuthClientRegistrationOutcome) -> bool {
    matches!(
        outcome,
        OAuthClientRegistrationOutcome::ClientIdTaken
            | OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged
            | OAuthClientRegistrationOutcome::ResourceNotFound(_)
    )
}

pub(super) fn client_record(
    store: &MySqlStore,
    client: &OAuthProviderClient,
    id: Option<PreparedDatabaseId>,
) -> Result<Map<String, Value>, AuthError> {
    record(
        store,
        "oauthClient",
        client,
        id,
        [("clientSecret", json!(client.client_secret))],
    )
}
