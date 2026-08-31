use super::{codec, eq, record};
use crate::{
    AuthError, DatabaseIdSupplier, OAuthProviderAccessToken, OAuthProviderRefreshToken,
    OAuthTokenIssuance, OAuthTokenRevocationCount, PreparedDatabaseId,
    mongodb::{MongoFilter, MongoFindOptions, MongoStore, query::execute, schema::MongoSchema},
};
use serde_json::{Map, Value, json};

pub(super) async fn validate(
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &MongoSchema,
    issuance: &OAuthTokenIssuance,
) -> Result<(), AuthError> {
    if let Some(refresh) = &issuance.refresh_token
        && exists(
            transaction,
            schema,
            "oauthRefreshToken",
            "token",
            &refresh.token,
        )
        .await?
    {
        return Err(AuthError::Storage(
            "OAuth refresh token identifier already exists".into(),
        ));
    }
    if let Some(access) = &issuance.access_token {
        if exists(
            transaction,
            schema,
            "oauthAccessToken",
            "token",
            &access.token,
        )
        .await?
        {
            return Err(AuthError::Storage(
                "OAuth access token identifier already exists".into(),
            ));
        }
        if let Some(refresh_id) = &access.refresh_id
            && issuance
                .refresh_token
                .as_ref()
                .is_none_or(|refresh| refresh.id != *refresh_id && !refresh_id.is_empty())
            && !exists(transaction, schema, "oauthRefreshToken", "id", refresh_id).await?
        {
            return Err(AuthError::Storage(
                "OAuth access token references an unknown refresh token".into(),
            ));
        }
    }
    Ok(())
}

async fn exists(
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &MongoSchema,
    model: &str,
    field: &str,
    value: &str,
) -> Result<bool, AuthError> {
    Ok(
        execute::find_one(transaction, schema, model, &[eq(field, value)], &[])
            .await?
            .is_some(),
    )
}

pub(super) async fn insert_issuance(
    store: &MongoStore,
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &MongoSchema,
    refresh_id: &dyn DatabaseIdSupplier,
    access_id: &dyn DatabaseIdSupplier,
    mut issuance: OAuthTokenIssuance,
) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
    let stored_refresh = if let Some(refresh) = issuance.refresh_token {
        let values = refresh_record(store, &refresh, refresh_id.prepare()?)?;
        Some(codec::decode_refresh(
            execute::insert_required(transaction, schema, "oauthRefreshToken", values).await?,
        )?)
    } else {
        None
    };
    if let Some(access) = issuance.access_token.as_mut()
        && access.refresh_id.is_some()
        && let Some(refresh) = &stored_refresh
    {
        access.refresh_id = Some(refresh.id.clone());
    }
    if let Some(access) = issuance.access_token {
        let values = access_record(store, &access, access_id.prepare()?)?;
        execute::insert_required(transaction, schema, "oauthAccessToken", values).await?;
    }
    Ok(stored_refresh)
}

pub(super) async fn delete_family(
    store: &MongoStore,
    filters: &[MongoFilter],
) -> Result<OAuthTokenRevocationCount, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.begin().await?;
    let refresh = execute::find_many(
        &mut transaction,
        schema,
        "oauthRefreshToken",
        filters,
        &MongoFindOptions::default(),
    )
    .await?;
    let ids = refresh
        .iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    let mut access = 0;
    for id in &ids {
        access += execute::delete_many(
            &mut transaction,
            schema,
            "oauthAccessToken",
            &[eq("refreshId", id)],
        )
        .await?;
    }
    let refresh_count =
        execute::delete_many(&mut transaction, schema, "oauthRefreshToken", filters).await?;
    transaction.commit().await.map_err(super::storage)?;
    Ok(counts(access, refresh_count))
}

fn refresh_record(
    store: &MongoStore,
    value: &OAuthProviderRefreshToken,
    id: PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    record(
        store,
        "oauthRefreshToken",
        value,
        Some(id),
        [
            ("token", json!(value.token)),
            (
                "rotationReplayResponse",
                json!(value.rotation_replay_response),
            ),
        ],
    )
}

fn access_record(
    store: &MongoStore,
    value: &OAuthProviderAccessToken,
    id: PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    record(
        store,
        "oauthAccessToken",
        value,
        Some(id),
        [("token", json!(value.token))],
    )
}

pub(super) fn counts(access: u64, refresh: u64) -> OAuthTokenRevocationCount {
    OAuthTokenRevocationCount {
        access_tokens: usize::try_from(access).unwrap_or(usize::MAX),
        refresh_tokens: usize::try_from(refresh).unwrap_or(usize::MAX),
    }
}

pub(super) async fn find_access(
    store: &MongoStore,
    filters: &[MongoFilter],
) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
    store
        .find_record("oauthAccessToken", filters, &[])
        .await?
        .map(codec::decode_access)
        .transpose()
}

pub(super) async fn find_refresh(
    store: &MongoStore,
    filters: &[MongoFilter],
) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
    store
        .find_record("oauthRefreshToken", filters, &[])
        .await?
        .map(codec::decode_refresh)
        .transpose()
}

pub(super) async fn list_access(
    store: &MongoStore,
    filters: &[MongoFilter],
) -> Result<Vec<OAuthProviderAccessToken>, AuthError> {
    store
        .find_records("oauthAccessToken", filters, &MongoFindOptions::default())
        .await?
        .into_iter()
        .map(codec::decode_access)
        .collect()
}

pub(super) async fn list_refresh(
    store: &MongoStore,
    filters: &[MongoFilter],
) -> Result<Vec<OAuthProviderRefreshToken>, AuthError> {
    store
        .find_records("oauthRefreshToken", filters, &MongoFindOptions::default())
        .await?
        .into_iter()
        .map(codec::decode_refresh)
        .collect()
}
