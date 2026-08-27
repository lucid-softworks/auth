use super::super::{
    super::{PostgresModel, rows::insert_query_prefix, storage_error},
    rows::{self, AccessRow, RefreshRow},
};
use crate::{
    AuthError, DatabaseIdSupplier,
    oauth_provider::{OAuthProviderAccessToken, OAuthProviderRefreshToken},
};
use serde_json::{Value, json};
use sqlx::PgConnection;

pub(super) async fn insert_refresh_token(
    connection: &mut PgConnection,
    id: &dyn DatabaseIdSupplier,
    token: &OAuthProviderRefreshToken,
    model: &PostgresModel<'_>,
) -> Result<OAuthProviderRefreshToken, AuthError> {
    let prepared_id = id.prepare()?;
    let writes = rows::insert_writes(
        model,
        token,
        &prepared_id,
        [
            ("token", Value::String(token.token.clone())),
            (
                "rotationReplayResponse",
                json!(token.rotation_replay_response),
            ),
        ],
    )?;
    let mut query = insert_query_prefix(model, writes);
    query
        .push(" RETURNING ")
        .push(rows::refresh_projection(model)?);
    query
        .build_query_as::<RefreshRow>()
        .fetch_one(connection)
        .await
        .map(Into::into)
        .map_err(storage_error)
}

pub(super) async fn insert_access_token(
    connection: &mut PgConnection,
    id: &dyn DatabaseIdSupplier,
    token: &OAuthProviderAccessToken,
    model: &PostgresModel<'_>,
) -> Result<OAuthProviderAccessToken, AuthError> {
    let prepared_id = id.prepare()?;
    let writes = rows::insert_writes(
        model,
        token,
        &prepared_id,
        [("token", Value::String(token.token.clone()))],
    )?;
    let mut query = insert_query_prefix(model, writes);
    query
        .push(" RETURNING ")
        .push(rows::access_projection(model)?);
    query
        .build_query_as::<AccessRow>()
        .fetch_one(connection)
        .await
        .map(Into::into)
        .map_err(storage_error)
}

pub(super) async fn reserve_issuance_token_values(
    connection: &mut PgConnection,
    refresh: Option<(&PostgresModel<'_>, &str)>,
    access: Option<(&PostgresModel<'_>, &str)>,
) -> Result<(), AuthError> {
    if let Some((model, token)) = refresh {
        reserve_token_value(connection, model, token).await?;
    }
    if let Some((model, token)) = access {
        reserve_token_value(connection, model, token).await?;
    }
    Ok(())
}

async fn reserve_token_value(
    connection: &mut PgConnection,
    model: &PostgresModel<'_>,
    token: &str,
) -> Result<(), AuthError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(token)
        .execute(&mut *connection)
        .await
        .map_err(storage_error)?;
    let mut query = sqlx::QueryBuilder::new("SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("token")?)
        .push(" = ")
        .push_bind(token.to_owned());
    if query
        .build_query_scalar::<i32>()
        .fetch_optional(connection)
        .await
        .map_err(storage_error)?
        .is_some()
    {
        return Err(AuthError::Storage(
            "OAuth token identifier already exists".into(),
        ));
    }
    Ok(())
}
