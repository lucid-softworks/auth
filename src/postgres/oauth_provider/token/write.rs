use super::super::{
    super::{PostgresModel, rows::insert_query_prefix, storage_error},
    rows::{self, ACCESS_FIELDS, AccessRow, REFRESH_FIELDS, RefreshRow},
};
use crate::{
    AuthError,
    oauth_provider::{OAuthProviderAccessToken, OAuthProviderRefreshToken},
};
use serde_json::{Value, json};
use sqlx::PgConnection;

pub(super) async fn insert_refresh_token(
    connection: &mut PgConnection,
    token: &OAuthProviderRefreshToken,
    model: &PostgresModel<'_>,
) -> Result<OAuthProviderRefreshToken, AuthError> {
    let writes = rows::writes(
        model,
        token,
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
        .push(model.projection_as(REFRESH_FIELDS)?);
    query
        .build_query_as::<RefreshRow>()
        .fetch_one(connection)
        .await
        .map(Into::into)
        .map_err(storage_error)
}

pub(super) async fn insert_access_token(
    connection: &mut PgConnection,
    token: &OAuthProviderAccessToken,
    model: &PostgresModel<'_>,
) -> Result<OAuthProviderAccessToken, AuthError> {
    let writes = rows::writes(
        model,
        token,
        [("token", Value::String(token.token.clone()))],
    )?;
    let mut query = insert_query_prefix(model, writes);
    query
        .push(" RETURNING ")
        .push(model.projection_as(ACCESS_FIELDS)?);
    query
        .build_query_as::<AccessRow>()
        .fetch_one(connection)
        .await
        .map(Into::into)
        .map_err(storage_error)
}
