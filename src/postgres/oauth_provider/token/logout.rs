use super::super::super::{PostgresModel, rows::update_query, storage_error};
use super::super::PostgresOAuthProviderStore;
use crate::{
    AuthError,
    oauth_provider::{OAuthSessionLogoutPlan, OAuthTokenRevocationCount},
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{QueryBuilder, types::Json};
use uuid::Uuid;

type AccessPlanRow = (Uuid, String, Option<DateTime<Utc>>);
type RefreshPlanRow = (Uuid, String, Option<DateTime<Utc>>, Json<Vec<String>>);

pub(super) async fn prepare(
    store: &PostgresOAuthProviderStore,
    session_id: Uuid,
) -> Result<OAuthSessionLogoutPlan, AuthError> {
    let access = store.model("oauthAccessToken")?;
    let access_rows = access_plan(store, &access, session_id).await?;
    let refresh = store.model("oauthRefreshToken")?;
    let refresh_rows = refresh_plan(store, &refresh, session_id).await?;
    Ok(build_plan(access_rows, refresh_rows))
}

async fn access_plan(
    store: &PostgresOAuthProviderStore,
    model: &PostgresModel<'_>,
    session_id: Uuid,
) -> Result<Vec<AccessPlanRow>, AuthError> {
    let mut query = QueryBuilder::new("SELECT \"id\", ");
    query
        .push(model.quoted_column("clientId")?)
        .push(", ")
        .push(model.quoted_column("revoked")?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("sessionId")?)
        .push(" = ")
        .push_bind(session_id);
    query
        .build_query_as::<AccessPlanRow>()
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)
}

async fn refresh_plan(
    store: &PostgresOAuthProviderStore,
    model: &PostgresModel<'_>,
    session_id: Uuid,
) -> Result<Vec<RefreshPlanRow>, AuthError> {
    let mut query = QueryBuilder::new("SELECT \"id\", ");
    query
        .push(model.quoted_column("clientId")?)
        .push(", ")
        .push(model.quoted_column("revoked")?)
        .push(", ")
        .push(model.quoted_column("scopes")?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("sessionId")?)
        .push(" = ")
        .push_bind(session_id);
    query
        .build_query_as::<RefreshPlanRow>()
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)
}

fn build_plan(access: Vec<AccessPlanRow>, refresh: Vec<RefreshPlanRow>) -> OAuthSessionLogoutPlan {
    let mut client_ids = access
        .iter()
        .map(|(_, client_id, _)| client_id.clone())
        .chain(refresh.iter().map(|(_, client_id, _, _)| client_id.clone()))
        .collect::<Vec<_>>();
    client_ids.sort();
    client_ids.dedup();
    OAuthSessionLogoutPlan {
        client_ids,
        access_token_ids: access
            .into_iter()
            .filter_map(|(id, _, revoked)| revoked.is_none().then_some(id))
            .collect(),
        refresh_token_ids: refresh
            .into_iter()
            .filter_map(|(id, _, revoked, scopes)| {
                (revoked.is_none() && !scopes.0.iter().any(|scope| scope == "offline_access"))
                    .then_some(id)
            })
            .collect(),
    }
}

pub(super) async fn apply(
    store: &PostgresOAuthProviderStore,
    plan: &OAuthSessionLogoutPlan,
    revoked_at: DateTime<Utc>,
) -> Result<OAuthTokenRevocationCount, AuthError> {
    let access = store.model("oauthAccessToken")?;
    let refresh = store.model("oauthRefreshToken")?;
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let access_tokens = revoke_ids(
        &mut transaction,
        &access,
        &plan.access_token_ids,
        revoked_at,
    )
    .await?;
    let refresh_tokens = revoke_ids(
        &mut transaction,
        &refresh,
        &plan.refresh_token_ids,
        revoked_at,
    )
    .await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OAuthTokenRevocationCount {
        access_tokens,
        refresh_tokens,
    })
}

async fn revoke_ids(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    ids: &[Uuid],
    revoked_at: DateTime<Utc>,
) -> Result<usize, AuthError> {
    let writes = model.encode_fields([("revoked", Value::String(revoked_at.to_rfc3339()))])?;
    let mut query = update_query(model, writes);
    query
        .push(" WHERE \"id\" = ANY(")
        .push_bind(ids.to_vec())
        .push("::UUID[]) AND ")
        .push(model.quoted_column("revoked")?)
        .push(" IS NULL");
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|result| result.rows_affected() as usize)
        .map_err(storage_error)
}
