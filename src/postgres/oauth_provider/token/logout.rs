use super::super::super::storage_error;
use super::super::PostgresOAuthProviderStore;
use crate::{
    AuthError,
    oauth_provider::{OAuthSessionLogoutPlan, OAuthTokenRevocationCount},
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::oauth_provider::schema::OAuthProviderModel;

type AccessPlanRow = (Uuid, String, Option<DateTime<Utc>>);
type RefreshPlanRow = (Uuid, String, Option<DateTime<Utc>>, Vec<String>);

pub(super) async fn prepare(
    store: &PostgresOAuthProviderStore,
    session_id: Uuid,
) -> Result<OAuthSessionLogoutPlan, AuthError> {
    let access = store.schema.model(OAuthProviderModel::AccessToken);
    let access_rows = sqlx::query_as::<_, AccessPlanRow>(&format!(
        "SELECT \"id\", {}, {} FROM {} WHERE {}=$1",
        access.column("clientId"),
        access.column("revoked"),
        access.table(),
        access.column("sessionId")
    ))
    .bind(session_id)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?;
    let refresh = store.schema.model(OAuthProviderModel::RefreshToken);
    let refresh_rows = sqlx::query_as::<_, RefreshPlanRow>(&format!(
        "SELECT \"id\", {}, {}, {} FROM {} WHERE {}=$1",
        refresh.column("clientId"),
        refresh.column("revoked"),
        refresh.column("scopes"),
        refresh.table(),
        refresh.column("sessionId")
    ))
    .bind(session_id)
    .fetch_all(store.pool())
    .await
    .map_err(storage_error)?;
    Ok(build_plan(access_rows, refresh_rows))
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
                (revoked.is_none() && !scopes.iter().any(|scope| scope == "offline_access"))
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
    let mut transaction = store.pool().begin().await.map_err(storage_error)?;
    let access = store.schema.model(OAuthProviderModel::AccessToken);
    let access_tokens = sqlx::query(&format!(
        "UPDATE {} SET {}=$2 WHERE \"id\"=ANY($1::UUID[]) AND {} IS NULL",
        access.table(),
        access.column("revoked"),
        access.column("revoked")
    ))
    .bind(&plan.access_token_ids)
    .bind(revoked_at)
    .execute(&mut *transaction)
    .await
    .map_err(storage_error)?
    .rows_affected() as usize;
    let refresh_tokens = revoke_refresh(store, &mut transaction, plan, revoked_at).await?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(OAuthTokenRevocationCount {
        access_tokens,
        refresh_tokens,
    })
}

async fn revoke_refresh(
    store: &PostgresOAuthProviderStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    plan: &OAuthSessionLogoutPlan,
    revoked_at: DateTime<Utc>,
) -> Result<usize, AuthError> {
    let refresh = store.schema.model(OAuthProviderModel::RefreshToken);
    sqlx::query(&format!(
        "UPDATE {} SET {}=$2 WHERE \"id\"=ANY($1::UUID[]) AND {} IS NULL",
        refresh.table(),
        refresh.column("revoked"),
        refresh.column("revoked")
    ))
    .bind(&plan.refresh_token_ids)
    .bind(revoked_at)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected() as usize)
    .map_err(storage_error)
}
