mod codec;

use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, AuthSession, AuthUser};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub(super) use codec::{decode_session, session_writes};

impl PostgresStore {
    pub(super) fn session_model(&self) -> Result<PostgresModel<'_>, AuthError> {
        self.physical_model("session")
    }
}

pub(super) async fn create(store: &PostgresStore, session: AuthSession) -> Result<(), AuthError> {
    let model = store.session_model()?;
    let writes = session_writes(&model, &session)?;
    let mut query = super::rows::insert_query_prefix(&model, writes);
    query
        .build()
        .execute(&store.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn find(
    store: &PostgresStore,
    token: &str,
) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
    let model = store.session_model()?;
    let mut query = select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("token")?)
        .push(" = ")
        .push_bind(token.to_owned());
    let Some(session) = fetch_optional(&model, query, &store.pool).await? else {
        return Ok(None);
    };
    let user = super::user::load_by_id(store, session.user_id).await?;
    Ok(user.map(|user| (session, user)))
}

pub(super) async fn find_by_id(
    store: &PostgresStore,
    session_id: Uuid,
) -> Result<Option<AuthSession>, AuthError> {
    let model = store.session_model()?;
    let mut query = select_query(&model);
    query.push(" WHERE \"id\" = ").push_bind(session_id);
    fetch_optional(&model, query, &store.pool).await
}

pub(super) async fn update_fields(
    store: &PostgresStore,
    session_id: Uuid,
    fields: serde_json::Map<String, serde_json::Value>,
) -> Result<Option<AuthSession>, AuthError> {
    let model = store.session_model()?;
    let writes = model.encode_fields(
        fields
            .iter()
            .filter(|(logical, _)| model.has_field(logical))
            .map(|(logical, value)| (logical.as_str(), value.clone()))
            .chain(std::iter::once((
                "updatedAt",
                json!(Utc::now().to_rfc3339()),
            ))),
    )?;
    let mut query = super::rows::update_query(&model, writes);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(session_id)
        .push(" RETURNING ")
        .push(model.all_projection());
    fetch_optional(&model, query, &store.pool).await
}

pub(super) async fn refresh(
    store: &PostgresStore,
    token: &str,
    expires_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<Option<AuthSession>, AuthError> {
    let model = store.session_model()?;
    let writes = model.encode_fields([
        ("expiresAt", json!(expires_at.to_rfc3339())),
        ("updatedAt", json!(updated_at.to_rfc3339())),
    ])?;
    let mut query = super::rows::update_query(&model, writes);
    query
        .push(" WHERE ")
        .push(model.quoted_column("token")?)
        .push(" = ")
        .push_bind(token.to_owned())
        .push(" RETURNING ")
        .push(model.all_projection());
    fetch_optional(&model, query, &store.pool).await
}

pub(super) async fn expire(
    store: &PostgresStore,
    session_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<(), AuthError> {
    let model = store.session_model()?;
    let writes = model.encode_fields([
        ("expiresAt", json!(expires_at.to_rfc3339())),
        ("updatedAt", json!(expires_at.to_rfc3339())),
    ])?;
    let mut query = super::rows::update_query(&model, writes);
    query.push(" WHERE \"id\" = ").push_bind(session_id);
    query
        .build()
        .execute(&store.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn delete(store: &PostgresStore, token: &str) -> Result<(), AuthError> {
    delete_where(store, "token", json!(token)).await
}

pub(super) async fn delete_by_id(store: &PostgresStore, id: Uuid) -> Result<(), AuthError> {
    delete_where(store, "id", json!(id.to_string())).await
}

pub(super) async fn delete_for_user(store: &PostgresStore, user_id: Uuid) -> Result<(), AuthError> {
    delete_where(store, "userId", json!(user_id.to_string())).await
}

pub(super) async fn delete_expired(
    store: &PostgresStore,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let model = store.session_model()?;
    let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("expiresAt")?)
        .push(" < ");
    model
        .encode("expiresAt", json!(now.to_rfc3339()))?
        .push_bind(&mut query);
    query
        .build()
        .execute(&store.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) fn select_query(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

async fn fetch_optional(
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
    pool: &sqlx::PgPool,
) -> Result<Option<AuthSession>, AuthError> {
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| decode_session(model, row))
        .transpose()
}

async fn delete_where(
    store: &PostgresStore,
    logical: &str,
    value: serde_json::Value,
) -> Result<(), AuthError> {
    let model = store.session_model()?;
    let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(logical)?)
        .push(" = ");
    model.encode(logical, value)?.push_bind(&mut query);
    query
        .build()
        .execute(&store.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}
