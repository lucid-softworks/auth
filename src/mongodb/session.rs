use super::{MongoFilter, MongoFilterOperator, MongoStore, codec};
use crate::{AuthError, AuthSession, store::DatabaseCreate};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) async fn create(
    store: &MongoStore,
    session: DatabaseCreate<AuthSession>,
) -> Result<AuthSession, AuthError> {
    let (session, id) = session.into_parts(store)?;
    let record = codec::create_record(store, "session", &session, &id)?;
    codec::decode("session", store.insert_required_record("session", record).await?)
}

pub(super) async fn find_by_token(
    store: &MongoStore,
    token: &str,
) -> Result<Option<AuthSession>, AuthError> {
    find(store, "token", json!(token)).await
}

pub(super) async fn find_by_id(
    store: &MongoStore,
    id: &str,
) -> Result<Option<AuthSession>, AuthError> {
    find(store, "id", json!(id)).await
}

pub(super) async fn update_fields(
    store: &MongoStore,
    id: &str,
    mut fields: Map<String, Value>,
) -> Result<Option<AuthSession>, AuthError> {
    let model = store.physical_schema()?.model("session")?;
    fields.retain(|field, _| field != "id" && model.has_field(field));
    fields.insert("updatedAt".into(), json!(Utc::now()));
    update(store, &[eq("id", json!(id))], fields).await
}

pub(super) async fn refresh(
    store: &MongoStore,
    token: &str,
    expires_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<Option<AuthSession>, AuthError> {
    update(
        store,
        &[eq("token", json!(token))],
        Map::from_iter([
            ("expiresAt".into(), json!(expires_at)),
            ("updatedAt".into(), json!(updated_at)),
        ]),
    )
    .await
}

pub(super) async fn expire(
    store: &MongoStore,
    id: &str,
    expires_at: DateTime<Utc>,
) -> Result<(), AuthError> {
    update(
        store,
        &[eq("id", json!(id))],
        Map::from_iter([
            ("expiresAt".into(), json!(expires_at)),
            ("updatedAt".into(), json!(expires_at)),
        ]),
    )
    .await
    .map(|_| ())
}

pub(super) async fn delete_by(
    store: &MongoStore,
    field: &str,
    value: Value,
) -> Result<(), AuthError> {
    store.delete_records("session", &[eq(field, value)]).await?;
    Ok(())
}

pub(super) async fn delete_expired(
    store: &MongoStore,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let mut filter = eq("expiresAt", json!(now));
    filter.operator = MongoFilterOperator::Lt;
    store.delete_records("session", &[filter]).await?;
    Ok(())
}

async fn find(
    store: &MongoStore,
    field: &str,
    value: Value,
) -> Result<Option<AuthSession>, AuthError> {
    store
        .find_record("session", &[eq(field, value)], &[])
        .await?
        .map(|record| codec::decode("session", record))
        .transpose()
}

async fn update(
    store: &MongoStore,
    filters: &[MongoFilter],
    values: Map<String, Value>,
) -> Result<Option<AuthSession>, AuthError> {
    store
        .update_record("session", filters, values)
        .await?
        .map(|record| codec::decode("session", record))
        .transpose()
}

fn eq(field: &str, value: Value) -> MongoFilter {
    MongoFilter::equal(field, value)
}
