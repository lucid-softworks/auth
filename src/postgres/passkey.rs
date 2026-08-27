mod codec;

use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, PasskeyDeleteOutcome, StoredPasskey};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder};

use codec::{decode_passkey, passkey_writes};

impl PostgresStore {
    fn passkey_model(&self) -> Result<PostgresModel<'_>, AuthError> {
        self.physical_model("passkey")
    }
}

pub(super) async fn save(
    store: &PostgresStore,
    passkey: crate::store::DatabaseCreate<StoredPasskey>,
) -> Result<StoredPasskey, AuthError> {
    if find_by_credential_id(store, &passkey.record.credential_id)
        .await?
        .is_some()
    {
        return Err(AuthError::CredentialAlreadyRegistered);
    }
    let (passkey, id) = passkey.into_parts(store)?;
    let model = store.passkey_model()?;
    let writes = passkey_writes(&model, &passkey, &id)?;
    let mut query = super::rows::insert_query(&model, writes);
    query
        .build()
        .fetch_one(&store.pool)
        .await
        .map_err(|error| {
            if super::user::is_unique_violation(&error) {
                AuthError::CredentialAlreadyRegistered
            } else {
                storage_error(error)
            }
        })
        .and_then(|row| decode_passkey(&model, &row))
}

pub(super) async fn list_for_user(
    store: &PostgresStore,
    user_id: &str,
) -> Result<Vec<StoredPasskey>, AuthError> {
    let model = store.passkey_model()?;
    let mut query = select_query(&model);
    push_user_predicate(&mut query, &model, user_id)?;
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?);
    let rows = query
        .build()
        .fetch_all(&store.pool)
        .await
        .map_err(storage_error)?;
    rows.iter().map(|row| decode_passkey(&model, row)).collect()
}

pub(super) async fn find_by_credential_id(
    store: &PostgresStore,
    credential_id: &str,
) -> Result<Option<StoredPasskey>, AuthError> {
    find_by(store, "credentialID", json!(credential_id)).await
}

pub(super) async fn find_by_id(
    store: &PostgresStore,
    passkey_id: &str,
) -> Result<Option<StoredPasskey>, AuthError> {
    find_by(store, "id", json!(passkey_id)).await
}

pub(super) async fn compare_and_swap(
    store: &PostgresStore,
    passkey: StoredPasskey,
    expected_counter: u32,
) -> Result<bool, AuthError> {
    let model = store.passkey_model()?;
    let writes = model.encode_fields([
        ("name", optional_string(passkey.name)),
        ("publicKey", json!(passkey.public_key)),
        ("counter", json!(passkey.counter)),
        ("deviceType", json!(passkey.device_type)),
        ("backedUp", json!(passkey.backed_up)),
        ("transports", optional_string(passkey.transports)),
        ("aaguid", optional_string(passkey.aaguid)),
    ])?;
    let mut query = super::rows::update_query(&model, writes);
    query.push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut query, &model, "id", json!(passkey.id))?;
    query
        .push(" AND ")
        .push(model.quoted_column("counter")?)
        .push(" = ");
    model
        .encode("counter", json!(expected_counter))?
        .push_bind(&mut query);
    query
        .build()
        .execute(&store.pool)
        .await
        .map(|result| result.rows_affected() == 1)
        .map_err(storage_error)
}

pub(super) async fn rename(
    store: &PostgresStore,
    user_id: &str,
    passkey_id: &str,
    name: String,
) -> Result<Option<StoredPasskey>, AuthError> {
    let model = store.passkey_model()?;
    let writes = model.encode_fields([("name", json!(name))])?;
    let mut query = super::rows::update_query(&model, writes);
    query.push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut query, &model, "id", json!(passkey_id))?;
    query
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    model
        .encode("userId", json!(user_id))?
        .push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    decode_optional(&model, query, &store.pool).await
}

pub(super) async fn delete(
    store: &PostgresStore,
    user_id: &str,
    passkey_id: &str,
    minimum_remaining: usize,
) -> Result<PasskeyDeleteOutcome, AuthError> {
    let user_model = store.user_model()?;
    let model = store.passkey_model()?;
    let mut transaction = store.pool.begin().await.map_err(storage_error)?;
    let mut lock = QueryBuilder::<Postgres>::new("SELECT \"id\" FROM ");
    lock.push(user_model.quoted_table())
        .push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut lock, &user_model, "id", json!(user_id))?;
    lock.push(" FOR UPDATE");
    lock.build()
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

    let mut owned = QueryBuilder::<Postgres>::new("SELECT EXISTS(SELECT 1 FROM ");
    owned.push(model.quoted_table()).push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut owned, &model, "id", json!(passkey_id))?;
    push_user_predicate_suffix(&mut owned, &model, user_id)?;
    owned.push(")");
    if !owned
        .build_query_scalar::<bool>()
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?
    {
        return Ok(PasskeyDeleteOutcome::NotFound);
    }
    let mut count = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
    count.push(model.quoted_table());
    push_user_predicate(&mut count, &model, user_id)?;
    let count = count
        .build_query_scalar::<i64>()
        .fetch_one(&mut *transaction)
        .await
        .map_err(storage_error)?;
    if count <= i64::try_from(minimum_remaining).unwrap_or(i64::MAX) {
        return Ok(PasskeyDeleteOutcome::MinimumRequired);
    }
    let mut delete = QueryBuilder::<Postgres>::new("DELETE FROM ");
    delete.push(model.quoted_table()).push(" WHERE \"id\" = ");
    super::rows::push_model_value(&mut delete, &model, "id", json!(passkey_id))?;
    push_user_predicate_suffix(&mut delete, &model, user_id)?;
    delete
        .build()
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(PasskeyDeleteOutcome::Deleted {
        remaining: usize::try_from(count - 1).unwrap_or(usize::MAX),
    })
}

pub(super) async fn delete_for_user(store: &PostgresStore, user_id: &str) -> Result<(), AuthError> {
    let model = store.passkey_model()?;
    let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
    query.push(model.quoted_table());
    push_user_predicate(&mut query, &model, user_id)?;
    query
        .build()
        .execute(&store.pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

fn select_query(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

async fn find_by(
    store: &PostgresStore,
    logical: &str,
    value: serde_json::Value,
) -> Result<Option<StoredPasskey>, AuthError> {
    let model = store.passkey_model()?;
    let mut query = select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column(logical)?)
        .push(" = ");
    model.encode(logical, value)?.push_bind(&mut query);
    decode_optional(&model, query, &store.pool).await
}

async fn decode_optional(
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
    pool: &sqlx::PgPool,
) -> Result<Option<StoredPasskey>, AuthError> {
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| decode_passkey(model, row))
        .transpose()
}

fn push_user_predicate(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    user_id: &str,
) -> Result<(), AuthError> {
    query.push(" WHERE ");
    push_user_comparison(query, model, user_id)
}

fn push_user_predicate_suffix(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    user_id: &str,
) -> Result<(), AuthError> {
    query.push(" AND ");
    push_user_comparison(query, model, user_id)
}

fn push_user_comparison(
    query: &mut QueryBuilder<'static, Postgres>,
    model: &PostgresModel<'_>,
    user_id: &str,
) -> Result<(), AuthError> {
    query.push(model.quoted_column("userId")?).push(" = ");
    model.encode("userId", json!(user_id))?.push_bind(query);
    Ok(())
}

fn optional_string(value: Option<String>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, serde_json::Value::String)
}
