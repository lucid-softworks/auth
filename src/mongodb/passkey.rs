use super::{MongoFilter, MongoFindOptions, MongoSort, MongoSortDirection, MongoStore, codec};
use crate::{AuthError, PasskeyDeleteOutcome, StoredPasskey, store::DatabaseCreate};
use serde_json::{Map, json};

pub(super) async fn save(
    store: &MongoStore,
    passkey: DatabaseCreate<StoredPasskey>,
) -> Result<StoredPasskey, AuthError> {
    let (passkey, id) = passkey.into_parts(store)?;
    let record = codec::create_record(store, "passkey", &passkey, &id)?;
    match store.insert_required_record("passkey", record).await {
        Ok(record) => codec::decode("passkey", record),
        Err(error) if crate::mongodb::error::is_unique_violation(&error) => {
            Err(AuthError::CredentialAlreadyRegistered)
        }
        Err(error) => Err(error),
    }
}

pub(super) async fn list(
    store: &MongoStore,
    user_id: &str,
) -> Result<Vec<StoredPasskey>, AuthError> {
    store
        .find_records(
            "passkey",
            &[eq("userId", user_id)],
            &MongoFindOptions {
                sort: Some(MongoSort {
                    field: "createdAt".into(),
                    direction: MongoSortDirection::Ascending,
                }),
                ..MongoFindOptions::default()
            },
        )
        .await?
        .into_iter()
        .map(|record| codec::decode("passkey", record))
        .collect()
}

pub(super) async fn find(
    store: &MongoStore,
    field: &str,
    value: &str,
) -> Result<Option<StoredPasskey>, AuthError> {
    store
        .find_record("passkey", &[eq(field, value)], &[])
        .await?
        .map(|record| codec::decode("passkey", record))
        .transpose()
}

pub(super) async fn compare_and_swap(
    store: &MongoStore,
    passkey: StoredPasskey,
    expected_counter: u32,
) -> Result<bool, AuthError> {
    let values = Map::from_iter([
        ("name".into(), json!(passkey.name)),
        ("publicKey".into(), json!(passkey.public_key)),
        ("counter".into(), json!(passkey.counter)),
        ("deviceType".into(), json!(passkey.device_type)),
        ("backedUp".into(), json!(passkey.backed_up)),
        ("transports".into(), json!(passkey.transports)),
        ("aaguid".into(), json!(passkey.aaguid)),
    ]);
    Ok(store
        .update_record(
            "passkey",
            &[
                eq("id", &passkey.id),
                MongoFilter::equal("counter", json!(expected_counter)),
            ],
            values,
        )
        .await?
        .is_some())
}

pub(super) async fn rename(
    store: &MongoStore,
    user_id: &str,
    passkey_id: &str,
    name: String,
) -> Result<Option<StoredPasskey>, AuthError> {
    store
        .update_record(
            "passkey",
            &[eq("id", passkey_id), eq("userId", user_id)],
            Map::from_iter([("name".into(), json!(name))]),
        )
        .await?
        .map(|record| codec::decode("passkey", record))
        .transpose()
}

pub(super) async fn delete(
    store: &MongoStore,
    user_id: &str,
    passkey_id: &str,
    minimum_remaining: usize,
) -> Result<PasskeyDeleteOutcome, AuthError> {
    let schema = store.physical_schema()?;
    let filters = [eq("userId", user_id)];
    let mut transaction = store.begin().await?;
    let exists = super::query::execute::find_one(
        &mut transaction,
        schema,
        "passkey",
        &[eq("id", passkey_id), eq("userId", user_id)],
        &[],
    )
    .await?
    .is_some();
    if !exists {
        transaction.rollback().await.map_err(storage)?;
        return Ok(PasskeyDeleteOutcome::NotFound);
    }
    let count = super::query::execute::count(&mut transaction, schema, "passkey", &filters).await?;
    if count <= u64::try_from(minimum_remaining).unwrap_or(u64::MAX) {
        transaction.rollback().await.map_err(storage)?;
        return Ok(PasskeyDeleteOutcome::MinimumRequired);
    }
    super::query::execute::delete_many(
        &mut transaction,
        schema,
        "passkey",
        &[eq("id", passkey_id), eq("userId", user_id)],
    )
    .await?;
    transaction.commit().await.map_err(storage)?;
    Ok(PasskeyDeleteOutcome::Deleted {
        remaining: usize::try_from(count - 1).unwrap_or(usize::MAX),
    })
}

pub(super) async fn delete_for_user(store: &MongoStore, user_id: &str) -> Result<(), AuthError> {
    store
        .delete_records("passkey", &[eq("userId", user_id)])
        .await?;
    Ok(())
}

fn eq(field: &str, value: &str) -> MongoFilter {
    MongoFilter::equal(field, json!(value))
}

fn storage(error: AuthError) -> AuthError {
    AuthError::Storage(error.to_string())
}
