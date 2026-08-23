use super::{rows::PasskeyRow, storage_error};
use crate::{
    AuthError, PasskeyDeleteOutcome, StoredPasskey, passkey::public_key_from_credential_value,
};
use serde_json::Value;
use sqlx::PgPool;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

const FIELDS: &str = "id, user_id, name, credential_id, public_key, counter, device_type, \
    backed_up, transports, aaguid, credential, created_at, updated_at";

pub(super) async fn save(
    pool: &PgPool,
    passkey: StoredPasskey,
) -> Result<StoredPasskey, AuthError> {
    sqlx::query_as::<_, PasskeyRow>(&format!(
        "INSERT INTO lucid_auth_passkeys \
         ({FIELDS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         RETURNING {FIELDS}"
    ))
    .bind(passkey.id)
    .bind(passkey.user_id)
    .bind(&passkey.name)
    .bind(&passkey.credential_id)
    .bind(&passkey.public_key)
    .bind(i64::from(passkey.counter))
    .bind(&passkey.device_type)
    .bind(passkey.backed_up)
    .bind(&passkey.transports)
    .bind(&passkey.aaguid)
    .bind(&passkey.credential)
    .bind(passkey.created_at)
    .bind(passkey.updated_at)
    .fetch_one(pool)
    .await
    .map(StoredPasskey::from)
    .map_err(|error| {
        if error
            .as_database_error()
            .is_some_and(|database| database.is_unique_violation())
        {
            AuthError::CredentialAlreadyRegistered
        } else {
            storage_error(error)
        }
    })
}

pub(super) async fn list_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Vec<StoredPasskey>, AuthError> {
    sqlx::query_as::<_, PasskeyRow>(&format!(
        "SELECT {FIELDS} FROM lucid_auth_passkeys WHERE user_id = $1 ORDER BY created_at"
    ))
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(StoredPasskey::from).collect())
    .map_err(storage_error)
}

pub(super) async fn find_by_credential_id(
    pool: &PgPool,
    credential_id: &str,
) -> Result<Option<StoredPasskey>, AuthError> {
    sqlx::query_as::<_, PasskeyRow>(&format!(
        "SELECT {FIELDS} FROM lucid_auth_passkeys WHERE credential_id = $1"
    ))
    .bind(credential_id)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(StoredPasskey::from))
    .map_err(storage_error)
}

pub(super) async fn find_by_id(
    pool: &PgPool,
    passkey_id: Uuid,
) -> Result<Option<StoredPasskey>, AuthError> {
    sqlx::query_as::<_, PasskeyRow>(&format!(
        "SELECT {FIELDS} FROM lucid_auth_passkeys WHERE id = $1"
    ))
    .bind(passkey_id)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(StoredPasskey::from))
    .map_err(storage_error)
}

pub(super) async fn compare_and_swap(
    pool: &PgPool,
    passkey: StoredPasskey,
    expected_counter: u32,
) -> Result<bool, AuthError> {
    sqlx::query(
        "UPDATE lucid_auth_passkeys SET name = $2, public_key = $3, counter = $4, \
           device_type = $5, backed_up = $6, transports = $7, aaguid = $8, \
           credential = $9, updated_at = $10 WHERE id = $1 AND counter = $11",
    )
    .bind(passkey.id)
    .bind(&passkey.name)
    .bind(&passkey.public_key)
    .bind(i64::from(passkey.counter))
    .bind(&passkey.device_type)
    .bind(passkey.backed_up)
    .bind(&passkey.transports)
    .bind(&passkey.aaguid)
    .bind(&passkey.credential)
    .bind(passkey.updated_at)
    .bind(i64::from(expected_counter))
    .execute(pool)
    .await
    .map(|result| result.rows_affected() == 1)
    .map_err(storage_error)
}

pub(super) async fn rename(
    pool: &PgPool,
    user_id: Uuid,
    passkey_id: Uuid,
    name: String,
) -> Result<Option<StoredPasskey>, AuthError> {
    sqlx::query_as::<_, PasskeyRow>(&format!(
        "UPDATE lucid_auth_passkeys SET name = $3, updated_at = NOW() \
         WHERE id = $1 AND user_id = $2 RETURNING {FIELDS}"
    ))
    .bind(passkey_id)
    .bind(user_id)
    .bind(name)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(StoredPasskey::from))
    .map_err(storage_error)
}

pub(super) async fn delete(
    pool: &PgPool,
    user_id: Uuid,
    passkey_id: Uuid,
    minimum_remaining: usize,
) -> Result<PasskeyDeleteOutcome, AuthError> {
    let mut transaction = pool.begin().await.map_err(storage_error)?;
    sqlx::query("SELECT id FROM lucid_auth_users WHERE id = $1 FOR UPDATE")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    let owned = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM lucid_auth_passkeys WHERE id = $1 AND user_id = $2)",
    )
    .bind(passkey_id)
    .bind(user_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(storage_error)?;
    if !owned {
        return Ok(PasskeyDeleteOutcome::NotFound);
    }
    let count =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lucid_auth_passkeys WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
    if count <= i64::try_from(minimum_remaining).unwrap_or(i64::MAX) {
        return Ok(PasskeyDeleteOutcome::MinimumRequired);
    }
    sqlx::query("DELETE FROM lucid_auth_passkeys WHERE id = $1 AND user_id = $2")
        .bind(passkey_id)
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;
    transaction.commit().await.map_err(storage_error)?;
    Ok(PasskeyDeleteOutcome::Deleted {
        remaining: usize::try_from(count - 1).unwrap_or(usize::MAX),
    })
}

pub(super) async fn delete_for_user(pool: &PgPool, user_id: Uuid) -> Result<(), AuthError> {
    sqlx::query("DELETE FROM lucid_auth_passkeys WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn backfill_public_keys(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), AuthError> {
    let credentials = sqlx::query_as::<_, (Uuid, Value)>(
        "SELECT id, credential FROM lucid_auth_passkeys WHERE public_key = ''",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)?;
    for (id, credential) in credentials {
        let public_key = public_key_from_credential_value(&credential).map_err(|error| {
            AuthError::Storage(format!(
                "could not migrate passkey {id} public key: {error}"
            ))
        })?;
        sqlx::query("UPDATE lucid_auth_passkeys SET public_key = $1 WHERE id = $2")
            .bind(public_key)
            .bind(id)
            .execute(&mut **transaction)
            .await
            .map_err(storage_error)?;
    }
    Ok(())
}
