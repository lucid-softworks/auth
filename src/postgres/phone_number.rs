use super::{PostgresStore, UserRow, storage_error};
use crate::{
    AuthError, AuthUser,
    phone_number::{PhoneNumberStore, PhoneNumberWriteOutcome},
};
use async_trait::async_trait;
use uuid::Uuid;

const USER_COLUMNS: &str = "id, username, display_username, name, email, email_verified, image, \
    additional_fields, role, is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at";
const PHONE_NUMBER_INDEX: &str = "lucid_auth_users_phone_number_unique_idx";

#[async_trait]
impl PhoneNumberStore for PostgresStore {
    async fn find_user_by_phone_number(
        &self,
        phone_number: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        let query = format!(
            "SELECT {USER_COLUMNS} FROM lucid_auth_users \
             WHERE additional_fields ->> 'phoneNumber' = $1"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(phone_number)
            .fetch_optional(&self.pool)
            .await
            .map(|row| row.map(AuthUser::from))
            .map_err(storage_error)
    }

    async fn create_phone_number_user(
        &self,
        mut user: AuthUser,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        require_phone_number(&user)?;
        user.email = user.email.to_lowercase();
        let query = format!(
            "INSERT INTO lucid_auth_users \
             (id, username, display_username, name, email, email_verified, image, additional_fields, role, \
              is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             RETURNING {USER_COLUMNS}"
        );
        let result = sqlx::query_as::<_, UserRow>(&query)
            .bind(user.id)
            .bind(&user.username)
            .bind(&user.display_username)
            .bind(&user.name)
            .bind(&user.email)
            .bind(user.email_verified)
            .bind(&user.image)
            .bind(serde_json::Value::Object(user.additional_fields))
            .bind(&user.role)
            .bind(user.is_anonymous)
            .bind(user.banned)
            .bind(&user.ban_reason)
            .bind(user.ban_expires)
            .bind(user.created_at)
            .bind(user.updated_at)
            .fetch_one(&self.pool)
            .await;
        match result {
            Ok(row) => Ok(PhoneNumberWriteOutcome::Written(AuthUser::from(row))),
            Err(error) if is_phone_number_conflict(&error) => {
                Ok(PhoneNumberWriteOutcome::AlreadyExists)
            }
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|database| database.is_unique_violation()) =>
            {
                Err(AuthError::UserAlreadyExists)
            }
            Err(error) => Err(storage_error(error)),
        }
    }

    async fn update_user_phone_number(
        &self,
        user_id: Uuid,
        phone_number: Option<String>,
        verified: bool,
    ) -> Result<PhoneNumberWriteOutcome<AuthUser>, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET \
               additional_fields = CASE \
                 WHEN $2::text IS NULL THEN \
                   (additional_fields - 'phoneNumber') || \
                   jsonb_build_object('phoneNumberVerified', $3::boolean) \
                 ELSE additional_fields || jsonb_build_object( \
                   'phoneNumber', $2::text, 'phoneNumberVerified', $3::boolean \
                 ) \
               END, \
               updated_at = NOW() \
             WHERE id = $1 \
             RETURNING {USER_COLUMNS}"
        );
        let result = sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(phone_number)
            .bind(verified)
            .fetch_optional(&self.pool)
            .await;
        match result {
            Ok(Some(row)) => Ok(PhoneNumberWriteOutcome::Written(AuthUser::from(row))),
            Ok(None) => Ok(PhoneNumberWriteOutcome::NotFound),
            Err(error) if is_phone_number_conflict(&error) => {
                Ok(PhoneNumberWriteOutcome::AlreadyExists)
            }
            Err(error) => Err(storage_error(error)),
        }
    }
}

fn require_phone_number(user: &AuthUser) -> Result<(), AuthError> {
    user.additional_fields
        .get("phoneNumber")
        .and_then(serde_json::Value::as_str)
        .map(|_| ())
        .ok_or_else(|| AuthError::Storage("phone-number user requires a phone number".into()))
}

fn is_phone_number_conflict(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .filter(|database| database.is_unique_violation())
        .and_then(|database| database.constraint())
        == Some(PHONE_NUMBER_INDEX)
}
