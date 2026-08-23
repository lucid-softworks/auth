use super::{PostgresStore, SessionRow, UserRow, storage_error};
use crate::{
    AccessStore, AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthSession, AuthUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

const USER_COLUMNS: &str = "id, username, display_username, name, email, email_verified, image, \
    additional_fields, role, is_anonymous, banned, ban_reason, ban_expires, created_at, updated_at";

#[async_trait]
impl AccessStore for PostgresStore {
    async fn list_users(&self, query: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        let mut sql =
            QueryBuilder::<Postgres>::new(format!("SELECT {USER_COLUMNS} FROM lucid_auth_users"));
        push_conditions(&mut sql, &query.conditions)?;
        sql.push(" ORDER BY ");
        push_sort_field(&mut sql, query.sort_by.as_deref().unwrap_or("createdAt"));
        sql.push(match query.sort_direction {
            AdminSortDirection::Asc => " ASC",
            AdminSortDirection::Desc => " DESC",
        });
        sql.push(" LIMIT ")
            .push_bind(query.limit as i64)
            .push(" OFFSET ")
            .push_bind(query.offset as i64);
        sql.build_query_as::<UserRow>()
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(AuthUser::from).collect())
            .map_err(storage_error)
    }

    async fn count_users(&self, conditions: &[AdminListCondition]) -> Result<i64, AuthError> {
        let mut sql = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM lucid_auth_users");
        push_conditions(&mut sql, conditions)?;
        sql.build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM lucid_auth_users WHERE role = $1")
            .bind(role)
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET role = $2, updated_at = NOW() WHERE id = $1 \
             RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(role)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        let query = format!(
            "UPDATE lucid_auth_users SET banned = $2, ban_reason = $3, ban_expires = $4, \
             updated_at = NOW() WHERE id = $1 RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(banned)
            .bind(reason)
            .bind(expires_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn admin_update_user(
        &self,
        user_id: Uuid,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        let mut user = super::user::load_by_id(&self.pool, user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if let Some(name) = update.name {
            user.name = name;
        }
        if let Some(email) = update.email {
            user.email = email;
        }
        if let Some(verified) = update.email_verified {
            user.email_verified = verified;
        }
        if let Some(image) = update.image {
            user.image = image;
        }
        if let Some(role) = update.role {
            user.role = role;
        }
        if let Some(banned) = update.banned {
            user.banned = banned;
        }
        if let Some(reason) = update.ban_reason {
            user.ban_reason = reason;
        }
        if let Some(expires) = update.ban_expires {
            user.ban_expires = expires;
        }
        user.additional_fields.extend(update.additional_fields);
        user.updated_at = Utc::now();
        let query = format!(
            "UPDATE lucid_auth_users SET name = $2, email = $3, email_verified = $4, image = $5, \
             additional_fields = $6, role = $7, banned = $8, ban_reason = $9, ban_expires = $10, updated_at = $11 \
             WHERE id = $1 RETURNING {USER_COLUMNS}"
        );
        sqlx::query_as::<_, UserRow>(&query)
            .bind(user_id)
            .bind(user.name)
            .bind(user.email)
            .bind(user.email_verified)
            .bind(user.image)
            .bind(serde_json::Value::Object(user.additional_fields))
            .bind(user.role)
            .bind(user.banned)
            .bind(user.ban_reason)
            .bind(user.ban_expires)
            .bind(user.updated_at)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| {
                if error
                    .as_database_error()
                    .is_some_and(|database| database.is_unique_violation())
                {
                    AuthError::UserAlreadyExistsEmail
                } else {
                    storage_error(error)
                }
            })?
            .map(AuthUser::from)
            .ok_or(AuthError::NotFound)
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let api_key_table_exists =
            sqlx::query_scalar::<_, bool>("SELECT to_regclass('lucid_auth_api_keys') IS NOT NULL")
                .fetch_one(&mut *transaction)
                .await
                .map_err(storage_error)?;
        if api_key_table_exists {
            sqlx::query("DELETE FROM lucid_auth_api_keys WHERE reference_id = $1")
                .bind(user_id.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        sqlx::query("DELETE FROM lucid_auth_verifications WHERE payload->>'userId' = $1")
            .bind(user_id.to_string())
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let result = sqlx::query("DELETE FROM lucid_auth_users WHERE id = $1")
            .bind(user_id)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError> {
        sqlx::query_as::<_, SessionRow>(
            "SELECT id, user_id, token_hash, actor_user_id, authentication_method, \
             expires_at, created_at, updated_at, ip_address, user_agent, additional_fields \
             FROM lucid_auth_sessions WHERE user_id = $1 AND expires_at > NOW() \
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map(|rows| rows.into_iter().map(AuthSession::from).collect())
        .map_err(storage_error)
    }

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError> {
        sqlx::query("DELETE FROM lucid_auth_sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(storage_error)
    }
}

fn push_conditions(
    query: &mut QueryBuilder<'_, Postgres>,
    conditions: &[AdminListCondition],
) -> Result<(), AuthError> {
    if conditions.is_empty() {
        return Ok(());
    }
    query.push(" WHERE ");
    for (index, condition) in conditions.iter().enumerate() {
        if index > 0 {
            query.push(" AND ");
        }
        let value = condition_text(&condition.value);
        push_text_field(query, &condition.field);
        query.push(" ");
        match condition.operator {
            AdminListOperator::Eq => {
                query.push("= ").push_bind(value);
            }
            AdminListOperator::Ne => {
                query.push("<> ").push_bind(value);
            }
            AdminListOperator::Lt => {
                query.push("< ").push_bind(value);
            }
            AdminListOperator::Lte => {
                query.push("<= ").push_bind(value);
            }
            AdminListOperator::Gt => {
                query.push("> ").push_bind(value);
            }
            AdminListOperator::Gte => {
                query.push(">= ").push_bind(value);
            }
            AdminListOperator::Contains => {
                query.push("ILIKE ").push_bind(format!("%{value}%"));
            }
            AdminListOperator::StartsWith => {
                query.push("ILIKE ").push_bind(format!("{value}%"));
            }
            AdminListOperator::EndsWith => {
                query.push("ILIKE ").push_bind(format!("%{value}"));
            }
            AdminListOperator::In | AdminListOperator::NotIn => {
                let values = condition
                    .value
                    .as_array()
                    .ok_or_else(|| AuthError::InvalidRequest("filter list is invalid".into()))?
                    .iter()
                    .map(condition_text)
                    .collect::<Vec<_>>();
                if condition.operator == AdminListOperator::NotIn {
                    query.push("<> ALL(");
                } else {
                    query.push("= ANY(");
                }
                query.push_bind(values).push(")");
            }
        };
    }
    Ok(())
}

fn push_sort_field(query: &mut QueryBuilder<'_, Postgres>, field: &str) {
    if let Some(column) = core_user_column(field) {
        query.push(column);
    } else {
        query
            .push("(additional_fields ->> ")
            .push_bind(field.to_owned())
            .push(")");
    }
}

fn push_text_field(query: &mut QueryBuilder<'_, Postgres>, field: &str) {
    if let Some(column) = core_user_column(field) {
        query.push("CAST(").push(column).push(" AS TEXT)");
    } else {
        query
            .push("(additional_fields ->> ")
            .push_bind(field.to_owned())
            .push(")");
    }
}

fn core_user_column(field: &str) -> Option<&'static str> {
    match field {
        "id" => Some("id"),
        "username" => Some("username"),
        "displayUsername" => Some("display_username"),
        "name" => Some("name"),
        "email" => Some("email"),
        "emailVerified" => Some("email_verified"),
        "image" => Some("image"),
        "role" => Some("role"),
        "isAnonymous" => Some("is_anonymous"),
        "banned" => Some("banned"),
        "banReason" => Some("ban_reason"),
        "banExpires" => Some("ban_expires"),
        "createdAt" => Some("created_at"),
        "updatedAt" => Some("updated_at"),
        _ => None,
    }
}

fn condition_text(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
