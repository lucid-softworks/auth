use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AccessStore, AdminListCondition, AdminListUsersQuery, AdminSortDirection, AdminUserUpdate,
    AuthError, AuthSession, AuthUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};

mod query;
use query::push_conditions;

#[async_trait]
impl AccessStore for PostgresStore {
    async fn list_users(&self, input: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        let model = self.user_model()?;
        let mut query = super::rows::select_query(&model);
        push_conditions(&mut query, &model, &input.conditions)?;
        query
            .push(" ORDER BY ")
            .push(model.quoted_column(input.sort_by.as_deref().unwrap_or("createdAt"))?)
            .push(match input.sort_direction {
                AdminSortDirection::Asc => " ASC",
                AdminSortDirection::Desc => " DESC",
            })
            .push(" LIMIT ")
            .push_bind(input.limit as i64)
            .push(" OFFSET ")
            .push_bind(input.offset as i64);
        let rows = query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| super::user::decode_user(&model, row))
            .collect()
    }

    async fn count_users(&self, conditions: &[AdminListCondition]) -> Result<i64, AuthError> {
        let model = self.user_model()?;
        let mut query = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
        query.push(model.quoted_table());
        push_conditions(&mut query, &model, conditions)?;
        query
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        let model = self.user_model()?;
        let mut query = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column("role")?)
            .push(" = ");
        model.encode("role", json!(role))?.push_bind(&mut query);
        query
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)
    }

    async fn update_user_role(&self, user_id: &str, role: &str) -> Result<AuthUser, AuthError> {
        self.update_user_fields(user_id, [("role", json!(role)), ("updatedAt", now_value())])
            .await
    }

    async fn update_user_ban(
        &self,
        user_id: &str,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        self.update_user_fields(
            user_id,
            [
                ("banned", json!(banned)),
                ("banReason", reason.map_or(Value::Null, Value::String)),
                (
                    "banExpires",
                    expires_at.map_or(Value::Null, |value| json!(value.to_rfc3339())),
                ),
                ("updatedAt", now_value()),
            ],
        )
        .await
    }

    async fn admin_update_user(
        &self,
        user_id: &str,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        let mut user = super::user::load_by_id(self, user_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if let Some(value) = update.name {
            user.name = value;
        }
        if let Some(value) = update.email {
            user.email = value;
        }
        if let Some(value) = update.email_verified {
            user.email_verified = value;
        }
        if let Some(value) = update.image {
            user.image = value;
        }
        if let Some(value) = update.role {
            user.role = value;
        }
        if let Some(value) = update.banned {
            user.banned = value;
        }
        if let Some(value) = update.ban_reason {
            user.ban_reason = value;
        }
        if let Some(value) = update.ban_expires {
            user.ban_expires = value;
        }
        user.additional_fields.extend(update.additional_fields);
        user.updated_at = Utc::now();

        let model = self.user_model()?;
        let id = crate::PreparedDatabaseId::Value(crate::DatabaseIdValue::String(user.id.clone()));
        let mut writes = super::user::user_writes(&model, &user, &id)?;
        writes.retain(|write| write.logical() != "id");
        let mut query = super::rows::update_query(&model, writes);
        query.push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(user_id))?;
        query.push(" RETURNING ").push(model.all_projection());
        decode_user_optional(&model, query, &self.pool).await
    }

    async fn delete_user(&self, user_id: &str) -> Result<(), AuthError> {
        let user_model = self.user_model()?;
        let api_key_model = self.physical_model_if_present("apikey")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        if let Some(model) = api_key_model {
            let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
            query
                .push(model.quoted_table())
                .push(" WHERE ")
                .push(model.quoted_column("referenceId")?)
                .push(" = ");
            model
                .encode("referenceId", json!(user_id))?
                .push_bind(&mut query);
            query
                .build()
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        let mut query = QueryBuilder::<Postgres>::new("DELETE FROM ");
        query
            .push(user_model.quoted_table())
            .push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &user_model, "id", json!(user_id))?;
        let result = query
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        transaction.commit().await.map_err(storage_error)
    }

    async fn list_sessions(&self, user_id: &str) -> Result<Vec<AuthSession>, AuthError> {
        let model = self.session_model()?;
        let mut query = super::session::select_query(&model);
        query
            .push(" WHERE ")
            .push(model.quoted_column("userId")?)
            .push(" = ");
        model
            .encode("userId", json!(user_id))?
            .push_bind(&mut query);
        query
            .push(" AND ")
            .push(model.quoted_column("expiresAt")?)
            .push(" >= NOW() ORDER BY ")
            .push(model.quoted_column("createdAt")?)
            .push(" DESC");
        let rows = query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?;
        rows.iter()
            .map(|row| super::session::decode_session(&model, row))
            .collect()
    }

    async fn delete_session_by_id(&self, session_id: &str) -> Result<(), AuthError> {
        super::session::delete_by_id(self, session_id).await
    }

    async fn delete_user_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        super::session::delete_for_user(self, user_id).await
    }
}

impl PostgresStore {
    async fn update_user_fields<'a>(
        &self,
        user_id: &str,
        fields: impl IntoIterator<Item = (&'a str, Value)>,
    ) -> Result<AuthUser, AuthError> {
        let model = self.user_model()?;
        let writes = model.encode_fields(fields)?;
        let mut query = super::rows::update_query(&model, writes);
        query.push(" WHERE \"id\" = ");
        super::rows::push_model_value(&mut query, &model, "id", json!(user_id))?;
        query.push(" RETURNING ").push(model.all_projection());
        decode_user_optional(&model, query, &self.pool).await
    }
}

async fn decode_user_optional(
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
    pool: &sqlx::PgPool,
) -> Result<AuthUser, AuthError> {
    query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(|error| {
            if super::user::is_unique_violation(&error) {
                AuthError::UserAlreadyExistsEmail
            } else {
                storage_error(error)
            }
        })?
        .as_ref()
        .map(|row| super::user::decode_user(model, row))
        .transpose()?
        .ok_or(AuthError::NotFound)
}

fn now_value() -> Value {
    json!(Utc::now().to_rfc3339())
}
