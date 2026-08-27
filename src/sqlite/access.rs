use super::{
    SqliteComparisonMode, SqliteFilter, SqliteFilterConnector, SqliteFilterOperator,
    SqliteFindOptions, SqliteSort, SqliteSortDirection, SqliteStore, codec, session,
};
use crate::{
    AccessStore, AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthSession, AuthUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl AccessStore for SqliteStore {
    async fn list_users(&self, input: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        let filters = filters(&input.conditions);
        let options = SqliteFindOptions {
            sort: Some(SqliteSort {
                field: input.sort_by.clone().unwrap_or_else(|| "createdAt".into()),
                direction: match input.sort_direction {
                    AdminSortDirection::Asc => SqliteSortDirection::Ascending,
                    AdminSortDirection::Desc => SqliteSortDirection::Descending,
                },
            }),
            limit: Some(input.limit as u64),
            offset: Some(input.offset as u64),
            select: Vec::new(),
        };
        self.find_records("user", &filters, &options)
            .await?
            .into_iter()
            .map(|record| codec::decode("user", record))
            .collect()
    }

    async fn count_users(&self, conditions: &[AdminListCondition]) -> Result<i64, AuthError> {
        let count = self.count_records("user", &filters(conditions)).await?;
        i64::try_from(count).map_err(|_| AuthError::Storage("SQLite user count overflow".into()))
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        let count = self
            .count_records("user", &[SqliteFilter::equal("role", json!(role))])
            .await?;
        i64::try_from(count).map_err(|_| AuthError::Storage("SQLite user count overflow".into()))
    }

    async fn update_user_role(&self, id: &str, role: &str) -> Result<AuthUser, AuthError> {
        update_fields(
            self,
            id,
            Map::from_iter([
                ("role".into(), json!(role)),
                ("updatedAt".into(), json!(Utc::now())),
            ]),
        )
        .await
    }

    async fn update_user_ban(
        &self,
        id: &str,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<AuthUser, AuthError> {
        update_fields(
            self,
            id,
            Map::from_iter([
                ("banned".into(), json!(banned)),
                ("banReason".into(), json!(reason)),
                ("banExpires".into(), json!(expires_at)),
                ("updatedAt".into(), json!(Utc::now())),
            ]),
        )
        .await
    }

    async fn admin_update_user(
        &self,
        id: &str,
        update: AdminUserUpdate,
    ) -> Result<AuthUser, AuthError> {
        let mut user = super::user::find(self, "id", id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if let Some(value) = update.name {
            user.name = value;
        }
        if let Some(value) = update.email {
            user.email = value.to_lowercase();
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
        let values = codec::update_record(self, "user", &user)?;
        update_fields(self, id, values).await
    }

    async fn delete_user(&self, id: &str) -> Result<(), AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        if schema.has_model("apikey") {
            super::query::execute::delete_many(
                &mut transaction,
                schema,
                "apikey",
                &[SqliteFilter::equal("referenceId", json!(id))],
            )
            .await?;
        }
        let affected = super::query::execute::delete_many(
            &mut transaction,
            schema,
            "user",
            &[SqliteFilter::equal("id", json!(id))],
        )
        .await?;
        if affected == 0 {
            transaction.rollback().await.map_err(storage)?;
            return Err(AuthError::NotFound);
        }
        transaction.commit().await.map_err(storage)
    }

    async fn list_sessions(&self, user_id: &str) -> Result<Vec<AuthSession>, AuthError> {
        self.find_records(
            "session",
            &[
                SqliteFilter::equal("userId", json!(user_id)),
                comparison("expiresAt", json!(Utc::now()), SqliteFilterOperator::Gte),
            ],
            &SqliteFindOptions {
                sort: Some(SqliteSort {
                    field: "createdAt".into(),
                    direction: SqliteSortDirection::Descending,
                }),
                ..SqliteFindOptions::default()
            },
        )
        .await?
        .into_iter()
        .map(|record| codec::decode("session", record))
        .collect()
    }

    async fn delete_session_by_id(&self, id: &str) -> Result<(), AuthError> {
        session::delete_by(self, "id", json!(id)).await
    }

    async fn delete_user_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        session::delete_by(self, "userId", json!(user_id)).await
    }
}

async fn update_fields(
    store: &SqliteStore,
    id: &str,
    values: Map<String, Value>,
) -> Result<AuthUser, AuthError> {
    store
        .update_record("user", &[SqliteFilter::equal("id", json!(id))], values)
        .await
        .map_err(user_update_error)?
        .map(|record| codec::decode("user", record))
        .transpose()?
        .ok_or(AuthError::NotFound)
}

fn filters(conditions: &[AdminListCondition]) -> Vec<SqliteFilter> {
    conditions
        .iter()
        .map(|condition| SqliteFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                AdminListOperator::Eq => SqliteFilterOperator::Eq,
                AdminListOperator::Ne => SqliteFilterOperator::Ne,
                AdminListOperator::Lt => SqliteFilterOperator::Lt,
                AdminListOperator::Lte => SqliteFilterOperator::Lte,
                AdminListOperator::Gt => SqliteFilterOperator::Gt,
                AdminListOperator::Gte => SqliteFilterOperator::Gte,
                AdminListOperator::In => SqliteFilterOperator::In,
                AdminListOperator::NotIn => SqliteFilterOperator::NotIn,
                AdminListOperator::Contains => SqliteFilterOperator::Contains,
                AdminListOperator::StartsWith => SqliteFilterOperator::StartsWith,
                AdminListOperator::EndsWith => SqliteFilterOperator::EndsWith,
            },
            connector: SqliteFilterConnector::And,
            mode: match condition.operator {
                AdminListOperator::Contains
                | AdminListOperator::StartsWith
                | AdminListOperator::EndsWith => SqliteComparisonMode::Insensitive,
                _ => SqliteComparisonMode::Sensitive,
            },
        })
        .collect()
}

fn comparison(field: &str, value: Value, operator: SqliteFilterOperator) -> SqliteFilter {
    SqliteFilter {
        field: field.into(),
        value,
        operator,
        connector: SqliteFilterConnector::And,
        mode: SqliteComparisonMode::Sensitive,
    }
}

fn user_update_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Storage(message) if message.contains("UNIQUE constraint failed") => {
            AuthError::UserAlreadyExistsEmail
        }
        error => error,
    }
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
