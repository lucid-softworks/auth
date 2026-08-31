use super::{
    MongoComparisonMode, MongoFilter, MongoFilterConnector, MongoFilterOperator,
    MongoFindOptions, MongoSort, MongoSortDirection, MongoStore, codec, session,
};
use crate::{
    AccessStore, AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthSession, AuthUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl AccessStore for MongoStore {
    async fn list_users(&self, input: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        let filters = filters(&input.conditions);
        let options = MongoFindOptions {
            sort: Some(MongoSort {
                field: input.sort_by.clone().unwrap_or_else(|| "createdAt".into()),
                direction: match input.sort_direction {
                    AdminSortDirection::Asc => MongoSortDirection::Ascending,
                    AdminSortDirection::Desc => MongoSortDirection::Descending,
                },
            }),
            limit: Some(input.limit as u64),
            offset: Some(input.offset as u64),
            select: Vec::new(),
            ..Default::default()
        };
        self.find_records("user", &filters, &options)
            .await?
            .into_iter()
            .map(|record| codec::decode("user", record))
            .collect()
    }

    async fn count_users(&self, conditions: &[AdminListCondition]) -> Result<i64, AuthError> {
        let count = self.count_records("user", &filters(conditions)).await?;
        i64::try_from(count).map_err(|_| AuthError::Storage("MongoDB user count overflow".into()))
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        let count = self
            .count_records("user", &[MongoFilter::equal("role", json!(role))])
            .await?;
        i64::try_from(count).map_err(|_| AuthError::Storage("MongoDB user count overflow".into()))
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
        let mut transaction = self.begin().await?;
        if schema.has_model("apikey") {
            super::query::execute::delete_many(
                &mut transaction,
                schema,
                "apikey",
                &[MongoFilter::equal("referenceId", json!(id))],
            )
            .await?;
        }
        let affected = super::query::execute::delete_many(
            &mut transaction,
            schema,
            "user",
            &[MongoFilter::equal("id", json!(id))],
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
                MongoFilter::equal("userId", json!(user_id)),
                comparison("expiresAt", json!(Utc::now()), MongoFilterOperator::Gte),
            ],
            &MongoFindOptions {
                sort: Some(MongoSort {
                    field: "createdAt".into(),
                    direction: MongoSortDirection::Descending,
                }),
                ..MongoFindOptions::default()
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
    store: &MongoStore,
    id: &str,
    values: Map<String, Value>,
) -> Result<AuthUser, AuthError> {
    store
        .update_record("user", &[MongoFilter::equal("id", json!(id))], values)
        .await
        .map_err(user_update_error)?
        .map(|record| codec::decode("user", record))
        .transpose()?
        .ok_or(AuthError::NotFound)
}

fn filters(conditions: &[AdminListCondition]) -> Vec<MongoFilter> {
    conditions
        .iter()
        .map(|condition| MongoFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                AdminListOperator::Eq => MongoFilterOperator::Eq,
                AdminListOperator::Ne => MongoFilterOperator::Ne,
                AdminListOperator::Lt => MongoFilterOperator::Lt,
                AdminListOperator::Lte => MongoFilterOperator::Lte,
                AdminListOperator::Gt => MongoFilterOperator::Gt,
                AdminListOperator::Gte => MongoFilterOperator::Gte,
                AdminListOperator::In => MongoFilterOperator::In,
                AdminListOperator::NotIn => MongoFilterOperator::NotIn,
                AdminListOperator::Contains => MongoFilterOperator::Contains,
                AdminListOperator::StartsWith => MongoFilterOperator::StartsWith,
                AdminListOperator::EndsWith => MongoFilterOperator::EndsWith,
            },
            connector: MongoFilterConnector::And,
            mode: match condition.operator {
                AdminListOperator::Contains
                | AdminListOperator::StartsWith
                | AdminListOperator::EndsWith => MongoComparisonMode::Insensitive,
                _ => MongoComparisonMode::Sensitive,
            },
        })
        .collect()
}

fn comparison(field: &str, value: Value, operator: MongoFilterOperator) -> MongoFilter {
    MongoFilter {
        field: field.into(),
        value,
        operator,
        connector: MongoFilterConnector::And,
        mode: MongoComparisonMode::Sensitive,
    }
}

fn user_update_error(error: AuthError) -> AuthError {
    match error {
        error if crate::mongodb::error::is_unique_violation(&error) => {
            AuthError::UserAlreadyExistsEmail
        }
        error => error,
    }
}

fn storage(error: AuthError) -> AuthError {
    AuthError::Storage(error.to_string())
}
