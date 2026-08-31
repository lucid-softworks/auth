use super::{
    MssqlComparisonMode, MssqlFilter, MssqlFilterConnector, MssqlFilterOperator,
    MssqlFindOptions, MssqlSort, MssqlSortDirection, MssqlStore, codec, session,
};
use crate::{
    AccessStore, AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthSession, AuthUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl AccessStore for MssqlStore {
    async fn list_users(&self, input: &AdminListUsersQuery) -> Result<Vec<AuthUser>, AuthError> {
        let filters = filters(&input.conditions);
        let options = MssqlFindOptions {
            sort: Some(MssqlSort {
                field: input.sort_by.clone().unwrap_or_else(|| "createdAt".into()),
                direction: match input.sort_direction {
                    AdminSortDirection::Asc => MssqlSortDirection::Ascending,
                    AdminSortDirection::Desc => MssqlSortDirection::Descending,
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
        i64::try_from(count).map_err(|_| AuthError::Storage("MSSQL user count overflow".into()))
    }

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError> {
        let count = self
            .count_records("user", &[MssqlFilter::equal("role", json!(role))])
            .await?;
        i64::try_from(count).map_err(|_| AuthError::Storage("MSSQL user count overflow".into()))
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
        let mut transaction = self.begin().await.map_err(storage)?;
        if schema.has_model("apikey") {
            super::query::execute::delete_many(
                &mut transaction,
                schema,
                "apikey",
                &[MssqlFilter::equal("referenceId", json!(id))],
            )
            .await?;
        }
        let affected = super::query::execute::delete_many(
            &mut transaction,
            schema,
            "user",
            &[MssqlFilter::equal("id", json!(id))],
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
                MssqlFilter::equal("userId", json!(user_id)),
                comparison("expiresAt", json!(Utc::now()), MssqlFilterOperator::Gte),
            ],
            &MssqlFindOptions {
                sort: Some(MssqlSort {
                    field: "createdAt".into(),
                    direction: MssqlSortDirection::Descending,
                }),
                ..MssqlFindOptions::default()
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
    store: &MssqlStore,
    id: &str,
    values: Map<String, Value>,
) -> Result<AuthUser, AuthError> {
    store
        .update_record("user", &[MssqlFilter::equal("id", json!(id))], values)
        .await
        .map_err(user_update_error)?
        .map(|record| codec::decode("user", record))
        .transpose()?
        .ok_or(AuthError::NotFound)
}

fn filters(conditions: &[AdminListCondition]) -> Vec<MssqlFilter> {
    conditions
        .iter()
        .map(|condition| MssqlFilter {
            field: condition.field.clone(),
            value: condition.value.clone(),
            operator: match condition.operator {
                AdminListOperator::Eq => MssqlFilterOperator::Eq,
                AdminListOperator::Ne => MssqlFilterOperator::Ne,
                AdminListOperator::Lt => MssqlFilterOperator::Lt,
                AdminListOperator::Lte => MssqlFilterOperator::Lte,
                AdminListOperator::Gt => MssqlFilterOperator::Gt,
                AdminListOperator::Gte => MssqlFilterOperator::Gte,
                AdminListOperator::In => MssqlFilterOperator::In,
                AdminListOperator::NotIn => MssqlFilterOperator::NotIn,
                AdminListOperator::Contains => MssqlFilterOperator::Contains,
                AdminListOperator::StartsWith => MssqlFilterOperator::StartsWith,
                AdminListOperator::EndsWith => MssqlFilterOperator::EndsWith,
            },
            connector: MssqlFilterConnector::And,
            mode: match condition.operator {
                AdminListOperator::Contains
                | AdminListOperator::StartsWith
                | AdminListOperator::EndsWith => MssqlComparisonMode::Insensitive,
                _ => MssqlComparisonMode::Sensitive,
            },
        })
        .collect()
}

fn comparison(field: &str, value: Value, operator: MssqlFilterOperator) -> MssqlFilter {
    MssqlFilter {
        field: field.into(),
        value,
        operator,
        connector: MssqlFilterConnector::And,
        mode: MssqlComparisonMode::Sensitive,
    }
}

fn user_update_error(error: AuthError) -> AuthError {
    match error {
        error if crate::mssql::error::is_unique_violation(&error) => {
            AuthError::UserAlreadyExistsEmail
        }
        error => error,
    }
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
