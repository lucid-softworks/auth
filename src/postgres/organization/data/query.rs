use super::super::{rows, storage_error};
use crate::{
    AuthError, Organization, OrganizationMember, OrganizationTeam, OrganizationTeamMember,
    postgres::PostgresModel,
};
use serde_json::{Value, json};
use sqlx::{Executor, Postgres, QueryBuilder, Transaction, postgres::PgRow};
use uuid::Uuid;

pub(super) async fn insert_organization<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    organization: &Organization,
) -> Result<(), AuthError>
where
    E: Executor<'e, Database = Postgres>,
{
    let writes = rows::organization_writes(model, organization)?;
    let mut query = crate::postgres::rows::insert_query_prefix(model, writes);
    query
        .build()
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn insert_member<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    member: &OrganizationMember,
) -> Result<(), AuthError>
where
    E: Executor<'e, Database = Postgres>,
{
    let mut query =
        crate::postgres::rows::insert_query_prefix(model, rows::member_writes(model, member)?);
    query
        .build()
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn insert_team<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    team: &OrganizationTeam,
) -> Result<(), AuthError>
where
    E: Executor<'e, Database = Postgres>,
{
    let mut query =
        crate::postgres::rows::insert_query_prefix(model, rows::team_writes(model, team)?);
    query
        .build()
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn insert_team_member<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    member: &OrganizationTeamMember,
) -> Result<(), AuthError>
where
    E: Executor<'e, Database = Postgres>,
{
    let mut query =
        crate::postgres::rows::insert_query_prefix(model, rows::team_member_writes(model, member)?);
    query
        .build()
        .execute(executor)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn fetch_organization<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    field: &str,
    value: Value,
) -> Result<Option<Organization>, AuthError>
where
    E: Executor<'e, Database = Postgres>,
{
    let mut query = crate::postgres::rows::select_query(model);
    query
        .push(" WHERE ")
        .push(model.quoted_column(field)?)
        .push(" = ");
    model.encode(field, value)?.push_bind(&mut query);
    query
        .build()
        .fetch_optional(executor)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_organization(model, row))
        .transpose()
}

pub(super) fn list_query(
    organization: &PostgresModel<'_>,
    member: &PostgresModel<'_>,
    user_id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = crate::postgres::rows::select_query(organization);
    query
        .push(" WHERE EXISTS (SELECT 1 FROM ")
        .push(member.quoted_table())
        .push(" WHERE ")
        .push(member.quoted_column("organizationId")?)
        .push(" = ")
        .push(organization.quoted_table())
        .push(".\"id\" AND ")
        .push(member.quoted_column("userId")?)
        .push(" = ");
    member
        .encode("userId", json!(user_id))?
        .push_bind(&mut query);
    query
        .push(") ORDER BY ")
        .push(organization.quoted_column("createdAt")?)
        .push(" ASC, ")
        .push(organization.quoted_table())
        .push(".\"id\" ASC");
    Ok(query)
}

pub(super) fn update_query(
    model: &PostgresModel<'_>,
    organization: &Organization,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([
        ("name", json!(organization.name)),
        ("slug", json!(organization.slug)),
        (
            "logo",
            organization.logo.clone().map_or(Value::Null, Value::String),
        ),
        (
            "metadata",
            organization
                .metadata
                .as_ref()
                .map(|value| serde_json::to_string(value).map(Value::String))
                .transpose()
                .map_err(storage_error)?
                .unwrap_or(Value::Null),
        ),
    ])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", uuid_value(organization.id))?
        .push_bind(&mut query);
    query
        .push(" AND NOT EXISTS (SELECT 1 FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("slug")?)
        .push(" = ");
    model
        .encode("slug", json!(organization.slug))?
        .push_bind(&mut query);
    query.push(" AND \"id\" <> ");
    model
        .encode("id", uuid_value(organization.id))?
        .push_bind(&mut query);
    query.push(") RETURNING ").push(model.all_projection());
    Ok(query)
}

pub(super) fn delete_query(
    model: &PostgresModel<'_>,
    id: Uuid,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", uuid_value(id))?.push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    Ok(query)
}

pub(super) async fn lock_user(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    user_id: &str,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.projection(["id"])?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ");
    model.encode("id", json!(user_id))?.push_bind(&mut query);
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map(|_: PgRow| ())
        .map_err(storage_error)
}

pub(super) async fn lock_organization_row(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    id: Uuid,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.projection(["id"])?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ");
    model.encode("id", uuid_value(id))?.push_bind(&mut query);
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map(|row| row.is_some())
        .map_err(storage_error)
}

pub(super) async fn advisory_slug_lock(
    transaction: &mut Transaction<'_, Postgres>,
    slug: &str,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("SELECT pg_advisory_xact_lock(hashtext(");
    query.push_bind(slug.to_owned()).push("))");
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn slug_exists(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    slug: &str,
) -> Result<bool, AuthError> {
    exists_by(transaction, model, "slug", json!(slug)).await
}

pub(super) async fn exists_by(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    field: &str,
    value: Value,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(field)?)
        .push(" = ");
    model.encode(field, value)?.push_bind(&mut query);
    query.push(")");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn count_by(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    field: &str,
    id: &str,
) -> Result<i64, AuthError> {
    let mut query = count_query(model, field, id)?;
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) fn count_query(
    model: &PostgresModel<'_>,
    field: &str,
    id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT count(*) FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(field)?)
        .push(" = ");
    model.encode(field, json!(id))?.push_bind(&mut query);
    Ok(query)
}

pub(super) async fn delete_by(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    field: &str,
    id: Uuid,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column(field)?)
        .push(" = ");
    model.encode(field, uuid_value(id))?.push_bind(&mut query);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn delete_team_members_for_organization(
    transaction: &mut Transaction<'_, Postgres>,
    team: &PostgresModel<'_>,
    member: &PostgresModel<'_>,
    organization_id: Uuid,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(member.quoted_table())
        .push(" WHERE ")
        .push(member.quoted_column("teamId")?)
        .push(" IN (SELECT \"id\" FROM ")
        .push(team.quoted_table())
        .push(" WHERE ")
        .push(team.quoted_column("organizationId")?)
        .push(" = ");
    team.encode("organizationId", uuid_value(organization_id))?
        .push_bind(&mut query);
    query.push(")");
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) fn incomplete_team_schema() -> AuthError {
    AuthError::InvalidConfiguration(
        "Better Auth organization team and teamMember models must be installed together".into(),
    )
}

pub(super) fn uuid_value(value: Uuid) -> Value {
    Value::String(value.to_string())
}

#[cfg(test)]
#[path = "query_test.rs"]
mod tests;
