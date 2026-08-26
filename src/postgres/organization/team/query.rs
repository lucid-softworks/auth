use super::super::{rows, storage_error};
use crate::{AuthError, OrganizationTeam, OrganizationTeamMember, postgres::PostgresModel};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

pub(super) async fn find_team<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    id: Uuid,
) -> Result<Option<OrganizationTeam>, AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut query = crate::postgres::rows::select_query(model);
    query.push(" WHERE \"id\" = ");
    model.encode("id", uuid_value(id))?.push_bind(&mut query);
    query
        .build()
        .fetch_optional(executor)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_team(model, row))
        .transpose()
}

pub(super) fn list_teams_query(
    model: &PostgresModel<'_>,
    organization_id: Uuid,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = crate::postgres::rows::select_query(model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", uuid_value(organization_id))?
        .push_bind(&mut query);
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" ASC, \"id\" ASC");
    Ok(query)
}

pub(super) fn update_team_query(
    model: &PostgresModel<'_>,
    team: &OrganizationTeam,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([
        ("name", json!(team.name)),
        (
            "updatedAt",
            team.updated_at
                .map_or(Value::Null, |value| json!(value.to_rfc3339())),
        ),
    ])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", uuid_value(team.id))?
        .push_bind(&mut query);
    query
        .push(" AND NOT EXISTS (SELECT 1 FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", uuid_value(team.organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("name")?)
        .push(" = ");
    model
        .encode("name", json!(team.name))?
        .push_bind(&mut query);
    query.push(" AND \"id\" <> ");
    model
        .encode("id", uuid_value(team.id))?
        .push_bind(&mut query);
    query.push(") RETURNING ").push(model.all_projection());
    Ok(query)
}

pub(super) async fn insert_team(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    team: &OrganizationTeam,
) -> Result<(), AuthError> {
    let mut query =
        crate::postgres::rows::insert_query_prefix(model, rows::team_writes(model, team)?);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn insert_team_member(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    member: &OrganizationTeamMember,
) -> Result<(), AuthError> {
    let mut query =
        crate::postgres::rows::insert_query_prefix(model, rows::team_member_writes(model, member)?);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn lock_team(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    id: Uuid,
) -> Result<(), AuthError> {
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
        .fetch_one(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn team_exists(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: Uuid,
    name: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", uuid_value(organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("name")?)
        .push(" = ");
    model.encode("name", json!(name))?.push_bind(&mut query);
    query.push(")");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn team_count(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: Uuid,
) -> Result<i64, AuthError> {
    let mut query = QueryBuilder::new("SELECT count(*) FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", uuid_value(organization_id))?
        .push_bind(&mut query);
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn delete_team(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    id: Uuid,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", uuid_value(id))?.push_bind(&mut query);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn team_member_exists(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("teamId")?)
        .push(" = ");
    model
        .encode("teamId", uuid_value(team_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    model
        .encode("userId", uuid_value(user_id))?
        .push_bind(&mut query);
    query.push(")");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn team_member_count(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    team_id: Uuid,
) -> Result<i64, AuthError> {
    let mut query = QueryBuilder::new("SELECT count(*) FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("teamId")?)
        .push(" = ");
    model
        .encode("teamId", uuid_value(team_id))?
        .push_bind(&mut query);
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) fn delete_team_member_query(
    model: &PostgresModel<'_>,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("teamId")?)
        .push(" = ");
    model
        .encode("teamId", uuid_value(team_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    model
        .encode("userId", uuid_value(user_id))?
        .push_bind(&mut query);
    Ok(query)
}

pub(super) fn list_team_members_query(
    model: &PostgresModel<'_>,
    team_id: Uuid,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = crate::postgres::rows::select_query(model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("teamId")?)
        .push(" = ");
    model
        .encode("teamId", uuid_value(team_id))?
        .push_bind(&mut query);
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" ASC, \"id\" ASC");
    Ok(query)
}

pub(super) fn list_user_teams_query(
    team: &PostgresModel<'_>,
    member: &PostgresModel<'_>,
    user_id: Uuid,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = crate::postgres::rows::select_query(team);
    query
        .push(" WHERE EXISTS (SELECT 1 FROM ")
        .push(member.quoted_table())
        .push(" WHERE ")
        .push(member.quoted_column("teamId")?)
        .push(" = ")
        .push(team.quoted_table())
        .push(".\"id\" AND ")
        .push(member.quoted_column("userId")?)
        .push(" = ");
    member
        .encode("userId", uuid_value(user_id))?
        .push_bind(&mut query);
    query
        .push(") ORDER BY ")
        .push(team.quoted_column("createdAt")?)
        .push(" ASC, ")
        .push(team.quoted_table())
        .push(".\"id\" ASC");
    Ok(query)
}

pub(super) fn uuid_value(value: Uuid) -> Value {
    Value::String(value.to_string())
}

#[cfg(test)]
#[path = "query_test.rs"]
mod tests;
