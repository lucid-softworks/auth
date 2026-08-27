use super::super::{rows, storage_error};
use crate::{AuthError, OrganizationMember, postgres::PostgresModel};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(super) async fn find<'e, E, const N: usize>(
    executor: E,
    model: &PostgresModel<'_>,
    filters: [(&str, Value); N],
    for_update: bool,
) -> Result<Option<OrganizationMember>, AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut query = filter_query(model, filters)?;
    if for_update {
        query.push(" FOR UPDATE");
    }
    query
        .build()
        .fetch_optional(executor)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_member(model, row))
        .transpose()
}

pub(super) fn filter_query<const N: usize>(
    model: &PostgresModel<'_>,
    filters: [(&str, Value); N],
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = crate::postgres::rows::select_query(model);
    for (index, (field, value)) in filters.into_iter().enumerate() {
        query
            .push(if index == 0 { " WHERE " } else { " AND " })
            .push(model.quoted_column(field)?)
            .push(" = ");
        model.encode(field, value)?.push_bind(&mut query);
    }
    Ok(query)
}

pub(super) fn list_query(
    model: &PostgresModel<'_>,
    organization_id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = filter_query(model, [("organizationId", json!(organization_id))])?;
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" ASC, \"id\" ASC");
    Ok(query)
}

pub(super) async fn insert_member<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    member: &OrganizationMember,
    id: &crate::PreparedDatabaseId,
) -> Result<OrganizationMember, AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut query =
        crate::postgres::rows::insert_query(model, rows::member_writes(model, member, id)?);
    let row = query
        .build()
        .fetch_one(executor)
        .await
        .map_err(storage_error)?;
    rows::decode_member(model, &row)
}

pub(in crate::postgres::organization) async fn lock_organization(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    id: &str,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.projection(["id"])?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE \"id\" = ");
    model.encode("id", json!(id))?.push_bind(&mut query);
    query.push(" FOR UPDATE");
    query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn member_exists(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: &str,
    user_id: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    model
        .encode("userId", json!(user_id))?
        .push_bind(&mut query);
    query.push(")");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn member_count(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: &str,
) -> Result<i64, AuthError> {
    let mut query = count_query(model, organization_id)?;
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) fn count_query(
    model: &PostgresModel<'_>,
    organization_id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT count(*) FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    Ok(query)
}

pub(super) async fn owner_count(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: &str,
    role: &str,
) -> Result<i64, AuthError> {
    let mut query = count_query(model, organization_id)?;
    query
        .push(" AND ")
        .push_bind(role.to_owned())
        .push(" = ANY(string_to_array(")
        .push(model.quoted_column("role")?)
        .push(", ','))");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn update_role(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    member_id: &str,
    role: String,
) -> Result<(), AuthError> {
    let writes = model.encode_fields([("role", json!(role))])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    model.encode("id", json!(member_id))?.push_bind(&mut query);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn delete_member(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    member_id: &str,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model.encode("id", json!(member_id))?.push_bind(&mut query);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) async fn delete_team_members(
    transaction: &mut Transaction<'_, Postgres>,
    team: &PostgresModel<'_>,
    team_member: &PostgresModel<'_>,
    organization_id: &str,
    user_id: &str,
) -> Result<(), AuthError> {
    let mut query = delete_team_members_query(team, team_member, organization_id, user_id)?;
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) fn delete_team_members_query(
    team: &PostgresModel<'_>,
    team_member: &PostgresModel<'_>,
    organization_id: &str,
    user_id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(team_member.quoted_table())
        .push(" WHERE ")
        .push(team_member.quoted_column("teamId")?)
        .push(" IN (SELECT \"id\" FROM ")
        .push(team.quoted_table())
        .push(" WHERE ")
        .push(team.quoted_column("organizationId")?)
        .push(" = ");
    team.encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .push(") AND ")
        .push(team_member.quoted_column("userId")?)
        .push(" = ");
    team_member
        .encode("userId", json!(user_id))?
        .push_bind(&mut query);
    Ok(query)
}

pub(super) fn has_role(roles: &str, role: &str) -> bool {
    roles
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}

pub(super) fn incomplete_team_schema() -> AuthError {
    AuthError::InvalidConfiguration(
        "Better Auth organization team and teamMember models must be installed together".into(),
    )
}

#[cfg(test)]
#[path = "query_test.rs"]
mod tests;
