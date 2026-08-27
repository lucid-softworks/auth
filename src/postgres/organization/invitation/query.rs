use super::super::{rows, storage_error};
use crate::{
    AuthError, OrganizationInvitation, OrganizationInvitationStatus, OrganizationMember,
    postgres::PostgresModel,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(super) async fn find<'e, E, const N: usize>(
    executor: E,
    model: &PostgresModel<'_>,
    filters: [(&str, Value); N],
    for_update: bool,
) -> Result<Option<OrganizationInvitation>, AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut query = filter_query(model, filters, false)?;
    if for_update {
        query.push(" FOR UPDATE");
    }
    decode_optional(
        model,
        query
            .build()
            .fetch_optional(executor)
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn list<'e, E>(
    executor: E,
    model: &PostgresModel<'_>,
    field: &str,
    value: Value,
    case_insensitive: bool,
) -> Result<Vec<OrganizationInvitation>, AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut query = filter_query(model, [(field, value)], case_insensitive)?;
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" ASC, \"id\" ASC");
    query
        .build()
        .fetch_all(executor)
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode_invitation(model, row))
        .collect()
}

pub(super) fn filter_query<const N: usize>(
    model: &PostgresModel<'_>,
    filters: [(&str, Value); N],
    case_insensitive: bool,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = crate::postgres::rows::select_query(model);
    for (index, (field, value)) in filters.into_iter().enumerate() {
        query.push(if index == 0 { " WHERE " } else { " AND " });
        if case_insensitive {
            query.push("lower(");
        }
        query.push(model.quoted_column(field)?);
        if case_insensitive {
            query.push(") = lower(");
        } else {
            query.push(" = ");
        }
        model.encode(field, value)?.push_bind(&mut query);
        if case_insensitive {
            query.push(")");
        }
    }
    Ok(query)
}

pub(super) async fn insert_invitation(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    invitation: &OrganizationInvitation,
    id: &crate::PreparedDatabaseId,
) -> Result<OrganizationInvitation, AuthError> {
    let mut query =
        crate::postgres::rows::insert_query(model, rows::invitation_writes(model, invitation, id)?);
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    rows::decode_invitation(model, &row)
}

pub(super) async fn insert_member(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    member: &OrganizationMember,
    id: &crate::PreparedDatabaseId,
) -> Result<OrganizationMember, AuthError> {
    let mut query =
        crate::postgres::rows::insert_query(model, rows::member_writes(model, member, id)?);
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)?;
    rows::decode_member(model, &row)
}

pub(super) async fn count_by_organization(
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

pub(super) async fn pending_count(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: &str,
    email: Option<&str>,
) -> Result<i64, AuthError> {
    let mut query = count_query(model, organization_id)?;
    if let Some(email) = email {
        query
            .push(" AND lower(")
            .push(model.quoted_column("email")?)
            .push(") = lower(");
        model.encode("email", json!(email))?.push_bind(&mut query);
        query.push(")");
    }
    query
        .push(" AND ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", json!("pending"))?
        .push_bind(&mut query);
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn cancel_pending_for_email(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: &str,
    email: &str,
) -> Result<(), AuthError> {
    let writes = model.encode_fields([("status", json!("canceled"))])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND lower(")
        .push(model.quoted_column("email")?)
        .push(") = lower(");
    model.encode("email", json!(email))?.push_bind(&mut query);
    query
        .push(") AND ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", json!("pending"))?
        .push_bind(&mut query);
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) fn status_update_query(
    model: &PostgresModel<'_>,
    id: &str,
    status: OrganizationInvitationStatus,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([("status", json!(rows::status_name(status)))])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    model.encode("id", json!(id))?.push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    Ok(query)
}

pub(super) async fn update_status(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    id: &str,
    status: OrganizationInvitationStatus,
) -> Result<(), AuthError> {
    let mut query = status_update_query(model, id, status)?;
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

pub(super) fn resend_query(
    model: &PostgresModel<'_>,
    organization_id: &str,
    email: &str,
    expires_at: DateTime<Utc>,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([("expiresAt", json!(expires_at.to_rfc3339()))])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = (SELECT \"id\" FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND lower(")
        .push(model.quoted_column("email")?)
        .push(") = lower(");
    model.encode("email", json!(email))?.push_bind(&mut query);
    query
        .push(") AND ")
        .push(model.quoted_column("status")?)
        .push(" = ");
    model
        .encode("status", json!("pending"))?
        .push_bind(&mut query);
    query
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" DESC LIMIT 1) RETURNING ")
        .push(model.all_projection());
    Ok(query)
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

pub(super) fn decode_optional(
    model: &PostgresModel<'_>,
    row: Option<sqlx::postgres::PgRow>,
) -> Result<Option<OrganizationInvitation>, AuthError> {
    row.as_ref()
        .map(|row| rows::decode_invitation(model, row))
        .transpose()
}

#[cfg(test)]
#[path = "query_test.rs"]
mod tests;
