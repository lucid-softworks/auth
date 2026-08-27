use super::{member::lock_organization, rows, storage_error};
use crate::{
    AuthError, OrganizationRole, OrganizationRoleStore,
    postgres::{PostgresModel, PostgresStore},
};
use async_trait::async_trait;
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};

#[async_trait]
impl OrganizationRoleStore for PostgresStore {
    async fn create_role(
        &self,
        role: &mut OrganizationRole,
        id: &dyn crate::DatabaseIdSupplier,
        maximum_roles: Option<usize>,
    ) -> Result<bool, AuthError> {
        let organization = self.physical_model("organization")?;
        let model = self.physical_model("organizationRole")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut transaction, &organization, &role.organization_id).await?;
        if let Some(limit) = maximum_roles
            && role_count(&mut transaction, &model, &role.organization_id).await? >= limit as i64
        {
            return Ok(false);
        }
        if find(
            &mut *transaction,
            &model,
            [
                ("organizationId", json!(role.organization_id)),
                ("role", json!(role.role)),
            ],
        )
        .await?
        .is_some()
        {
            return Ok(false);
        }
        let prepared = id.prepare()?;
        let mut query = crate::postgres::rows::insert_query(
            &model,
            rows::role_writes(&model, role, &prepared)?,
        );
        let row = query
            .build()
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
        *role = rows::decode_role(&model, &row)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }

    async fn find_role(&self, id: &str) -> Result<Option<OrganizationRole>, AuthError> {
        let model = self.physical_model("organizationRole")?;
        find(&self.pool, &model, [("id", json!(id))]).await
    }

    async fn find_role_by_name(
        &self,
        organization_id: &str,
        role: &str,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        let model = self.physical_model("organizationRole")?;
        find(
            &self.pool,
            &model,
            [
                ("organizationId", json!(organization_id)),
                ("role", json!(role)),
            ],
        )
        .await
    }

    async fn list_roles(&self, organization_id: &str) -> Result<Vec<OrganizationRole>, AuthError> {
        let model = self.physical_model("organizationRole")?;
        let mut query = list_query(&model, organization_id)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| rows::decode_role(&model, row))
            .collect()
    }

    async fn update_role(
        &self,
        role: OrganizationRole,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        let model = self.physical_model("organizationRole")?;
        let mut query = update_query(&model, &role)?;
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| rows::decode_role(&model, row))
            .transpose()
    }

    async fn delete_role(&self, id: &str) -> Result<bool, AuthError> {
        let organization = self.physical_model("organization")?;
        let model = self.physical_model("organizationRole")?;
        let member = self.physical_model("member")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let Some(role) = find(&mut *transaction, &model, [("id", json!(id))]).await? else {
            return Ok(false);
        };
        lock_organization(&mut transaction, &organization, &role.organization_id).await?;
        if role_assigned(&mut transaction, &member, &role.organization_id, &role.role).await? {
            return Ok(false);
        }
        let mut query = QueryBuilder::new("DELETE FROM ");
        query.push(model.quoted_table()).push(" WHERE \"id\" = ");
        model.encode("id", json!(id))?.push_bind(&mut query);
        query
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(true)
    }
}

async fn find<'e, E, const N: usize>(
    executor: E,
    model: &PostgresModel<'_>,
    filters: [(&str, Value); N],
) -> Result<Option<OrganizationRole>, AuthError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let mut query = filter_query(model, filters)?;
    query
        .build()
        .fetch_optional(executor)
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode_role(model, row))
        .transpose()
}

fn filter_query<const N: usize>(
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

fn list_query(
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

fn update_query(
    model: &PostgresModel<'_>,
    role: &OrganizationRole,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([
        ("role", json!(role.role)),
        (
            "permission",
            json!(serde_json::to_string(&role.permission).map_err(storage_error)?),
        ),
        (
            "updatedAt",
            role.updated_at
                .map_or(Value::Null, |value| json!(value.to_rfc3339())),
        ),
    ])?;
    let mut query = crate::postgres::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    model.encode("id", json!(role.id))?.push_bind(&mut query);
    query
        .push(" AND NOT EXISTS (SELECT 1 FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", json!(role.organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push(model.quoted_column("role")?)
        .push(" = ");
    model
        .encode("role", json!(role.role))?
        .push_bind(&mut query);
    query.push(" AND \"id\" <> ");
    model.encode("id", json!(role.id))?.push_bind(&mut query);
    query.push(") RETURNING ").push(model.all_projection());
    Ok(query)
}

async fn role_count(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    organization_id: &str,
) -> Result<i64, AuthError> {
    let mut query = QueryBuilder::new("SELECT count(*) FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("organizationId")?)
        .push(" = ");
    model
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

async fn role_assigned(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    member: &PostgresModel<'_>,
    organization_id: &str,
    role: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(member.quoted_table())
        .push(" WHERE ")
        .push(member.quoted_column("organizationId")?)
        .push(" = ");
    member
        .encode("organizationId", json!(organization_id))?
        .push_bind(&mut query);
    query
        .push(" AND ")
        .push_bind(role.to_owned())
        .push(" = ANY(string_to_array(")
        .push(member.quoted_column("role")?)
        .push(", ',')))");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::BTreeMap;
    use uuid::Uuid;

    #[test]
    fn role_queries_remap_create_filter_sort_and_update() {
        let physical = super::super::test_support::physical_schema();
        let model = physical.model("organizationRole").unwrap();
        let role = OrganizationRole {
            id: Uuid::from_u128(51).to_string(),
            organization_id: Uuid::from_u128(52).to_string(),
            role: "private-role".into(),
            permission: BTreeMap::from([("team".into(), vec!["read".into()])]),
            created_at: Utc::now(),
            updated_at: Some(Utc::now()),
        };

        let writes = rows::role_writes(
            &model,
            &role,
            &crate::postgres::rows::explicit_id(role.id.clone()),
        )
        .unwrap();
        let insert = crate::postgres::rows::insert_query_prefix(&model, writes);
        assert!(insert.sql().starts_with("INSERT INTO \"org\"\"roles\""));
        assert!(insert.sql().contains("\"permission json\""));
        assert!(!insert.sql().contains("private-role"));

        let filter = filter_query(
            &model,
            [
                ("organizationId", json!(role.organization_id)),
                ("role", json!("private-role")),
            ],
        )
        .unwrap();
        assert!(filter.sql().contains("\"tenant id\" = $1"));
        assert!(filter.sql().contains("\"role name\" = $2"));

        let list = list_query(&model, &role.organization_id).unwrap();
        assert!(list.sql().contains("ORDER BY \"created time\" ASC"));
        let update = update_query(&model, &role).unwrap();
        assert!(update.sql().contains("SET \"role name\" = $1"));
        assert!(update.sql().contains("\"permission json\" = $2"));
        assert!(update.sql().contains("\"role name\" AS \"role\""));
        assert!(
            update
                .sql()
                .ends_with(&format!(") RETURNING {}", model.all_projection()))
        );
    }
}
