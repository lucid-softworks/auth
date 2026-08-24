use super::{member::lock_organization, rows::RoleRow, storage_error};
use crate::{AuthError, OrganizationRole, OrganizationRoleStore, postgres::PostgresStore};
use async_trait::async_trait;
use uuid::Uuid;

const COLUMNS: &str = "id, organization_id, role, permission, created_at, updated_at";

#[async_trait]
impl OrganizationRoleStore for PostgresStore {
    async fn create_role(
        &self,
        role: OrganizationRole,
        maximum_roles: Option<usize>,
    ) -> Result<bool, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut tx, role.organization_id).await?;
        if let Some(limit) = maximum_roles {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM lucid_auth_organization_roles WHERE organization_id=$1",
            )
            .bind(role.organization_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            if count >= limit as i64 {
                return Ok(false);
            }
        }
        let result = sqlx::query("INSERT INTO lucid_auth_organization_roles (id,organization_id,role,permission,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (organization_id,role) DO NOTHING")
            .bind(role.id).bind(role.organization_id).bind(role.role).bind(serde_json::to_value(role.permission).map_err(storage_error)?).bind(role.created_at).bind(role.updated_at).execute(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(result.rows_affected() == 1)
    }

    async fn find_role(&self, id: Uuid) -> Result<Option<OrganizationRole>, AuthError> {
        one(sqlx::query_as::<_, RoleRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organization_roles WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?)
    }

    async fn find_role_by_name(
        &self,
        organization_id: Uuid,
        role: &str,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        one(sqlx::query_as::<_, RoleRow>(&format!("SELECT {COLUMNS} FROM lucid_auth_organization_roles WHERE organization_id=$1 AND role=$2")).bind(organization_id).bind(role).fetch_optional(&self.pool).await.map_err(storage_error)?)
    }

    async fn list_roles(&self, organization_id: Uuid) -> Result<Vec<OrganizationRole>, AuthError> {
        sqlx::query_as::<_, RoleRow>(&format!("SELECT {COLUMNS} FROM lucid_auth_organization_roles WHERE organization_id=$1 ORDER BY created_at,id")).bind(organization_id).fetch_all(&self.pool).await.map_err(storage_error)?.into_iter().map(TryInto::try_into).collect()
    }

    async fn update_role(
        &self,
        role: OrganizationRole,
    ) -> Result<Option<OrganizationRole>, AuthError> {
        let row = sqlx::query_as::<_, RoleRow>(&format!("UPDATE lucid_auth_organization_roles SET role=$2,permission=$3,updated_at=$4 WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM lucid_auth_organization_roles WHERE organization_id=$5 AND role=$2 AND id<>$1) RETURNING {COLUMNS}"))
            .bind(role.id).bind(role.role).bind(serde_json::to_value(role.permission).map_err(storage_error)?).bind(role.updated_at).bind(role.organization_id).fetch_optional(&self.pool).await.map_err(storage_error)?;
        one(row)
    }

    async fn delete_role(&self, id: Uuid) -> Result<bool, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let Some(role) = sqlx::query_as::<_, RoleRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organization_roles WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        else {
            return Ok(false);
        };
        lock_organization(&mut tx, role.organization_id).await?;
        let assigned = sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM lucid_auth_organization_members WHERE organization_id=$1 AND $2 = ANY(string_to_array(role, ',')))").bind(role.organization_id).bind(&role.role).fetch_one(&mut *tx).await.map_err(storage_error)?;
        if assigned {
            return Ok(false);
        }
        sqlx::query("DELETE FROM lucid_auth_organization_roles WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(true)
    }
}

fn one(row: Option<RoleRow>) -> Result<Option<OrganizationRole>, AuthError> {
    row.map(TryInto::try_into).transpose()
}
