use super::{rows::MemberRow, storage_error};
use crate::{
    AuthError, OrganizationMember, OrganizationMemberStore, OrganizationMemberWriteOutcome,
    postgres::PostgresStore,
};
use async_trait::async_trait;
use uuid::Uuid;

const COLUMNS: &str = "id, organization_id, user_id, role, created_at";

#[async_trait]
impl OrganizationMemberStore for PostgresStore {
    async fn find_member_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>, AuthError> {
        find(&self.pool, "id", id).await
    }

    async fn find_member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>, AuthError> {
        sqlx::query_as::<_, MemberRow>(&format!("SELECT {COLUMNS} FROM lucid_auth_organization_members WHERE organization_id=$1 AND user_id=$2"))
            .bind(organization_id).bind(user_id).fetch_optional(&self.pool).await.map(|row| row.map(Into::into)).map_err(storage_error)
    }

    async fn list_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>, AuthError> {
        sqlx::query_as::<_, MemberRow>(&format!("SELECT {COLUMNS} FROM lucid_auth_organization_members WHERE organization_id=$1 ORDER BY created_at,id"))
            .bind(organization_id).fetch_all(&self.pool).await.map(|rows| rows.into_iter().map(Into::into).collect()).map_err(storage_error)
    }

    async fn add_member(
        &self,
        member: OrganizationMember,
        membership_limit: usize,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut tx, member.organization_id).await?;
        if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM lucid_auth_organization_members WHERE organization_id=$1 AND user_id=$2)")
            .bind(member.organization_id).bind(member.user_id).fetch_one(&mut *tx).await.map_err(storage_error)? {
            return Ok(OrganizationMemberWriteOutcome::AlreadyMember);
        }
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM lucid_auth_organization_members WHERE organization_id=$1",
        )
        .bind(member.organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_error)?;
        if count >= membership_limit as i64 {
            return Ok(OrganizationMemberWriteOutcome::LimitReached);
        }
        sqlx::query("INSERT INTO lucid_auth_organization_members (id,organization_id,user_id,role,created_at) VALUES ($1,$2,$3,$4,$5)")
            .bind(member.id).bind(member.organization_id).bind(member.user_id).bind(member.role).bind(member.created_at)
            .execute(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn update_member_role(
        &self,
        member_id: Uuid,
        role: String,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let Some(current) = sqlx::query_as::<_, MemberRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organization_members WHERE id=$1 FOR UPDATE"
        ))
        .bind(member_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        lock_organization(&mut tx, current.organization_id).await?;
        if has_role(&current.role, creator_role)
            && !has_role(&role, creator_role)
            && owner_count(&mut tx, current.organization_id, creator_role).await? <= 1
        {
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        sqlx::query("UPDATE lucid_auth_organization_members SET role=$2 WHERE id=$1")
            .bind(member_id)
            .bind(role)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }

    async fn remove_member(
        &self,
        member_id: Uuid,
        creator_role: &str,
    ) -> Result<OrganizationMemberWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let Some(current) = sqlx::query_as::<_, MemberRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organization_members WHERE id=$1 FOR UPDATE"
        ))
        .bind(member_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        else {
            return Ok(OrganizationMemberWriteOutcome::NotFound);
        };
        lock_organization(&mut tx, current.organization_id).await?;
        if has_role(&current.role, creator_role)
            && owner_count(&mut tx, current.organization_id, creator_role).await? <= 1
        {
            return Ok(OrganizationMemberWriteOutcome::LastOwner);
        }
        sqlx::query("DELETE FROM lucid_auth_organization_members WHERE id=$1")
            .bind(member_id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_organization_team_members tm USING lucid_auth_organization_teams t WHERE tm.team_id=t.id AND t.organization_id=$1 AND tm.user_id=$2")
            .bind(current.organization_id).bind(current.user_id).execute(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationMemberWriteOutcome::Written)
    }
}

async fn find(
    pool: &sqlx::PgPool,
    column: &str,
    value: Uuid,
) -> Result<Option<OrganizationMember>, AuthError> {
    sqlx::query_as::<_, MemberRow>(&format!(
        "SELECT {COLUMNS} FROM lucid_auth_organization_members WHERE {column}=$1"
    ))
    .bind(value)
    .fetch_optional(pool)
    .await
    .map(|row| row.map(Into::into))
    .map_err(storage_error)
}

pub(super) async fn lock_organization(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: Uuid,
) -> Result<(), AuthError> {
    sqlx::query("SELECT id FROM lucid_auth_organizations WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(storage_error)?;
    Ok(())
}

async fn owner_count(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    role: &str,
) -> Result<i64, AuthError> {
    sqlx::query_scalar("SELECT count(*) FROM lucid_auth_organization_members WHERE organization_id=$1 AND $2 = ANY(string_to_array(role, ','))")
        .bind(organization_id).bind(role).fetch_one(&mut **tx).await.map_err(storage_error)
}

fn has_role(roles: &str, role: &str) -> bool {
    roles
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == role)
}
