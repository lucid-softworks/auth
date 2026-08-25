use super::{rows::OrganizationRow, storage_error};
use crate::{
    AuthError, Organization, OrganizationCreateOutcome, OrganizationDataStore, OrganizationMember,
    OrganizationTeam, OrganizationTeamMember, postgres::PostgresStore,
};
use async_trait::async_trait;
use uuid::Uuid;

const COLUMNS: &str = "id, name, slug, logo, metadata, created_at";

#[async_trait]
impl OrganizationDataStore for PostgresStore {
    async fn raw_insert_organization(
        &self,
        organization: Organization,
    ) -> Result<Organization, AuthError> {
        sqlx::query("INSERT INTO lucid_auth_organizations (id, name, slug, logo, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(organization.id)
            .bind(&organization.name)
            .bind(&organization.slug)
            .bind(&organization.logo)
            .bind(&organization.metadata)
            .bind(organization.created_at)
            .execute(&self.pool)
            .await
            .map_err(storage_error)?;
        Ok(organization)
    }

    async fn raw_delete_organization(&self, id: Uuid) -> Result<(), AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_organization_members WHERE organization_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_organization_invitations WHERE organization_id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        sqlx::query("DELETE FROM lucid_auth_organizations WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)
    }

    async fn create_organization(
        &self,
        organization: Organization,
        owner: OrganizationMember,
        default_team: Option<(OrganizationTeam, OrganizationTeamMember)>,
        organization_limit: Option<usize>,
    ) -> Result<OrganizationCreateOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT id FROM lucid_auth_users WHERE id = $1 FOR UPDATE")
            .bind(owner.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&organization.slug)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM lucid_auth_organizations WHERE slug = $1)",
        )
        .bind(&organization.slug)
        .fetch_one(&mut *tx)
        .await
        .map_err(storage_error)?
        {
            return Ok(OrganizationCreateOutcome::SlugTaken);
        }
        if let Some(limit) = organization_limit {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM lucid_auth_organization_members WHERE user_id = $1",
            )
            .bind(owner.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            if count >= limit as i64 {
                return Ok(OrganizationCreateOutcome::LimitReached);
            }
        }
        sqlx::query("INSERT INTO lucid_auth_organizations (id, name, slug, logo, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
            .bind(organization.id).bind(&organization.name).bind(&organization.slug).bind(&organization.logo).bind(&organization.metadata).bind(organization.created_at)
            .execute(&mut *tx).await.map_err(storage_error)?;
        sqlx::query("INSERT INTO lucid_auth_organization_members (id, organization_id, user_id, role, created_at) VALUES ($1,$2,$3,$4,$5)")
            .bind(owner.id).bind(owner.organization_id).bind(owner.user_id).bind(&owner.role).bind(owner.created_at)
            .execute(&mut *tx).await.map_err(storage_error)?;
        if let Some((team, member)) = default_team {
            sqlx::query("INSERT INTO lucid_auth_organization_teams (id, name, organization_id, created_at, updated_at) VALUES ($1,$2,$3,$4,$5)")
                .bind(team.id).bind(&team.name).bind(team.organization_id).bind(team.created_at).bind(team.updated_at)
                .execute(&mut *tx).await.map_err(storage_error)?;
            sqlx::query("INSERT INTO lucid_auth_organization_team_members (id, team_id, user_id, created_at) VALUES ($1,$2,$3,$4)")
                .bind(member.id).bind(member.team_id).bind(member.user_id).bind(member.created_at)
                .execute(&mut *tx).await.map_err(storage_error)?;
        }
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationCreateOutcome::Created)
    }

    async fn find_organization_by_id(&self, id: Uuid) -> Result<Option<Organization>, AuthError> {
        sqlx::query_as::<_, OrganizationRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organizations WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn find_organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, AuthError> {
        sqlx::query_as::<_, OrganizationRow>(&format!(
            "SELECT {COLUMNS} FROM lucid_auth_organizations WHERE slug=$1"
        ))
        .bind(slug)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn list_organizations(&self, user_id: Uuid) -> Result<Vec<Organization>, AuthError> {
        sqlx::query_as::<_, OrganizationRow>(&format!("SELECT o.{columns} FROM lucid_auth_organizations o JOIN lucid_auth_organization_members m ON m.organization_id=o.id WHERE m.user_id=$1 ORDER BY o.created_at,o.id", columns=COLUMNS.replace(", ", ", o.")))
            .bind(user_id).fetch_all(&self.pool).await.map(|rows| rows.into_iter().map(Into::into).collect()).map_err(storage_error)
    }

    async fn update_organization(
        &self,
        organization: Organization,
    ) -> Result<Option<Organization>, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let exists = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM lucid_auth_organizations WHERE id=$1 FOR UPDATE",
        )
        .bind(organization.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        .is_some();
        if !exists {
            return Ok(None);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(&organization.slug)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        let result = sqlx::query_as::<_, OrganizationRow>(&format!("UPDATE lucid_auth_organizations SET name=$2,slug=$3,logo=$4,metadata=$5 WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM lucid_auth_organizations WHERE slug=$3 AND id<>$1) RETURNING {COLUMNS}"))
            .bind(organization.id).bind(organization.name).bind(organization.slug).bind(organization.logo).bind(organization.metadata)
            .fetch_optional(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(result.map(Into::into))
    }

    async fn delete_organization(&self, id: Uuid) -> Result<Option<Organization>, AuthError> {
        sqlx::query_as::<_, OrganizationRow>(&format!(
            "DELETE FROM lucid_auth_organizations WHERE id=$1 RETURNING {COLUMNS}"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }
}
