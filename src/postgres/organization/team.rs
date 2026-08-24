use super::{
    member::lock_organization,
    rows::{TeamMemberRow, TeamRow},
    storage_error,
};
use crate::{
    AuthError, OrganizationTeam, OrganizationTeamMember, OrganizationTeamStore,
    OrganizationTeamWriteOutcome, postgres::PostgresStore,
};
use async_trait::async_trait;
use uuid::Uuid;

const TEAM_COLUMNS: &str = "id, name, organization_id, created_at, updated_at";
const MEMBER_COLUMNS: &str = "id, team_id, user_id, created_at";

#[async_trait]
impl OrganizationTeamStore for PostgresStore {
    async fn create_team(
        &self,
        team: OrganizationTeam,
        maximum_teams: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut tx, team.organization_id).await?;
        if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM lucid_auth_organization_teams WHERE organization_id=$1 AND name=$2)").bind(team.organization_id).bind(&team.name).fetch_one(&mut *tx).await.map_err(storage_error)? {
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if let Some(limit) = maximum_teams {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM lucid_auth_organization_teams WHERE organization_id=$1",
            )
            .bind(team.organization_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            if count >= limit as i64 {
                return Ok(OrganizationTeamWriteOutcome::LimitReached);
            }
        }
        sqlx::query("INSERT INTO lucid_auth_organization_teams (id,name,organization_id,created_at,updated_at) VALUES ($1,$2,$3,$4,$5)").bind(team.id).bind(team.name).bind(team.organization_id).bind(team.created_at).bind(team.updated_at).execute(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn find_team(&self, id: Uuid) -> Result<Option<OrganizationTeam>, AuthError> {
        sqlx::query_as::<_, TeamRow>(&format!(
            "SELECT {TEAM_COLUMNS} FROM lucid_auth_organization_teams WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map(|row| row.map(Into::into))
        .map_err(storage_error)
    }

    async fn list_teams(&self, organization_id: Uuid) -> Result<Vec<OrganizationTeam>, AuthError> {
        sqlx::query_as::<_, TeamRow>(&format!("SELECT {TEAM_COLUMNS} FROM lucid_auth_organization_teams WHERE organization_id=$1 ORDER BY created_at,id")).bind(organization_id).fetch_all(&self.pool).await.map(|rows| rows.into_iter().map(Into::into).collect()).map_err(storage_error)
    }

    async fn update_team(
        &self,
        team: OrganizationTeam,
    ) -> Result<Option<OrganizationTeam>, AuthError> {
        sqlx::query_as::<_, TeamRow>(&format!("UPDATE lucid_auth_organization_teams SET name=$2,updated_at=$3 WHERE id=$1 AND NOT EXISTS (SELECT 1 FROM lucid_auth_organization_teams WHERE organization_id=$4 AND name=$2 AND id<>$1) RETURNING {TEAM_COLUMNS}"))
            .bind(team.id).bind(team.name).bind(team.updated_at).bind(team.organization_id).fetch_optional(&self.pool).await.map(|row| row.map(Into::into)).map_err(storage_error)
    }

    async fn remove_team(
        &self,
        id: Uuid,
        allow_removing_all: bool,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        let Some(team) = sqlx::query_as::<_, TeamRow>(&format!(
            "SELECT {TEAM_COLUMNS} FROM lucid_auth_organization_teams WHERE id=$1"
        ))
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(storage_error)?
        else {
            return Ok(OrganizationTeamWriteOutcome::NotFound);
        };
        lock_organization(&mut tx, team.organization_id).await?;
        if !allow_removing_all {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM lucid_auth_organization_teams WHERE organization_id=$1",
            )
            .bind(team.organization_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            if count <= 1 {
                return Ok(OrganizationTeamWriteOutcome::LastTeam);
            }
        }
        sqlx::query("DELETE FROM lucid_auth_organization_teams WHERE id=$1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(storage_error)?;
        remove_team_from_invitations(&mut tx, team.organization_id, id).await?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn add_team_member(
        &self,
        member: OrganizationTeamMember,
        maximum_members: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let mut tx = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT id FROM lucid_auth_organization_teams WHERE id=$1 FOR UPDATE")
            .bind(member.team_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
        if sqlx::query_scalar::<_, bool>("SELECT EXISTS (SELECT 1 FROM lucid_auth_organization_team_members WHERE team_id=$1 AND user_id=$2)").bind(member.team_id).bind(member.user_id).fetch_one(&mut *tx).await.map_err(storage_error)? {
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if let Some(limit) = maximum_members {
            let count = sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM lucid_auth_organization_team_members WHERE team_id=$1",
            )
            .bind(member.team_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(storage_error)?;
            if count >= limit as i64 {
                return Ok(OrganizationTeamWriteOutcome::LimitReached);
            }
        }
        sqlx::query("INSERT INTO lucid_auth_organization_team_members (id,team_id,user_id,created_at) VALUES ($1,$2,$3,$4)").bind(member.id).bind(member.team_id).bind(member.user_id).bind(member.created_at).execute(&mut *tx).await.map_err(storage_error)?;
        tx.commit().await.map_err(storage_error)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn remove_team_member(
        &self,
        team_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let result = sqlx::query(
            "DELETE FROM lucid_auth_organization_team_members WHERE team_id=$1 AND user_id=$2",
        )
        .bind(team_id)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;
        Ok(if result.rows_affected() == 0 {
            OrganizationTeamWriteOutcome::NotFound
        } else {
            OrganizationTeamWriteOutcome::Written
        })
    }

    async fn list_team_members(
        &self,
        team_id: Uuid,
    ) -> Result<Vec<OrganizationTeamMember>, AuthError> {
        sqlx::query_as::<_, TeamMemberRow>(&format!("SELECT {MEMBER_COLUMNS} FROM lucid_auth_organization_team_members WHERE team_id=$1 ORDER BY created_at,id")).bind(team_id).fetch_all(&self.pool).await.map(|rows| rows.into_iter().map(Into::into).collect()).map_err(storage_error)
    }

    async fn list_user_teams(&self, user_id: Uuid) -> Result<Vec<OrganizationTeam>, AuthError> {
        sqlx::query_as::<_, TeamRow>("SELECT t.id,t.name,t.organization_id,t.created_at,t.updated_at FROM lucid_auth_organization_teams t JOIN lucid_auth_organization_team_members m ON m.team_id=t.id WHERE m.user_id=$1 ORDER BY t.created_at,t.id").bind(user_id).fetch_all(&self.pool).await.map(|rows| rows.into_iter().map(Into::into).collect()).map_err(storage_error)
    }
}

async fn remove_team_from_invitations(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    team_id: Uuid,
) -> Result<(), AuthError> {
    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as("SELECT id,team_id FROM lucid_auth_organization_invitations WHERE organization_id=$1 AND status='pending' AND team_id IS NOT NULL FOR UPDATE").bind(organization_id).fetch_all(&mut **tx).await.map_err(storage_error)?;
    for (id, team_ids) in rows {
        let remaining = team_ids
            .unwrap_or_default()
            .split(',')
            .filter(|candidate| *candidate != team_id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query("UPDATE lucid_auth_organization_invitations SET team_id=$2 WHERE id=$1")
            .bind(id)
            .bind((!remaining.is_empty()).then_some(remaining))
            .execute(&mut **tx)
            .await
            .map_err(storage_error)?;
    }
    Ok(())
}
