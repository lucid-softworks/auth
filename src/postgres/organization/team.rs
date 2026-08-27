use super::{member::lock_organization, rows, storage_error};
use crate::{
    AuthError, OrganizationTeam, OrganizationTeamMember, OrganizationTeamStore,
    OrganizationTeamWriteOutcome, postgres::PostgresStore,
};
use async_trait::async_trait;

mod invitation;
mod query;

use invitation::remove_team_from_invitations;
use query::*;

#[async_trait]
impl OrganizationTeamStore for PostgresStore {
    async fn create_team(
        &self,
        team: &mut OrganizationTeam,
        id: &dyn crate::DatabaseIdSupplier,
        maximum_teams: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let organization = self.physical_model("organization")?;
        let model = self.physical_model("team")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_organization(&mut transaction, &organization, &team.organization_id).await?;
        if team_exists(&mut transaction, &model, &team.organization_id, &team.name).await? {
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if let Some(limit) = maximum_teams
            && team_count(&mut transaction, &model, &team.organization_id).await? >= limit as i64
        {
            return Ok(OrganizationTeamWriteOutcome::LimitReached);
        }
        let prepared = id.prepare()?;
        *team = insert_team(&mut transaction, &model, team, &prepared).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn find_team(&self, id: &str) -> Result<Option<OrganizationTeam>, AuthError> {
        let model = self.physical_model("team")?;
        find_team(&self.pool, &model, id).await
    }

    async fn list_teams(&self, organization_id: &str) -> Result<Vec<OrganizationTeam>, AuthError> {
        let model = self.physical_model("team")?;
        let mut query = list_teams_query(&model, organization_id)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| rows::decode_team(&model, row))
            .collect()
    }

    async fn update_team(
        &self,
        team: OrganizationTeam,
    ) -> Result<Option<OrganizationTeam>, AuthError> {
        let model = self.physical_model("team")?;
        let mut query = update_team_query(&model, &team)?;
        query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(storage_error)?
            .as_ref()
            .map(|row| rows::decode_team(&model, row))
            .transpose()
    }

    async fn remove_team(
        &self,
        id: &str,
        allow_removing_all: bool,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let organization = self.physical_model("organization")?;
        let team_model = self.physical_model("team")?;
        let invitation_model = self.physical_model("invitation")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        let Some(team) = find_team(&mut *transaction, &team_model, id).await? else {
            return Ok(OrganizationTeamWriteOutcome::NotFound);
        };
        lock_organization(&mut transaction, &organization, &team.organization_id).await?;
        if !allow_removing_all
            && team_count(&mut transaction, &team_model, &team.organization_id).await? <= 1
        {
            return Ok(OrganizationTeamWriteOutcome::LastTeam);
        }
        delete_team(&mut transaction, &team_model, id).await?;
        remove_team_from_invitations(
            &mut transaction,
            &invitation_model,
            &team.organization_id,
            id,
        )
        .await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn add_team_member(
        &self,
        member: &mut OrganizationTeamMember,
        id: &dyn crate::DatabaseIdSupplier,
        maximum_members: Option<usize>,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let team = self.physical_model("team")?;
        let model = self.physical_model("teamMember")?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        lock_team(&mut transaction, &team, &member.team_id).await?;
        if team_member_exists(&mut transaction, &model, &member.team_id, &member.user_id).await? {
            return Ok(OrganizationTeamWriteOutcome::AlreadyExists);
        }
        if let Some(limit) = maximum_members
            && team_member_count(&mut transaction, &model, &member.team_id).await? >= limit as i64
        {
            return Ok(OrganizationTeamWriteOutcome::LimitReached);
        }
        let prepared = id.prepare()?;
        *member = insert_team_member(&mut transaction, &model, member, &prepared).await?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(OrganizationTeamWriteOutcome::Written)
    }

    async fn remove_team_member(
        &self,
        team_id: &str,
        user_id: &str,
    ) -> Result<OrganizationTeamWriteOutcome, AuthError> {
        let model = self.physical_model("teamMember")?;
        let mut query = delete_team_member_query(&model, team_id, user_id)?;
        let result = query
            .build()
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
        team_id: &str,
    ) -> Result<Vec<OrganizationTeamMember>, AuthError> {
        let model = self.physical_model("teamMember")?;
        let mut query = list_team_members_query(&model, team_id)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| rows::decode_team_member(&model, row))
            .collect()
    }

    async fn list_user_teams(&self, user_id: &str) -> Result<Vec<OrganizationTeam>, AuthError> {
        let team = self.physical_model("team")?;
        let member = self.physical_model("teamMember")?;
        let mut query = list_user_teams_query(&team, &member, user_id)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| rows::decode_team(&team, row))
            .collect()
    }
}
