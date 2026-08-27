use super::{active_or, require_team_permission, team_not_found};
use crate::{
    AuthError, AuthService, OrganizationError, OrganizationTeam, OrganizationTeamWriteOutcome,
    SessionWithUser,
};
use chrono::Utc;

impl AuthService {
    pub async fn create_organization_team(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        name: String,
    ) -> Result<OrganizationTeam, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let member = plugin
            .store
            .find_member(&organization_id, &session.user.id)
            .await?
            .ok_or_else(|| {
                OrganizationError::forbidden(
                    "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION",
                    "You are not allowed to invite users to this organization",
                )
            })?;
        require_team_permission(
            self,
            &member,
            "create",
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION",
            "You are not allowed to create teams in this organization",
        )
        .await?;
        let now = Utc::now();
        let organization = plugin
            .store
            .find_organization_by_id(&organization_id)
            .await?
            .ok_or_else(team_not_found)?;
        let mut team = OrganizationTeam {
            id: String::new(),
            name,
            organization_id,
            created_at: now,
            updated_at: Some(now),
        };
        if let Some(hooks) = &plugin.config.hooks {
            team = hooks
                .before_create_team(team, &session.user, &organization)
                .await?;
        }
        let input = if team.id.is_empty() {
            crate::DatabaseIdInput::Absent
        } else {
            crate::DatabaseIdInput::String(team.id.clone())
        };
        let plan = self.database_id_plan("team", input, true);
        let id = || plan.prepare(self.store.as_ref());
        match plugin
            .store
            .create_team(&mut team, &id, plugin.config.teams.maximum_teams)
            .await?
        {
            OrganizationTeamWriteOutcome::Written => {
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_create_team(&team, &session.user, &organization)
                        .await?;
                }
                Ok(team)
            }
            OrganizationTeamWriteOutcome::AlreadyExists => Err(OrganizationError::bad_request(
                "TEAM_ALREADY_EXISTS",
                "Team already exists",
            )
            .into()),
            OrganizationTeamWriteOutcome::LimitReached => Err(OrganizationError::bad_request(
                "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS",
                "You have reached the maximum number of teams",
            )
            .into()),
            _ => Err(team_not_found()),
        }
    }

    pub async fn update_organization_team(
        &self,
        session: &SessionWithUser,
        team_id: String,
        name: Option<String>,
    ) -> Result<OrganizationTeam, AuthError> {
        let plugin = self.organization_plugin()?;
        let mut team = plugin
            .store
            .find_team(&team_id)
            .await?
            .ok_or_else(team_not_found)?;
        let member = plugin
            .store
            .find_member(&team.organization_id, &session.user.id)
            .await?
            .ok_or_else(team_not_found)?;
        require_team_permission(
            self,
            &member,
            "update",
            "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM",
            "You are not allowed to update this team",
        )
        .await?;
        if let Some(name) = name {
            team.name = name;
        }
        team.updated_at = Some(Utc::now());
        let organization = plugin
            .store
            .find_organization_by_id(&team.organization_id)
            .await?
            .ok_or_else(team_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            team = hooks
                .before_update_team(team, &session.user, &organization)
                .await?;
        }
        let updated = plugin.store.update_team(team).await?.ok_or_else(|| {
            AuthError::from(OrganizationError::bad_request(
                "TEAM_ALREADY_EXISTS",
                "Team already exists",
            ))
        })?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_update_team(&updated, &session.user, &organization)
                .await?;
        }
        Ok(updated)
    }

    pub async fn remove_organization_team(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
        team_id: String,
    ) -> Result<(), AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let team = plugin
            .store
            .find_team(&team_id)
            .await?
            .filter(|team| team.organization_id == organization_id)
            .ok_or_else(team_not_found)?;
        let member = plugin
            .store
            .find_member(&organization_id, &session.user.id)
            .await?
            .ok_or_else(team_not_found)?;
        if Self::active_team_id(session) == Some(team.id.clone()) {
            return Err(OrganizationError::forbidden(
                "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM",
                "You are not allowed to delete this team",
            )
            .into());
        }
        require_team_permission(
            self,
            &member,
            "delete",
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION",
            "You are not allowed to delete teams in this organization",
        )
        .await?;
        let organization = plugin
            .store
            .find_organization_by_id(&organization_id)
            .await?
            .ok_or_else(team_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_delete_team(&team, &session.user, &organization)
                .await?;
        }
        match plugin
            .store
            .remove_team(&team_id, plugin.config.teams.allow_removing_all_teams)
            .await?
        {
            OrganizationTeamWriteOutcome::Written => {
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_delete_team(&team, &session.user, &organization)
                        .await?;
                }
                Ok(())
            }
            OrganizationTeamWriteOutcome::LastTeam => Err(OrganizationError::bad_request(
                "UNABLE_TO_REMOVE_LAST_TEAM",
                "Unable to remove last team",
            )
            .into()),
            _ => Err(team_not_found()),
        }
    }

    pub async fn list_organization_teams(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
    ) -> Result<Vec<OrganizationTeam>, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        if plugin
            .store
            .find_member(&organization_id, &session.user.id)
            .await?
            .is_none()
        {
            return Err(OrganizationError::forbidden(
                "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION",
                "You are not allowed to access this organization as an owner",
            )
            .into());
        }
        plugin.store.list_teams(&organization_id).await
    }

    pub async fn set_active_organization_team(
        &self,
        session: &SessionWithUser,
        team_id: Option<String>,
    ) -> Result<Option<OrganizationTeam>, AuthError> {
        let Some(team_id) = team_id else {
            self.set_active_team(session, None).await?;
            return Ok(None);
        };
        let organization_id = Self::active_organization_id(session).ok_or_else(|| {
            OrganizationError::bad_request("NO_ACTIVE_ORGANIZATION", "No active organization")
        })?;
        let plugin = self.organization_plugin()?;
        let team = plugin
            .store
            .find_team(&team_id)
            .await?
            .filter(|team| team.organization_id == organization_id)
            .ok_or_else(team_not_found)?;
        if !plugin
            .store
            .list_team_members(&team_id)
            .await?
            .iter()
            .any(|member| member.user_id == session.user.id)
        {
            return Err(OrganizationError::forbidden(
                "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
                "User is not a member of the team",
            )
            .into());
        }
        self.set_active_team(session, Some(team_id)).await?;
        Ok(Some(team))
    }
}
