use super::{active_or, member_not_found, require_member_update, team_not_found};
use crate::{
    AuthError, AuthService, OrganizationError, OrganizationTeam, OrganizationTeamMember,
    OrganizationTeamWriteOutcome, SessionWithUser,
};
use chrono::Utc;
use uuid::Uuid;

impl AuthService {
    pub async fn list_user_organization_teams(
        &self,
        session: &SessionWithUser,
        user_id: Option<Uuid>,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<OrganizationTeam>, AuthError> {
        let plugin = self.organization_plugin()?;
        let target = user_id.unwrap_or(session.user.id);
        if target != session.user.id {
            let organization_id = active_or(session, organization_id)?;
            let actor = plugin
                .store
                .find_member(organization_id, session.user.id)
                .await?
                .ok_or_else(member_not_found)?;
            require_member_update(
                self,
                &actor,
                "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
                "You are not allowed to update this member",
            )
            .await?;
            if plugin
                .store
                .find_member(organization_id, target)
                .await?
                .is_none()
            {
                return Err(member_not_found());
            }
        } else if let Some(organization_id) = organization_id
            && plugin
                .store
                .find_member(organization_id, target)
                .await?
                .is_none()
        {
            return Err(member_not_found());
        }
        let mut teams = plugin.store.list_user_teams(target).await?;
        if let Some(organization_id) = organization_id {
            teams.retain(|team| team.organization_id == organization_id);
        }
        Ok(teams)
    }

    pub async fn list_organization_team_members(
        &self,
        session: &SessionWithUser,
        team_id: Option<Uuid>,
    ) -> Result<Vec<OrganizationTeamMember>, AuthError> {
        let team_id = team_id
            .or_else(|| Self::active_team_id(session))
            .ok_or_else(|| {
                OrganizationError::bad_request(
                    "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM",
                    "You do not have an active team",
                )
            })?;
        let plugin = self.organization_plugin()?;
        let team = plugin
            .store
            .find_team(team_id)
            .await?
            .ok_or_else(team_not_found)?;
        let organization_member = plugin
            .store
            .find_member(team.organization_id, session.user.id)
            .await?;
        let team_member = plugin
            .store
            .list_team_members(team_id)
            .await?
            .iter()
            .any(|member| member.user_id == session.user.id);
        if organization_member.is_none() || !team_member {
            return Err(OrganizationError::bad_request(
                "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
                "User is not a member of the team",
            )
            .into());
        }
        plugin.store.list_team_members(team_id).await
    }

    pub async fn add_organization_team_member(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
        team_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationTeamMember, AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let actor = plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        require_member_update(
            self,
            &actor,
            "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER",
            "You are not allowed to create a new member",
        )
        .await?;
        require_target_and_team(plugin, organization_id, team_id, user_id).await?;
        let team = plugin
            .store
            .find_team(team_id)
            .await?
            .ok_or_else(team_not_found)?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(team_not_found)?;
        let target_user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::InvalidRequest("User not found".into()))?;
        let mut team_member = OrganizationTeamMember {
            id: Uuid::new_v4(),
            team_id,
            user_id,
            created_at: Utc::now(),
        };
        if let Some(hooks) = &plugin.config.hooks {
            team_member = hooks
                .before_add_team_member(team_member, &team, &target_user, &organization)
                .await?;
        }
        match plugin
            .store
            .add_team_member(
                team_member.clone(),
                plugin.config.teams.maximum_members_per_team,
            )
            .await?
        {
            OrganizationTeamWriteOutcome::Written => {
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_add_team_member(&team_member, &team, &target_user, &organization)
                        .await?;
                }
                Ok(team_member)
            }
            OrganizationTeamWriteOutcome::AlreadyExists => Ok(plugin
                .store
                .list_team_members(team_id)
                .await?
                .into_iter()
                .find(|member| member.user_id == user_id)
                .expect("existing team member")),
            OrganizationTeamWriteOutcome::LimitReached => Err(OrganizationError::forbidden(
                "TEAM_MEMBER_LIMIT_REACHED",
                "Team member limit reached",
            )
            .into()),
            _ => Err(team_not_found()),
        }
    }

    pub async fn remove_organization_team_member(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
        team_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        let organization_id = active_or(session, organization_id)?;
        let plugin = self.organization_plugin()?;
        let actor = plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        require_member_update(
            self,
            &actor,
            "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER",
            "You are not allowed to remove a team member",
        )
        .await?;
        require_target_and_team(plugin, organization_id, team_id, user_id).await?;
        let team = plugin
            .store
            .find_team(team_id)
            .await?
            .ok_or_else(team_not_found)?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(team_not_found)?;
        let team_member = plugin
            .store
            .list_team_members(team_id)
            .await?
            .into_iter()
            .find(|member| member.user_id == user_id)
            .ok_or_else(|| {
                OrganizationError::bad_request(
                    "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
                    "User is not a member of the team",
                )
            })?;
        let target_user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| AuthError::InvalidRequest("User not found".into()))?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_remove_team_member(&team_member, &team, &target_user, &organization)
                .await?;
        }
        match plugin.store.remove_team_member(team_id, user_id).await? {
            OrganizationTeamWriteOutcome::Written => {
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_remove_team_member(&team_member, &team, &target_user, &organization)
                        .await?;
                }
                Ok(())
            }
            _ => Err(OrganizationError::bad_request(
                "USER_IS_NOT_A_MEMBER_OF_THE_TEAM",
                "User is not a member of the team",
            )
            .into()),
        }
    }
}

async fn require_target_and_team(
    plugin: &crate::OrganizationPlugin,
    organization_id: Uuid,
    team_id: Uuid,
    user_id: Uuid,
) -> Result<(), AuthError> {
    if plugin
        .store
        .find_member(organization_id, user_id)
        .await?
        .is_none()
    {
        return Err(member_not_found());
    }
    if !plugin
        .store
        .find_team(team_id)
        .await?
        .is_some_and(|team| team.organization_id == organization_id)
    {
        return Err(team_not_found());
    }
    Ok(())
}
