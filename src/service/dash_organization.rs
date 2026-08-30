use super::AuthService;
use crate::{
    AuthError, NewOrganization, OrganizationCreation, OrganizationError, OrganizationMember,
    OrganizationMemberWriteOutcome, SessionWithUser,
};
use chrono::Utc;

impl AuthService {
    pub(crate) async fn dash_delete_organization(
        &self,
        organization_id: &str,
    ) -> Result<crate::Organization, AuthError> {
        let plugin = self.organization_plugin()?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(|| dash_not_found("Organization not found"))?;
        let mut owners = plugin
            .store
            .list_members(organization_id)
            .await?
            .into_iter()
            .filter(|member| member.role == "owner")
            .collect::<Vec<_>>();
        owners.sort_by_key(|member| member.created_at);
        let owner = owners
            .first()
            .ok_or_else(|| dash_not_found("Organization owner not found"))?;
        let user = self
            .store
            .find_user_by_id(&owner.user_id)
            .await?
            .ok_or_else(|| dash_not_found("Organization owner not found"))?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks.before_delete(&organization, &user).await?;
        }
        let deleted = plugin
            .store
            .delete_organization(organization_id)
            .await?
            .ok_or_else(|| dash_not_found("Organization not found"))?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks.after_delete(&deleted, &user).await?;
        }
        Ok(deleted)
    }

    pub(crate) async fn create_dash_organization(
        &self,
        session: &SessionWithUser,
        input: NewOrganization,
        default_team_name: Option<String>,
        skip_default_team: bool,
    ) -> Result<OrganizationCreation, AuthError> {
        self.create_organization_with_options(
            session,
            input,
            default_team_name,
            skip_default_team,
            false,
        )
        .await
    }

    pub(crate) async fn dash_add_organization_member(
        &self,
        organization_id: &str,
        user_id: &str,
        role: String,
    ) -> Result<OrganizationMember, AuthError> {
        let plugin = self.organization_plugin()?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(|| dash_not_found("Organization not found"))?;
        let user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or_else(|| dash_not_found("User not found"))?;
        let mut member = OrganizationMember {
            id: String::new(),
            organization_id: organization_id.to_owned(),
            user_id: user_id.to_owned(),
            role,
            created_at: Utc::now(),
        };
        if let Some(hooks) = &plugin.config.hooks {
            member = hooks
                .before_add_member(member, &user, &organization)
                .await?;
        }
        let plan = self.database_id_plan("member", crate::DatabaseIdInput::Absent, false);
        let id = || plan.prepare(self.store.as_ref());
        match plugin
            .store
            .add_member(&mut member, &id, plugin.config.membership_limit)
            .await?
        {
            OrganizationMemberWriteOutcome::Written => {
                self.observe_member_added(&organization, &member, &user).await;
                if let Some(hooks) = &plugin.config.hooks {
                    hooks.after_add_member(&member, &user, &organization).await?;
                }
                Ok(member)
            }
            OrganizationMemberWriteOutcome::AlreadyMember => Err(OrganizationError::bad_request(
                "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                "User is already a member of this organization",
            )
            .into()),
            OrganizationMemberWriteOutcome::LimitReached => Err(OrganizationError::bad_request(
                "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
                "Organization membership limit reached",
            )
            .into()),
            _ => Err(dash_not_found("Organization not found")),
        }
    }

    pub(crate) async fn dash_remove_organization_member(
        &self,
        organization_id: &str,
        member_id: &str,
    ) -> Result<OrganizationMember, AuthError> {
        let plugin = self.organization_plugin()?;
        let member = plugin
            .store
            .find_member_by_id(member_id)
            .await?
            .filter(|member| member.organization_id == organization_id)
            .ok_or_else(|| dash_not_found("Member not found"))?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(|| dash_not_found("Organization not found"))?;
        let user = self
            .store
            .find_user_by_id(&member.user_id)
            .await?
            .ok_or_else(|| dash_not_found("User not found or is not associated with this member"))?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_remove_member(&member, &user, &organization)
                .await?;
        }
        match plugin.store.remove_member(member_id, "\0").await? {
            OrganizationMemberWriteOutcome::Written => {}
            _ => return Err(dash_not_found("Member not found")),
        }
        self.observe_member_removed(&organization, &member, &user).await;
        if let Some(hooks) = &plugin.config.hooks {
            hooks.after_remove_member(&member, &user, &organization).await?;
        }
        Ok(member)
    }

    pub(crate) async fn dash_update_organization_member_role(
        &self,
        organization_id: &str,
        member_id: &str,
        role: String,
    ) -> Result<OrganizationMember, AuthError> {
        let plugin = self.organization_plugin()?;
        let existing = plugin
            .store
            .find_member_by_id(member_id)
            .await?
            .filter(|member| member.organization_id == organization_id)
            .ok_or_else(|| dash_not_found("Member not found"))?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(|| dash_not_found("Organization not found"))?;
        let user = self
            .store
            .find_user_by_id(&existing.user_id)
            .await?
            .ok_or_else(|| dash_not_found("User not found or is not associated with this member"))?;
        let previous_role = existing.role.clone();
        let role = match &plugin.config.hooks {
            Some(hooks) => hooks
                .before_update_member_role(role, &existing, &user, &organization)
                .await?,
            None => role,
        };
        match plugin.store.update_member_role(member_id, role, "\0").await? {
            OrganizationMemberWriteOutcome::Written => {}
            _ => {
                return Err(AuthError::Storage(
                    "Failed to update member role".into(),
                ));
            }
        }
        let member = plugin
            .store
            .find_member_by_id(member_id)
            .await?
            .ok_or_else(|| AuthError::Storage("Failed to update member role".into()))?;
        self.observe_member_role_updated(&organization, &member, &previous_role, &user)
            .await;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_update_member_role(&member, &previous_role, &user, &organization)
                .await?;
        }
        Ok(member)
    }
}

fn dash_not_found(message: &'static str) -> AuthError {
    OrganizationError::not_found("NOT_FOUND", message).into()
}
