use super::AuthService;
use crate::{
    AuthError, OrganizationError, OrganizationMember, OrganizationMemberWriteOutcome,
    OrganizationPermissions, SessionWithUser,
};
use std::collections::BTreeMap;
use uuid::Uuid;

impl AuthService {
    pub async fn active_organization_member(
        &self,
        session: &SessionWithUser,
    ) -> Result<OrganizationMember, AuthError> {
        let organization_id = Self::active_organization_id(session).ok_or_else(no_active)?;
        self.organization_plugin()?
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(member_not_found)
    }

    pub async fn list_organization_members(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<OrganizationMember>, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(no_active)?;
        let plugin = self.organization_plugin()?;
        if plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .is_none()
        {
            return Err(not_member());
        }
        plugin.store.list_members(organization_id).await
    }

    pub async fn list_organization_members_with_users(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<crate::OrganizationMemberWithUser>, AuthError> {
        let members = self
            .list_organization_members(session, organization_id)
            .await?;
        let mut output = Vec::with_capacity(members.len());
        for member in members {
            if let Some(user) = self.store.find_user_by_id(member.user_id).await? {
                output.push(crate::OrganizationMemberWithUser { member, user });
            }
        }
        Ok(output)
    }

    pub async fn update_organization_member_role(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
        member_id: Uuid,
        role: String,
    ) -> Result<OrganizationMember, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(no_active)?;
        let plugin = self.organization_plugin()?;
        let actor = plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        let target = plugin
            .store
            .find_member_by_id(member_id)
            .await?
            .filter(|member| member.organization_id == organization_id)
            .ok_or_else(member_not_found)?;
        let mut role = normalize_roles(&role);
        validate_member_role(self, organization_id, &role).await?;
        let actor_is_creator = has_role(&actor.role, &plugin.config.creator_role);
        if (has_role(&target.role, &plugin.config.creator_role)
            || has_role(&role, &plugin.config.creator_role))
            && !actor_is_creator
        {
            return Err(not_allowed_update());
        }
        require_member_permission(self, &actor, "update", true).await?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(no_active)?;
        let target_user = self
            .store
            .find_user_by_id(target.user_id)
            .await?
            .ok_or_else(|| AuthError::InvalidRequest("User not found".into()))?;
        if let Some(hooks) = &plugin.config.hooks {
            role = hooks
                .before_update_member_role(role, &target, &target_user, &organization)
                .await?;
        }
        validate_member_role(self, organization_id, &role).await?;
        let previous_role = target.role.clone();
        match plugin
            .store
            .update_member_role(member_id, role, &plugin.config.creator_role)
            .await?
        {
            OrganizationMemberWriteOutcome::Written => {
                let member = plugin
                    .store
                    .find_member_by_id(member_id)
                    .await?
                    .ok_or_else(member_not_found)?;
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_update_member_role(
                            &member,
                            &previous_role,
                            &target_user,
                            &organization,
                        )
                        .await?;
                }
                Ok(member)
            }
            OrganizationMemberWriteOutcome::LastOwner => Err(last_owner()),
            _ => Err(member_not_found()),
        }
    }

    pub async fn remove_organization_member(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
        member_id_or_email: &str,
    ) -> Result<OrganizationMember, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(no_active)?;
        let plugin = self.organization_plugin()?;
        let actor = plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        require_member_permission(self, &actor, "delete", false).await?;
        let target = if member_id_or_email.contains('@') {
            match self.store.find_user_by_email(member_id_or_email).await? {
                Some(user) => plugin.store.find_member(organization_id, user.id).await?,
                None => None,
            }
        } else {
            match Uuid::parse_str(member_id_or_email) {
                Ok(id) => plugin
                    .store
                    .find_member_by_id(id)
                    .await?
                    .filter(|member| member.organization_id == organization_id),
                Err(_) => None,
            }
        }
        .ok_or_else(member_not_found)?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(no_active)?;
        let target_user = self
            .store
            .find_user_by_id(target.user_id)
            .await?
            .ok_or_else(|| AuthError::InvalidRequest("User not found".into()))?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_remove_member(&target, &target_user, &organization)
                .await?;
        }
        match plugin
            .store
            .remove_member(target.id, &plugin.config.creator_role)
            .await?
        {
            OrganizationMemberWriteOutcome::Written => {
                if target.user_id == session.user.id
                    && Self::active_organization_id(session) == Some(organization_id)
                {
                    self.set_active_organization(session, None).await?;
                }
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_remove_member(&target, &target_user, &organization)
                        .await?;
                }
                if let Some(stripe) = self.organization_stripe_plugin() {
                    stripe
                        .after_organization_member_change(&organization, plugin.store.as_ref())
                        .await;
                }
                Ok(target)
            }
            OrganizationMemberWriteOutcome::LastOwner => Err(last_owner()),
            _ => Err(member_not_found()),
        }
    }

    pub async fn leave_organization(
        &self,
        session: &SessionWithUser,
        organization_id: Uuid,
    ) -> Result<OrganizationMember, AuthError> {
        let plugin = self.organization_plugin()?;
        let member = plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        let organization = plugin
            .store
            .find_organization_by_id(organization_id)
            .await?
            .ok_or_else(no_active)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_remove_member(&member, &session.user, &organization)
                .await?;
        }
        match plugin
            .store
            .remove_member(member.id, &plugin.config.creator_role)
            .await?
        {
            OrganizationMemberWriteOutcome::Written => {
                if Self::active_organization_id(session) == Some(organization_id) {
                    self.set_active_organization(session, None).await?;
                }
                if let Some(hooks) = &plugin.config.hooks {
                    hooks
                        .after_remove_member(&member, &session.user, &organization)
                        .await?;
                }
                if let Some(stripe) = self.organization_stripe_plugin() {
                    stripe
                        .after_organization_member_change(&organization, plugin.store.as_ref())
                        .await;
                }
                Ok(member)
            }
            OrganizationMemberWriteOutcome::LastOwner => Err(last_owner()),
            _ => Err(member_not_found()),
        }
    }

    pub async fn organization_member_role(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
        user_id: Option<Uuid>,
    ) -> Result<String, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(no_active)?;
        let plugin = self.organization_plugin()?;
        if plugin
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .is_none()
        {
            return Err(not_member());
        }
        plugin
            .store
            .find_member(organization_id, user_id.unwrap_or(session.user.id))
            .await?
            .map(|member| member.role)
            .ok_or_else(not_member)
    }

    pub async fn has_organization_permission(
        &self,
        session: &SessionWithUser,
        organization_id: Option<Uuid>,
        permissions: OrganizationPermissions,
    ) -> Result<bool, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(no_active)?;
        let member = self
            .organization_plugin()?
            .store
            .find_member(organization_id, session.user.id)
            .await?
            .ok_or_else(|| {
                OrganizationError::unauthorized(
                    "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION",
                    "User is not a member of the organization",
                )
            })?;
        self.organization_has_permission(&member, &permissions, false)
            .await
    }
}

async fn validate_member_role(
    service: &AuthService,
    organization_id: Uuid,
    role: &str,
) -> Result<(), AuthError> {
    if role.is_empty()
        || !service
            .organization_role_exists(organization_id, role)
            .await?
    {
        Err(OrganizationError::bad_request("ROLE_NOT_FOUND", "Role not found").into())
    } else {
        Ok(())
    }
}

async fn require_member_permission(
    service: &AuthService,
    member: &OrganizationMember,
    action: &str,
    allow_creator_all: bool,
) -> Result<(), AuthError> {
    let permissions = BTreeMap::from([("member".into(), vec![action.into()])]);
    if service
        .organization_has_permission(member, &permissions, allow_creator_all)
        .await?
    {
        Ok(())
    } else if action == "delete" {
        Err(OrganizationError::unauthorized(
            "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER",
            "You are not allowed to delete this member",
        )
        .into())
    } else {
        Err(not_allowed_update())
    }
}

fn normalize_roles(role: &str) -> String {
    role.split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

fn has_role(roles: &str, expected: &str) -> bool {
    roles.split(',').map(str::trim).any(|role| role == expected)
}

fn no_active() -> AuthError {
    OrganizationError::bad_request("NO_ACTIVE_ORGANIZATION", "No active organization").into()
}

fn member_not_found() -> AuthError {
    OrganizationError::bad_request("MEMBER_NOT_FOUND", "Member not found").into()
}

fn not_member() -> AuthError {
    OrganizationError::forbidden(
        "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
        "You are not a member of this organization",
    )
    .into()
}

fn last_owner() -> AuthError {
    OrganizationError::bad_request(
        "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER",
        "You cannot leave the organization as the only owner",
    )
    .into()
}

fn not_allowed_update() -> AuthError {
    OrganizationError::forbidden(
        "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER",
        "You are not allowed to update this member",
    )
    .into()
}
