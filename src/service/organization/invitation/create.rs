use super::super::AuthService;
use super::support::{
    has_role, member_not_found, normalize_roles, organization_not_found, require_permission,
    validate_teams,
};
use crate::service::email_password::normalize_email;
use crate::{
    AuthError, NewOrganizationInvitation, OrganizationError, OrganizationInvitation,
    OrganizationInvitationEmail, OrganizationInvitationStatus, OrganizationInvitationWriteOutcome,
    SessionWithUser,
};
use chrono::{Duration, Utc};

impl AuthService {
    pub async fn invite_organization_member(
        &self,
        session: &SessionWithUser,
        input: NewOrganizationInvitation,
    ) -> Result<OrganizationInvitation, AuthError> {
        let organization_id = input
            .organization_id
            .clone()
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(organization_not_found)?;
        let plugin = self.organization_plugin()?;
        let inviter = plugin
            .store
            .find_member(&organization_id, &session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        require_permission(self, &inviter, "create").await?;
        let email = normalize_email(&input.email)?;
        let role = normalize_roles(&input.role);
        validate_invited_role(self, &inviter, &organization_id, &role).await?;
        if let Some(user) = self.store.find_user_by_email(&email).await?
            && plugin
                .store
                .find_member(&organization_id, &user.id)
                .await?
                .is_some()
        {
            return Err(OrganizationError::bad_request(
                "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
                "User is already a member of this organization",
            )
            .into());
        }
        validate_teams(plugin, &organization_id, &input.team_ids).await?;
        let organization = plugin
            .store
            .find_organization_by_id(&organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if input.resend
            && let Some(invitation) = plugin
                .store
                .resend_invitation(
                    &organization_id,
                    &email,
                    Utc::now() + Duration::seconds(plugin.config.invitation_expires_in_seconds),
                )
                .await?
        {
            send_invitation(plugin, invitation.clone(), organization, inviter, session).await?;
            return Ok(invitation);
        }
        let mut invitation = new_invitation(plugin, session, input, organization_id, email, role);
        if let Some(hooks) = &plugin.config.hooks {
            invitation = hooks
                .before_create_invitation(invitation, &session.user, &organization)
                .await?;
        }
        persist_invitation(self, plugin, &mut invitation).await?;
        self.observe_member_invited(&organization, &invitation, &session.user)
            .await;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_create_invitation(&invitation, &session.user, &organization)
                .await?;
        }
        send_invitation(plugin, invitation.clone(), organization, inviter, session).await?;
        Ok(invitation)
    }
}

async fn send_invitation(
    plugin: &crate::OrganizationPlugin,
    invitation: OrganizationInvitation,
    organization: crate::Organization,
    inviter: crate::OrganizationMember,
    session: &SessionWithUser,
) -> Result<(), AuthError> {
    if let Some(sender) = &plugin.config.invitation_email_sender {
        sender
            .send(OrganizationInvitationEmail {
                invitation,
                organization,
                inviter,
                inviter_user: session.user.clone(),
            })
            .await?;
    }
    Ok(())
}

async fn validate_invited_role(
    service: &AuthService,
    inviter: &crate::OrganizationMember,
    organization_id: &str,
    role: &str,
) -> Result<(), AuthError> {
    let plugin = service.organization_plugin()?;
    if role.is_empty()
        || !service
            .organization_role_exists(organization_id, role)
            .await?
    {
        return Err(OrganizationError::bad_request("ROLE_NOT_FOUND", "Role not found").into());
    }
    if has_role(role, &plugin.config.creator_role)
        && !has_role(&inviter.role, &plugin.config.creator_role)
    {
        return Err(OrganizationError::forbidden(
            "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE",
            "You are not allowed to invite a user with this role",
        )
        .into());
    }
    Ok(())
}

fn new_invitation(
    plugin: &crate::OrganizationPlugin,
    session: &SessionWithUser,
    input: NewOrganizationInvitation,
    organization_id: String,
    email: String,
    role: String,
) -> OrganizationInvitation {
    let now = Utc::now();
    OrganizationInvitation {
        id: String::new(),
        organization_id,
        email,
        role,
        status: OrganizationInvitationStatus::Pending,
        team_id: (!input.team_ids.is_empty()).then(|| input.team_ids.join(",")),
        inviter_id: session.user.id.clone(),
        expires_at: now + Duration::seconds(plugin.config.invitation_expires_in_seconds),
        created_at: now,
    }
}

async fn persist_invitation(
    service: &AuthService,
    plugin: &crate::OrganizationPlugin,
    invitation: &mut OrganizationInvitation,
) -> Result<(), AuthError> {
    let plan = service.database_id_plan("invitation", crate::DatabaseIdInput::Absent, false);
    let id = || plan.prepare(service.store.as_ref());
    match plugin
        .store
        .create_invitation(
            invitation,
            &id,
            plugin.config.invitation_limit,
            plugin.config.membership_limit,
            plugin.config.cancel_pending_invitations_on_reinvite,
        )
        .await?
    {
        OrganizationInvitationWriteOutcome::Written => Ok(()),
        OrganizationInvitationWriteOutcome::AlreadyInvited => Err(OrganizationError::bad_request(
            "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION",
            "User is already invited to this organization",
        )
        .into()),
        OrganizationInvitationWriteOutcome::LimitReached => Err(OrganizationError::forbidden(
            "INVITATION_LIMIT_REACHED",
            "Invitation limit reached",
        )
        .into()),
        _ => Err(organization_not_found()),
    }
}
