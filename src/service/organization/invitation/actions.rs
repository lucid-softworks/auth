use super::super::AuthService;
use super::support::{
    invitation_not_found, inviter_missing, member_not_found, organization_not_found,
    require_invitation_viewer, require_pending, require_permission, require_recipient,
    single_team_id,
};
use crate::{
    AuthError, OrganizationError, OrganizationInvitation, OrganizationInvitationAcceptance,
    OrganizationInvitationDetails, OrganizationInvitationStatus,
    OrganizationInvitationWriteOutcome, SessionWithUser,
};
use chrono::Utc;

impl AuthService {
    pub async fn accept_organization_invitation(
        &self,
        session: &SessionWithUser,
        invitation_id: String,
    ) -> Result<OrganizationInvitationAcceptance, AuthError> {
        let plugin = self.organization_plugin()?;
        let invitation = require_pending(plugin, &invitation_id).await?;
        require_recipient(
            session,
            &invitation,
            plugin.config.require_email_verification_on_invitation,
        )?;
        if plugin
            .store
            .find_member(&invitation.organization_id, &invitation.inviter_id)
            .await?
            .is_none()
        {
            return Err(inviter_missing());
        }
        let organization = plugin
            .store
            .find_organization_by_id(&invitation.organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_accept_invitation(&invitation, &session.user, &organization)
                .await?;
        }
        accept_atomically(self, plugin, &invitation_id, &session.user.id).await?;
        self.set_active_organization(session, Some(invitation.organization_id.clone()))
            .await?;
        if let Some(team_id) = single_team_id(&invitation) {
            self.set_active_team(session, Some(team_id)).await?;
        }
        let member = plugin
            .store
            .find_member(&invitation.organization_id, &session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        let invitation = plugin
            .store
            .find_invitation(&invitation_id)
            .await?
            .ok_or_else(invitation_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_accept_invitation(&invitation, &member, &session.user, &organization)
                .await?;
        }
        if let Some(stripe) = self.organization_stripe_plugin() {
            stripe
                .after_organization_member_change(&organization, plugin.store.as_ref())
                .await;
        }
        Ok(OrganizationInvitationAcceptance { invitation, member })
    }

    pub async fn reject_organization_invitation(
        &self,
        session: &SessionWithUser,
        invitation_id: String,
    ) -> Result<OrganizationInvitation, AuthError> {
        let plugin = self.organization_plugin()?;
        let invitation = require_pending(plugin, &invitation_id).await?;
        require_recipient(
            session,
            &invitation,
            plugin.config.require_email_verification_on_invitation,
        )?;
        let organization = plugin
            .store
            .find_organization_by_id(&invitation.organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_reject_invitation(&invitation, &session.user, &organization)
                .await?;
        }
        let rejected = plugin
            .store
            .set_invitation_status(&invitation_id, OrganizationInvitationStatus::Rejected)
            .await?
            .ok_or_else(invitation_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_reject_invitation(&rejected, &session.user, &organization)
                .await?;
        }
        Ok(rejected)
    }

    pub async fn cancel_organization_invitation(
        &self,
        session: &SessionWithUser,
        invitation_id: String,
    ) -> Result<OrganizationInvitation, AuthError> {
        let plugin = self.organization_plugin()?;
        let invitation = plugin
            .store
            .find_invitation(&invitation_id)
            .await?
            .ok_or_else(invitation_not_found)?;
        let member = plugin
            .store
            .find_member(&invitation.organization_id, &session.user.id)
            .await?
            .ok_or_else(member_not_found)?;
        require_permission(self, &member, "cancel").await?;
        let organization = plugin
            .store
            .find_organization_by_id(&invitation.organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_cancel_invitation(&invitation, &session.user, &organization)
                .await?;
        }
        let canceled = plugin
            .store
            .set_invitation_status(&invitation_id, OrganizationInvitationStatus::Canceled)
            .await?
            .ok_or_else(invitation_not_found)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_cancel_invitation(&canceled, &session.user, &organization)
                .await?;
        }
        Ok(canceled)
    }

    pub async fn get_organization_invitation(
        &self,
        session: &SessionWithUser,
        invitation_id: String,
    ) -> Result<OrganizationInvitationDetails, AuthError> {
        let plugin = self.organization_plugin()?;
        let invitation = require_pending(plugin, &invitation_id).await?;
        require_invitation_viewer(
            session,
            &invitation,
            plugin.config.require_email_verification_on_invitation,
        )?;
        let organization = plugin
            .store
            .find_organization_by_id(&invitation.organization_id)
            .await?
            .ok_or_else(organization_not_found)?;
        if plugin
            .store
            .find_member(&invitation.organization_id, &invitation.inviter_id)
            .await?
            .is_none()
        {
            return Err(inviter_missing());
        }
        let inviter = self
            .store
            .find_user_by_id(&invitation.inviter_id)
            .await?
            .ok_or_else(inviter_missing)?;
        Ok(OrganizationInvitationDetails {
            invitation,
            organization_name: organization.name,
            organization_slug: organization.slug,
            inviter_email: inviter.email,
        })
    }
}

async fn accept_atomically(
    service: &AuthService,
    plugin: &crate::OrganizationPlugin,
    invitation_id: &str,
    user_id: &str,
) -> Result<(), AuthError> {
    let member_plan = service.database_id_plan("member", crate::DatabaseIdInput::Absent, false);
    let team_member_plan =
        service.database_id_plan("teamMember", crate::DatabaseIdInput::Absent, false);
    let member_id = || member_plan.prepare(service.store.as_ref());
    let team_member_id = || team_member_plan.prepare(service.store.as_ref());
    match plugin
        .store
        .accept_invitation(
            invitation_id,
            user_id,
            Utc::now(),
            plugin.config.membership_limit,
            &member_id,
            &team_member_id,
        )
        .await?
    {
        OrganizationInvitationWriteOutcome::Written => Ok(()),
        OrganizationInvitationWriteOutcome::AlreadyMember => Err(OrganizationError::bad_request(
            "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION",
            "User is already a member of this organization",
        )
        .into()),
        OrganizationInvitationWriteOutcome::LimitReached => Err(OrganizationError::forbidden(
            "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED",
            "Organization membership limit reached",
        )
        .into()),
        _ => Err(invitation_not_found()),
    }
}
