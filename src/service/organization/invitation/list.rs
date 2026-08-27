use super::super::AuthService;
use super::support::organization_not_found;
use crate::{
    AuthError, OrganizationError, OrganizationInvitation, OrganizationInvitationStatus,
    SessionWithUser,
};

impl AuthService {
    pub async fn list_organization_invitations(
        &self,
        session: &SessionWithUser,
        organization_id: Option<String>,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        let organization_id = organization_id
            .or_else(|| Self::active_organization_id(session))
            .ok_or_else(organization_not_found)?;
        let plugin = self.organization_plugin()?;
        if plugin
            .store
            .find_member(&organization_id, &session.user.id)
            .await?
            .is_none()
        {
            return Err(OrganizationError::forbidden(
                "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION",
                "You are not a member of this organization",
            )
            .into());
        }
        plugin.store.list_invitations(&organization_id).await
    }

    pub async fn list_current_user_organization_invitations(
        &self,
        session: &SessionWithUser,
    ) -> Result<Vec<OrganizationInvitation>, AuthError> {
        if !session.user.email_verified {
            return Err(OrganizationError::forbidden(
                "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION",
                "Email verification required to view or list invitations for the session email",
            )
            .into());
        }
        Ok(self
            .organization_plugin()?
            .store
            .list_user_invitations(&session.user.email)
            .await?
            .into_iter()
            .filter(|invitation| invitation.status == OrganizationInvitationStatus::Pending)
            .collect())
    }
}
