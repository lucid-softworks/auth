use super::{AuthService, SignInResult};
use crate::{
    AdminCreateUser, AuthError, AuthUser, AuthenticationMethod, OrganizationInvitation,
    OrganizationInvitationStatus,
};
use serde_json::{Map, json};

impl AuthService {
    pub(crate) async fn dash_cancel_organization_invitation(
        &self,
        invitation: OrganizationInvitation,
    ) -> Result<OrganizationInvitation, AuthError> {
        let plugin = self.organization_plugin()?;
        let organization = plugin
            .store
            .find_organization_by_id(&invitation.organization_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        let user = self
            .store
            .find_user_by_id(&invitation.inviter_id)
            .await?
            .ok_or(AuthError::NotFound)?;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .before_cancel_invitation(&invitation, &user, &organization)
                .await?;
        }
        let canceled = plugin
            .store
            .set_invitation_status(&invitation.id, OrganizationInvitationStatus::Canceled)
            .await?
            .ok_or(AuthError::NotFound)?;
        self.observe_dash_invitation_canceled(&organization, &canceled, &user)
            .await;
        if let Some(hooks) = &plugin.config.hooks {
            hooks
                .after_cancel_invitation(&canceled, &user, &organization)
                .await?;
        }
        Ok(canceled)
    }

    pub(crate) async fn dash_invitation_user(
        &self,
        email: String,
        name: String,
        password: Option<String>,
    ) -> Result<AuthUser, AuthError> {
        if let Some(user) = self.store.find_user_by_email(&email).await? {
            return Ok(user);
        }
        self.dash_create_user(AdminCreateUser {
            email,
            password,
            name,
            roles: Vec::new(),
            data: Map::from_iter([("emailVerified".into(), json!(true))]),
        })
        .await
    }

    pub(crate) async fn dash_invitation_session(
        &self,
        user: AuthUser,
    ) -> Result<SignInResult, AuthError> {
        self.create_session(user, AuthenticationMethod::Extension, None, None, None)
            .await
    }

    pub(crate) fn dash_auth_base_url(&self) -> String {
        self.config
            .base_url()
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
            .unwrap_or_else(|| "/".into())
    }
}
