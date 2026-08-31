mod resolution;

use super::{AuthService, SignInResult};
use crate::{AuthError, AuthenticationMethod, OAuthAccount, OAuthTokens, OAuthUserInfo};
use chrono::Utc;

pub(super) struct OAuthSignInPolicy {
    pub provider_id: String,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
    pub override_user_info: bool,
    pub selected_user: Option<OAuthSelectedUser>,
    pub require_exact_account_binding: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct OAuthSelectedUser {
    pub user_id: String,
    pub update_profile: bool,
}

impl AuthService {
    #[cfg(feature = "axum")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish_sso_sign_in_with_tokens(
        &self,
        provider_id: &str,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        state: super::OAuthState,
        disable_implicit_sign_up: bool,
        override_user_info: bool,
        user_agent: Option<String>,
    ) -> Result<super::OAuthCallbackResult, AuthError> {
        self.finish_sso_sign_in_with_resolution(
            provider_id,
            tokens,
            user_info,
            state,
            disable_implicit_sign_up,
            override_user_info,
            None,
            false,
            user_agent,
        )
        .await
    }

    #[cfg(feature = "axum")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn finish_sso_sign_in_with_resolution(
        &self,
        provider_id: &str,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        state: super::OAuthState,
        disable_implicit_sign_up: bool,
        override_user_info: bool,
        selected_user: Option<OAuthSelectedUser>,
        require_exact_account_binding: bool,
        user_agent: Option<String>,
    ) -> Result<super::OAuthCallbackResult, AuthError> {
        let (session, is_new_user) = self
            .finish_oauth_sign_in_with_policy(
                &OAuthSignInPolicy {
                    provider_id: provider_id.into(),
                    disable_implicit_sign_up,
                    disable_sign_up: false,
                    require_email_verification: false,
                    override_user_info,
                    selected_user,
                    require_exact_account_binding,
                },
                tokens,
                user_info,
                state.request_sign_up,
                None,
                user_agent,
            )
            .await?;
        let redirect_url = if is_new_user {
            state.new_user_url.unwrap_or(state.callback_url)
        } else {
            state.callback_url
        };
        Ok(super::OAuthCallbackResult {
            session: Some(session),
            redirect_url,
            is_new_user,
        })
    }

    pub(super) async fn finish_oauth_sign_in(
        &self,
        provider: &dyn crate::SocialProvider,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        request_sign_up: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SignInResult, bool), AuthError> {
        self.finish_oauth_sign_in_with_policy(
            &OAuthSignInPolicy {
                provider_id: provider.id().into(),
                disable_implicit_sign_up: provider.disable_implicit_sign_up(),
                disable_sign_up: provider.disable_sign_up(),
                require_email_verification: provider.require_email_verification(),
                override_user_info: provider.override_user_info(),
                selected_user: None,
                require_exact_account_binding: false,
            },
            tokens,
            user_info,
            request_sign_up,
            ip_address,
            user_agent,
        )
        .await
    }

    pub(super) async fn finish_oauth_sign_in_with_policy(
        &self,
        policy: &OAuthSignInPolicy,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        request_sign_up: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SignInResult, bool), AuthError> {
        let now = Utc::now();
        let account = self.oauth_account(&policy.provider_id, &user_info, tokens, now)?;
        let (user, is_new_user) = self
            .resolve_oauth_user(policy, user_info, account, request_sign_up, now)
            .await?;
        if policy.require_email_verification && !user.email_verified {
            let should_send = if is_new_user {
                self.config
                    .email_verification
                    .send_on_sign_up
                    .unwrap_or(true)
            } else {
                self.config.email_verification.send_on_sign_in
            };
            if should_send
                && (self.config.email_verification.sender.is_some()
                    || self.email_otp_overrides_verification())
            {
                let _ = self.deliver_verification_email(user.clone(), None).await;
            }
            return Err(AuthError::EmailNotVerified);
        }
        let expected_user_id = policy
            .selected_user
            .as_ref()
            .map(|selected| selected.user_id.as_str())
            .unwrap_or(&user.id)
            .to_owned();
        let session = self
            .create_session(
                user,
                AuthenticationMethod::OAuth,
                None,
                ip_address,
                user_agent,
            )
            .await
            .map_err(|_| AuthError::OAuthUnableToCreateSession)?;
        if policy.require_exact_account_binding
            && session.session.session.user_id != expected_user_id
        {
            return Err(sso_conflict(
                "session_hook_user_conflict",
                "Session hook changed the selected user",
            ));
        }
        Ok((session, is_new_user))
    }

    pub(super) fn oauth_account(
        &self,
        provider_id: &str,
        user_info: &OAuthUserInfo,
        tokens: OAuthTokens,
        now: chrono::DateTime<Utc>,
    ) -> Result<OAuthAccount, AuthError> {
        Ok(OAuthAccount {
            id: String::new(),
            user_id: String::new(),
            issuer: user_info.issuer.clone(),
            account_id: user_info.account_id.clone(),
            provider_id: provider_id.into(),
            access_token: self.protect_oauth_token(tokens.access_token)?,
            refresh_token: self.protect_oauth_token(tokens.refresh_token)?,
            id_token: tokens.id_token,
            access_token_expires_at: tokens.access_token_expires_at,
            refresh_token_expires_at: tokens.refresh_token_expires_at,
            scope: (!tokens.scopes.is_empty()).then(|| tokens.scopes.join(",")),
            password: None,
            additional_fields: serde_json::Map::new(),
            created_at: now,
            updated_at: now,
        })
    }
}

fn sso_conflict(code: &'static str, message: &'static str) -> AuthError {
    AuthError::SsoAuthenticationConflict { code, message }
}
