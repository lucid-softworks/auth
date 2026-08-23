use super::{AuthService, SignInResult, account_limit_key, password::verify_password};
use crate::{
    AuthError, SessionWithUser, UserProfileUpdate, UsernameConfig, UsernameError, UsernamePlugin,
};

impl AuthService {
    #[cfg(feature = "axum")]
    pub(crate) async fn better_auth_user(
        &self,
        user: &crate::AuthUser,
    ) -> Result<crate::protocol::better_auth::BetterAuthUser, AuthError> {
        let mut output = crate::protocol::better_auth::BetterAuthUser::from(user);
        match self.plugins.find::<UsernamePlugin>() {
            Some(plugin) if plugin.config().display_username => {}
            Some(_) => output.display_username = None,
            None => {
                output.username = None;
                output.display_username = None;
            }
        }
        if self.plugins.find::<crate::TwoFactorPlugin>().is_some() {
            output.two_factor_enabled = Some(self.two_factor_enabled(user.id).await?);
        }
        if self.plugins.find::<crate::AdminPlugin>().is_none() {
            output.role = None;
            output.banned = None;
            output.ban_reason = None;
            output.ban_expires = None;
        }
        Ok(output)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn better_auth_session_response(
        &self,
        value: &SessionWithUser,
        token: impl Into<String>,
    ) -> Result<crate::protocol::better_auth::SessionResponse, AuthError> {
        Ok(crate::protocol::better_auth::SessionResponse {
            session: crate::protocol::better_auth::BetterAuthSession::from_session(
                &value.session,
                token,
            ),
            user: self.better_auth_user(&value.user).await?,
        })
    }

    fn username_config(&self) -> Result<&UsernameConfig, AuthError> {
        self.plugins
            .find::<UsernamePlugin>()
            .map(UsernamePlugin::config)
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("the username plugin is not enabled".into())
            })
    }

    pub(super) async fn prepare_username_signup(
        &self,
        username: Option<String>,
        display_username: Option<String>,
    ) -> Result<(Option<String>, Option<String>), AuthError> {
        let Some(config) = self
            .plugins
            .find::<UsernamePlugin>()
            .map(UsernamePlugin::config)
        else {
            return Ok((None, None));
        };
        let mut username = username;
        if username.is_none()
            && let Some(display) = display_username.as_deref()
            && config.validate_username(display).await.is_ok()
        {
            username = Some(display.to_owned());
        }
        if let Some(value) = username.as_deref() {
            config.validate_username(value).await?;
            let normalized = config.normalize(value);
            if self
                .store
                .find_user_by_username(&normalized)
                .await?
                .is_some()
            {
                return Err(UsernameError::AlreadyTaken.into());
            }
        }
        if config.display_username
            && let Some(value) = display_username.as_deref()
        {
            config.validate_display_username(value).await?;
        }
        let stored_username = username.as_deref().map(|value| config.normalize(value));
        let stored_display = if config.display_username {
            display_username
                .as_deref()
                .map(|value| config.normalize_display(value))
                .or(username)
        } else {
            None
        };
        Ok((stored_username, stored_display))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn sign_in_username_plugin(
        &self,
        username: &str,
        password: String,
        remember_me: Option<bool>,
        callback_url: Option<&str>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let config = self.username_config()?;
        if username.is_empty() || password.is_empty() {
            return Err(UsernameError::InvalidUsernameOrPassword.into());
        }
        config.validate_sign_in_username(username).await?;
        let normalized = config.normalize(username);
        self.enforce_rate_limit(&normalized, ip_address.as_deref())
            .await?;
        let user = self.store.find_user_by_username(&normalized).await?;
        let password_hash = match &user {
            Some(user) => self.store.find_password_hash(user.id).await?,
            None => None,
        };
        let valid = verify_password(password, password_hash).await?;
        let Some(user) = user.filter(|_| valid) else {
            self.record_failure(&normalized, ip_address.as_deref())
                .await?;
            return Err(UsernameError::InvalidUsernameOrPassword.into());
        };
        if self.config.email_and_password.require_email_verification && !user.email_verified {
            self.maybe_send_signin_verification(&user, callback_url)
                .await?;
            return Err(UsernameError::EmailNotVerified.into());
        }
        self.store
            .clear_auth_failures(&account_limit_key(&normalized))
            .await?;
        self.create_email_password_session(user, remember_me, ip_address, user_agent)
            .await
    }

    pub async fn username_available_plugin(&self, username: &str) -> Result<bool, AuthError> {
        let config = self.username_config()?;
        if username.is_empty() {
            return Err(UsernameError::Invalid.into());
        }
        config.validate_availability_username(username).await?;
        Ok(self
            .store
            .find_user_by_username(&config.normalize(username))
            .await?
            .is_none())
    }

    pub async fn update_current_user(
        &self,
        session: &SessionWithUser,
        mut update: UserProfileUpdate,
    ) -> Result<(), AuthError> {
        if update.name.is_none()
            && update.image.is_none()
            && update.username.is_none()
            && update.display_username.is_none()
        {
            return Err(AuthError::InvalidRequest("No fields to update".into()));
        }
        if update.username.is_some() || update.display_username.is_some() {
            let config = self.username_config()?;
            if let Some(value) = update.username.as_deref() {
                config.validate_username(value).await?;
                let normalized = config.normalize(value);
                if config.immutable_username
                    && session.user.username.is_some()
                    && session.user.username.as_deref() != Some(normalized.as_str())
                {
                    return Err(UsernameError::Immutable.into());
                }
                if self
                    .store
                    .find_user_by_username(&normalized)
                    .await?
                    .is_some_and(|user| user.id != session.user.id)
                {
                    return Err(UsernameError::AlreadyTaken.into());
                }
                update.username = Some(normalized);
            }
            if let Some(value) = update.display_username.as_deref() {
                if !config.display_username {
                    update.display_username = None;
                } else {
                    config.validate_display_username(value).await?;
                    update.display_username = Some(config.normalize_display(value));
                }
            }
        }
        self.store
            .update_user_profile(session.user.id, update)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        Ok(())
    }
}
