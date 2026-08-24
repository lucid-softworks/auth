use crate::{
    AuthError, AuthPlugin, CookieConfig, DatabaseHooks, EmailVerificationConfig,
    PasswordBreachChecker, PasswordResetCallback, PasswordResetEmailSender, SecondaryStorage,
    SessionConfig, TrustedOrigin, UserConfig, client_ip::IpAddressConfig,
    rate_limit::RateLimitConfig,
};
use chrono::Duration;
use std::sync::Arc;
use url::Url;

mod verification;
pub use verification::{
    VerificationConfig, VerificationIdentifierConfig, VerificationIdentifierHasher,
    VerificationIdentifierStorage,
};

/// Runtime behavior for an authentication service.
#[derive(Clone)]
pub struct AuthConfig {
    pub secret: Vec<u8>,
    pub session_ttl: Duration,
    /// Better Auth session freshness window. Zero disables freshness checks.
    pub session_fresh_age: Duration,
    /// Explicitly controls secure cookies. When unset, an HTTPS base URL uses
    /// secure cookies and an HTTP or absent base URL does not.
    pub use_secure_cookies: Option<bool>,
    pub cookies: CookieConfig,
    pub development_bypass: bool,
    /// Better Auth-compatible global, special-route, plugin, and custom rate limiting.
    pub rate_limit: RateLimitConfig,
    pub password_breach_checker: Option<Arc<dyn PasswordBreachChecker>>,
    /// Better Auth-compatible email/password behavior. The flow is disabled
    /// by default, matching Better Auth.
    pub email_and_password: EmailPasswordConfig,
    pub email_verification: EmailVerificationConfig,
    pub user: UserConfig,
    pub session: SessionConfig,
    pub account: AccountConfig,
    pub verification: VerificationConfig,
    pub database_hooks: Option<Arc<dyn DatabaseHooks>>,
    /// Better Auth-compatible secondary storage for live sessions,
    /// verification values, and, by default, request rate limits.
    pub secondary_storage: Option<Arc<dyn SecondaryStorage>>,
    /// Better Auth-compatible built-in or custom social providers.
    pub(crate) social_providers: Vec<Arc<dyn crate::SocialProvider>>,
    pub(crate) trusted_social_providers: Vec<String>,
    /// Better Auth-compatible client-IP tracking and trusted proxy settings.
    pub ip_address: IpAddressConfig,
    /// Additional browser origins allowed to call authentication endpoints or
    /// receive absolute callback redirects.
    pub trusted_origins: Vec<TrustedOrigin>,
    pub(crate) plugins: Vec<Arc<dyn AuthPlugin>>,
    pub(crate) base_url: Option<Url>,
    pub(crate) base_path: String,
    pub(crate) cors_enabled: bool,
}

/// Core email/password settings matching Better Auth 1.7.1 defaults.
#[derive(Clone)]
pub struct EmailPasswordConfig {
    pub enabled: bool,
    pub disable_sign_up: bool,
    pub auto_sign_in: bool,
    pub require_email_verification: bool,
    pub min_password_length: usize,
    pub max_password_length: usize,
    pub send_reset_password: Option<Arc<dyn PasswordResetEmailSender>>,
    pub on_password_reset: Option<Arc<dyn PasswordResetCallback>>,
    pub reset_password_token_expires_in: Duration,
    pub revoke_sessions_on_password_reset: bool,
}

impl Default for EmailPasswordConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            disable_sign_up: false,
            auto_sign_in: true,
            require_email_verification: false,
            min_password_length: 8,
            max_password_length: 128,
            send_reset_password: None,
            on_password_reset: None,
            reset_password_token_expires_in: Duration::hours(1),
            revoke_sessions_on_password_reset: false,
        }
    }
}

impl AuthConfig {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AuthError> {
        let secret = secret.into();
        if secret.len() < 32 {
            return Err(AuthError::InvalidConfiguration(
                "secret must contain at least 32 bytes".into(),
            ));
        }
        Ok(Self {
            secret,
            session_ttl: Duration::days(7),
            session_fresh_age: Duration::days(1),
            use_secure_cookies: None,
            cookies: CookieConfig::default(),
            development_bypass: false,
            rate_limit: RateLimitConfig::default(),
            password_breach_checker: None,
            email_and_password: EmailPasswordConfig::default(),
            email_verification: EmailVerificationConfig::default(),
            user: UserConfig::default(),
            session: SessionConfig::default(),
            account: AccountConfig::default(),
            verification: VerificationConfig::default(),
            database_hooks: None,
            secondary_storage: None,
            social_providers: Vec::new(),
            trusted_social_providers: Vec::new(),
            ip_address: IpAddressConfig::default(),
            trusted_origins: Vec::new(),
            plugins: Vec::new(),
            base_url: None,
            base_path: "/api/auth".into(),
            cors_enabled: false,
        })
    }

    pub fn set_base_url(&mut self, value: &str) -> Result<(), AuthError> {
        let url = Url::parse(value).map_err(|_| {
            AuthError::InvalidConfiguration("base URL must be an absolute HTTP(S) URL".into())
        })?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(AuthError::InvalidConfiguration(
                "base URL must be an absolute HTTP(S) URL without credentials, query, or fragment"
                    .into(),
            ));
        }
        if url.path() != "/" {
            self.base_path = normalize_base_path(url.path())?;
        }
        self.base_url = Some(url);
        Ok(())
    }

    pub fn base_url(&self) -> Option<&Url> {
        self.base_url.as_ref()
    }

    pub fn set_base_path(&mut self, value: &str) -> Result<(), AuthError> {
        self.base_path = normalize_base_path(value)?;
        Ok(())
    }

    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Enables credentialed CORS responses for the configured trusted origins.
    pub fn enable_cors(&mut self) {
        self.cors_enabled = true;
    }

    pub fn trust_origin(&mut self, origin: &str) -> Result<(), AuthError> {
        self.trusted_origins.push(TrustedOrigin::parse(origin)?);
        Ok(())
    }

    pub fn add_social_provider<P>(&mut self, provider: P) -> Result<(), AuthError>
    where
        P: crate::SocialProvider + 'static,
    {
        self.add_social_provider_arc(Arc::new(provider))
    }

    pub fn add_social_provider_arc(
        &mut self,
        provider: Arc<dyn crate::SocialProvider>,
    ) -> Result<(), AuthError> {
        let id = provider.id();
        if id.trim().is_empty() || self.social_providers.iter().any(|item| item.id() == id) {
            return Err(AuthError::InvalidConfiguration(format!(
                "social provider '{id}' has an empty or duplicate id"
            )));
        }
        self.social_providers.push(provider);
        Ok(())
    }

    /// Trusts a provider's email-verification assertion for implicit linking.
    /// The existing local account must still have a verified matching email.
    pub fn trust_social_provider(&mut self, provider_id: &str) -> Result<(), AuthError> {
        if provider_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "trusted social provider id must not be empty".into(),
            ));
        }
        if !self
            .trusted_social_providers
            .iter()
            .any(|trusted| trusted == provider_id)
        {
            self.trusted_social_providers.push(provider_id.into());
        }
        Ok(())
    }

    /// Enables a native plugin. Full dependency, conflict, and contribution
    /// validation occurs in [`crate::AuthService::try_new`].
    pub fn add_plugin<P>(&mut self, plugin: P) -> Result<(), AuthError>
    where
        P: AuthPlugin + 'static,
    {
        self.add_plugin_arc(Arc::new(plugin))
    }

    pub fn add_plugin_arc(&mut self, plugin: Arc<dyn AuthPlugin>) -> Result<(), AuthError> {
        let id = plugin.descriptor().id;
        if self
            .plugins
            .iter()
            .any(|enabled| enabled.descriptor().id == id)
        {
            return Err(AuthError::InvalidConfiguration(format!(
                "plugin '{id}' is enabled more than once"
            )));
        }
        self.plugins.push(plugin);
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), AuthError> {
        self.rate_limit.validate()?;
        self.session.validate()?;
        if self.session_fresh_age < Duration::zero() {
            return Err(AuthError::InvalidConfiguration(
                "session fresh age must not be negative".into(),
            ));
        }
        let password = &self.email_and_password;
        if password.min_password_length == 0
            || password.max_password_length < password.min_password_length
        {
            return Err(AuthError::InvalidConfiguration(
                "email/password bounds must have a positive minimum no greater than the maximum"
                    .into(),
            ));
        }
        if password.reset_password_token_expires_in <= Duration::zero() {
            return Err(AuthError::InvalidConfiguration(
                "password reset expiry must be positive".into(),
            ));
        }
        if password.send_reset_password.is_some() && self.base_url.is_none() {
            return Err(AuthError::InvalidConfiguration(
                "a base URL is required when a password reset sender is configured".into(),
            ));
        }
        if self.email_verification.expires_in <= Duration::zero() {
            return Err(AuthError::InvalidConfiguration(
                "email verification expiry must be positive".into(),
            ));
        }
        if self.email_verification.sender.is_some() && self.base_url.is_none() {
            return Err(AuthError::InvalidConfiguration(
                "a base URL is required when an email verification sender is configured".into(),
            ));
        }
        if self.user.delete_user.delete_token_expires_in <= Duration::zero() {
            return Err(AuthError::InvalidConfiguration(
                "delete-user token expiry must be positive".into(),
            ));
        }
        if self
            .user
            .delete_user
            .send_delete_account_verification
            .is_some()
            && self.base_url.is_none()
        {
            return Err(AuthError::InvalidConfiguration(
                "a base URL is required when a delete-account sender is configured".into(),
            ));
        }
        validate_additional_field_config(self)?;
        if !self.social_providers.is_empty() && self.base_url.is_none() {
            return Err(AuthError::InvalidConfiguration(
                "a base URL is required when social providers are configured".into(),
            ));
        }
        for provider in &self.social_providers {
            provider.validate_configuration()?;
        }
        for trusted in &self.trusted_social_providers {
            if !self
                .social_providers
                .iter()
                .any(|provider| provider.id() == trusted)
            {
                return Err(AuthError::InvalidConfiguration(format!(
                    "trusted social provider '{trusted}' is not configured"
                )));
            }
        }
        Ok(())
    }
}

/// Better Auth 1.7 account-linking policy.
#[derive(Debug, Clone, Default)]
pub struct AccountConfig {
    pub account_linking: AccountLinkingConfig,
    pub additional_fields: crate::AdditionalFieldSet,
}

#[derive(Debug, Clone)]
pub struct AccountLinkingConfig {
    pub enabled: bool,
    pub allow_different_emails: bool,
    pub allow_unlinking_all: bool,
    pub disable_implicit_linking: bool,
    pub require_local_email_verified: bool,
}

impl Default for AccountLinkingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allow_different_emails: false,
            allow_unlinking_all: false,
            disable_implicit_linking: false,
            require_local_email_verified: true,
        }
    }
}

fn validate_additional_field_config(config: &AuthConfig) -> Result<(), AuthError> {
    for (model, fields) in [
        (crate::DatabaseModel::User, &config.user.additional_fields),
        (
            crate::DatabaseModel::Session,
            &config.session.additional_fields,
        ),
        (
            crate::DatabaseModel::Account,
            &config.account.additional_fields,
        ),
        (
            crate::DatabaseModel::Verification,
            &config.verification.additional_fields,
        ),
    ] {
        crate::additional_fields::validate_field_names(
            model.as_str(),
            fields,
            crate::additional_fields::reserved_field_names(model),
        )?;
    }
    Ok(())
}

fn normalize_base_path(value: &str) -> Result<String, AuthError> {
    let value = value.trim();
    if value.is_empty() || value.contains(['?', '#', '\\']) || value.chars().any(char::is_control) {
        return Err(AuthError::InvalidConfiguration(
            "base path must be a non-empty URL path without a query or fragment".into(),
        ));
    }
    let with_slash = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    let normalized = with_slash.trim_end_matches('/');
    Ok(if normalized.is_empty() {
        "/".into()
    } else {
        normalized.into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_normalizes_deployment_urls() {
        let mut config = AuthConfig::new([7_u8; 32]).unwrap();
        config
            .set_base_url("https://auth.example.com/custom/")
            .unwrap();
        assert_eq!(config.base_path(), "/custom");
        assert_eq!(
            config.base_url().unwrap().host_str(),
            Some("auth.example.com")
        );
        config.set_base_path("auth").unwrap();
        assert_eq!(config.base_path(), "/auth");
        assert!(config.set_base_url("javascript:alert(1)").is_err());
        assert!(config.set_base_path("/auth?unsafe=true").is_err());
    }

    #[test]
    fn validates_email_password_bounds() {
        let mut config = AuthConfig::new([8_u8; 32]).unwrap();
        config.email_and_password.min_password_length = 0;
        assert!(config.validate().is_err());
        config.email_and_password.min_password_length = 20;
        config.email_and_password.max_password_length = 10;
        assert!(config.validate().is_err());
    }
}
