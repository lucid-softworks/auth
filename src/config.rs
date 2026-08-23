use crate::{
    AuthError, CookieConfig, PasswordBreachChecker, TrustedOrigin, client_ip::IpAddressConfig,
};
use chrono::Duration;
use std::sync::Arc;
use url::Url;

/// Runtime behavior for an authentication service.
#[derive(Clone)]
pub struct AuthConfig {
    pub secret: Vec<u8>,
    pub session_ttl: Duration,
    /// Explicitly controls secure cookies. When unset, an HTTPS base URL uses
    /// secure cookies and an HTTP or absent base URL does not.
    pub use_secure_cookies: Option<bool>,
    pub cookies: CookieConfig,
    pub allow_anonymous: bool,
    pub development_bypass: bool,
    pub max_attempts: usize,
    pub max_ip_attempts: usize,
    pub lockout_window: Duration,
    pub passkeys: Option<PasskeyConfig>,
    pub password_breach_checker: Option<Arc<dyn PasswordBreachChecker>>,
    /// Better Auth-compatible client-IP tracking and trusted proxy settings.
    pub ip_address: IpAddressConfig,
    /// Additional browser origins allowed to call authentication endpoints or
    /// receive absolute callback redirects.
    pub trusted_origins: Vec<TrustedOrigin>,
    pub required_mfa_roles: Vec<String>,
    /// Maximum age of strong authentication for security-sensitive operations.
    pub step_up_ttl: Duration,
    pub(crate) base_url: Option<Url>,
    pub(crate) base_path: String,
    pub(crate) cors_enabled: bool,
}

/// Stable relying-party settings used for WebAuthn ceremonies.
#[derive(Debug, Clone)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
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
            use_secure_cookies: None,
            cookies: CookieConfig::default(),
            allow_anonymous: false,
            development_bypass: false,
            max_attempts: 5,
            max_ip_attempts: 15,
            lockout_window: Duration::minutes(5),
            passkeys: None,
            password_breach_checker: None,
            ip_address: IpAddressConfig::default(),
            trusted_origins: Vec::new(),
            required_mfa_roles: Vec::new(),
            step_up_ttl: Duration::days(1),
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
}
