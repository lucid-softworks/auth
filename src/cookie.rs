/// Cookie `SameSite` policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    #[cfg(feature = "axum")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

/// Optional cookie attributes merged over Better Auth's defaults.
#[derive(Debug, Clone, Default)]
pub struct CookieAttributes {
    pub path: Option<String>,
    pub domain: Option<String>,
    pub same_site: Option<SameSite>,
    pub secure: Option<bool>,
    pub http_only: Option<bool>,
}

/// Name and attribute overrides for one authentication cookie.
#[derive(Debug, Clone, Default)]
pub struct CookieOptions {
    pub name: Option<String>,
    pub attributes: CookieAttributes,
}

/// Better Auth-compatible cookie naming and attribute configuration.
#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub prefix: String,
    pub default_attributes: CookieAttributes,
    pub session_token: CookieOptions,
    cross_subdomain_enabled: bool,
    cross_subdomain_domain: Option<String>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            prefix: "better-auth".into(),
            default_attributes: CookieAttributes::default(),
            session_token: CookieOptions::default(),
            cross_subdomain_enabled: false,
            cross_subdomain_domain: None,
        }
    }
}

impl CookieConfig {
    /// Enables or disables cookie sharing across subdomains. When enabled
    /// without an explicit domain, the configured static base URL host is used.
    pub fn set_cross_subdomain(&mut self, enabled: bool, domain: Option<String>) {
        self.cross_subdomain_enabled = enabled;
        self.cross_subdomain_domain = domain;
    }

    pub fn cross_subdomain_enabled(&self) -> bool {
        self.cross_subdomain_enabled
    }

    pub fn cross_subdomain_domain(&self) -> Option<&str> {
        self.cross_subdomain_domain.as_deref()
    }

    #[cfg(any(feature = "axum", test))]
    pub(crate) fn resolve(
        &self,
        kind: CookieKind,
        secure_name: bool,
        base_url_host: Option<&str>,
    ) -> ResolvedCookie {
        self.resolve_with_suffix(kind, None, secure_name, base_url_host)
    }

    #[cfg(any(feature = "axum", test))]
    pub(crate) fn resolve_with_suffix(
        &self,
        kind: CookieKind,
        suffix_override: Option<&str>,
        secure_name: bool,
        base_url_host: Option<&str>,
    ) -> ResolvedCookie {
        let default_suffix = match kind {
            CookieKind::SessionToken => "session_token",
            CookieKind::PasskeyChallenge => "better-auth-passkey",
            #[cfg(feature = "axum")]
            CookieKind::Plugin => "plugin",
        };
        let suffix = suffix_override.unwrap_or(default_suffix);
        let options = match kind {
            CookieKind::SessionToken => Some(&self.session_token),
            CookieKind::PasskeyChallenge => None,
            #[cfg(feature = "axum")]
            CookieKind::Plugin => None,
        };
        let unprefixed_name = options
            .and_then(|options| options.name.clone())
            .unwrap_or_else(|| format!("{}.{suffix}", self.prefix));
        let name = if secure_name {
            format!("__Secure-{unprefixed_name}")
        } else {
            unprefixed_name
        };
        let cross_subdomain = self.cross_subdomain_enabled.then(|| {
            self.cross_subdomain_domain
                .as_deref()
                .or(base_url_host)
                .map(str::to_owned)
        });
        let attributes = ResolvedCookieAttributes {
            path: options
                .and_then(|options| options.attributes.path.clone())
                .clone()
                .or_else(|| self.default_attributes.path.clone())
                .unwrap_or_else(|| "/".into()),
            domain: options
                .and_then(|options| options.attributes.domain.clone())
                .or_else(|| self.default_attributes.domain.clone())
                .or_else(|| cross_subdomain.flatten()),
            same_site: options
                .and_then(|options| options.attributes.same_site)
                .or(self.default_attributes.same_site)
                .unwrap_or(SameSite::Lax),
            secure: options
                .and_then(|options| options.attributes.secure)
                .or(self.default_attributes.secure)
                .unwrap_or(secure_name),
            http_only: options
                .and_then(|options| options.attributes.http_only)
                .or(self.default_attributes.http_only)
                .unwrap_or(true),
        };
        ResolvedCookie { name, attributes }
    }
}

#[cfg(any(feature = "axum", test))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum CookieKind {
    SessionToken,
    PasskeyChallenge,
    #[cfg(feature = "axum")]
    Plugin,
}

#[cfg(any(feature = "axum", test))]
#[derive(Debug, Clone)]
pub(crate) struct ResolvedCookie {
    pub name: String,
    pub attributes: ResolvedCookieAttributes,
}

#[cfg(any(feature = "axum", test))]
#[derive(Debug, Clone)]
pub(crate) struct ResolvedCookieAttributes {
    pub path: String,
    pub domain: Option<String>,
    pub same_site: SameSite,
    pub secure: bool,
    pub http_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_names_and_per_cookie_attributes_follow_better_auth_precedence() {
        let mut config = CookieConfig::default();
        config.default_attributes.domain = Some(".example.com".into());
        config.default_attributes.same_site = Some(SameSite::None);
        config.session_token.name = Some("session".into());
        config.session_token.attributes.path = Some("/auth".into());
        let cookie = config.resolve(CookieKind::SessionToken, true, Some("auth.example.com"));
        assert_eq!(cookie.name, "__Secure-session");
        assert_eq!(cookie.attributes.path, "/auth");
        assert_eq!(cookie.attributes.domain.as_deref(), Some(".example.com"));
        assert_eq!(cookie.attributes.same_site, SameSite::None);
        assert!(cookie.attributes.secure);
        assert!(cookie.attributes.http_only);
    }

    #[test]
    fn cross_subdomain_defaults_to_the_static_base_url_host() {
        let mut config = CookieConfig::default();
        config.set_cross_subdomain(true, None);
        let cookie = config.resolve(CookieKind::PasskeyChallenge, false, Some("example.com"));
        assert_eq!(cookie.attributes.domain.as_deref(), Some("example.com"));
    }
}
