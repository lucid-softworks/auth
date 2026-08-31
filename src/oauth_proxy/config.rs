use chrono::Duration;
use std::{collections::BTreeMap, fmt};
use url::Url;

/// Dedicated encryption material shared by every environment participating in
/// an OAuth proxy flow.
#[derive(Clone, PartialEq, Eq)]
pub enum OAuthProxySecret {
    Plain(Vec<u8>),
    Versioned(OAuthProxyVersionedSecret),
}

impl fmt::Debug for OAuthProxySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => formatter.write_str("Plain([REDACTED])"),
            Self::Versioned(secret) => formatter
                .debug_struct("Versioned")
                .field("current_version", &secret.current_version)
                .field("versions", &secret.keys.keys().collect::<Vec<_>>())
                .field("has_legacy_secret", &secret.legacy_secret.is_some())
                .finish(),
        }
    }
}

impl From<Vec<u8>> for OAuthProxySecret {
    fn from(value: Vec<u8>) -> Self {
        Self::Plain(value)
    }
}

impl From<String> for OAuthProxySecret {
    fn from(value: String) -> Self {
        Self::Plain(value.into_bytes())
    }
}

impl From<&str> for OAuthProxySecret {
    fn from(value: &str) -> Self {
        Self::Plain(value.as_bytes().to_vec())
    }
}

/// Better Auth `SecretConfig` equivalent for a dedicated OAuth proxy secret.
#[derive(Clone, PartialEq, Eq)]
pub struct OAuthProxyVersionedSecret {
    pub current_version: u32,
    pub keys: BTreeMap<u32, Vec<u8>>,
    pub legacy_secret: Option<Vec<u8>>,
}

impl fmt::Debug for OAuthProxyVersionedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthProxyVersionedSecret")
            .field("current_version", &self.current_version)
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .field("has_legacy_secret", &self.legacy_secret.is_some())
            .finish()
    }
}

/// Better Auth 1.7.2 OAuth proxy options.
#[derive(Clone)]
pub struct OAuthProxyConfig {
    /// Explicit URL for the current (usually preview) environment.
    pub current_url: Option<Url>,
    /// Stable deployment whose OAuth callback URL is registered with providers.
    pub production_url: Option<Url>,
    /// Maximum encrypted-profile age. Better Auth expresses this in seconds.
    pub max_age: Duration,
    /// Optional dedicated secret; the global auth secret is used when absent.
    pub secret: Option<OAuthProxySecret>,
}

impl Default for OAuthProxyConfig {
    fn default() -> Self {
        Self {
            current_url: None,
            production_url: None,
            max_age: Duration::seconds(60),
            secret: None,
        }
    }
}

impl fmt::Debug for OAuthProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthProxyConfig")
            .field("current_url", &self.current_url)
            .field("production_url", &self.production_url)
            .field("max_age", &self.max_age)
            .field("has_dedicated_secret", &self.secret.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_debug_output_match_the_pinned_options_without_leaking_secrets() {
        let defaults = OAuthProxyConfig::default();
        assert_eq!(defaults.max_age, Duration::seconds(60));
        assert!(defaults.current_url.is_none());
        assert!(defaults.production_url.is_none());
        assert!(defaults.secret.is_none());

        let secret = OAuthProxySecret::from("dedicated-oauth-proxy-secret");
        let debug = format!("{secret:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("dedicated-oauth-proxy-secret"));
    }

    #[test]
    fn versioned_secret_debug_exposes_versions_but_not_key_material() {
        let secret = OAuthProxyVersionedSecret {
            current_version: 7,
            keys: BTreeMap::from([
                (3, b"alpha-secret-material-881".to_vec()),
                (7, b"beta-secret-material-992".to_vec()),
            ]),
            legacy_secret: Some(b"gamma-secret-material-773".to_vec()),
        };
        let debug = format!("{secret:?}");
        assert!(debug.contains("current_version: 7"));
        assert!(debug.contains("has_legacy_secret: true"));
        for material in [
            "alpha-secret-material-881",
            "beta-secret-material-992",
            "gamma-secret-material-773",
        ] {
            assert!(!debug.contains(material));
        }
    }
}
