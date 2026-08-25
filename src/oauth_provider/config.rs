use crate::AuthError;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};

use super::error::OAuthProviderConfigError;

pub const DEFAULT_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];
pub const DEFAULT_GRANT_TYPES: &[&str] =
    &["authorization_code", "client_credentials", "refresh_token"];
pub const DEFAULT_DPOP_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES512", "PS256", "RS256"];

include!("config/definitions.rs");
include!("config/extensions.rs");
#[derive(Clone)]
pub struct OAuthProviderConfig {
    pub(crate) runtime_instance_id: uuid::Uuid,
    pub schema: OAuthProviderSchema,
    pub scopes: Vec<String>,
    pub resources: Vec<OAuthResourceInput>,
    pub resource_seed_mode: OAuthResourceSeedMode,
    pub cached_resources: BTreeSet<String>,
    pub enforce_per_client_resources: bool,
    pub client_registration_default_resources: Vec<String>,
    pub client_registration_allowed_resources: Vec<String>,
    pub cached_trusted_clients: BTreeSet<String>,
    pub access_token_expires_in: u64,
    pub m2m_access_token_expires_in: u64,
    pub id_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub refresh_token_reuse_interval: u64,
    pub code_expires_in: u64,
    pub scope_expirations: BTreeMap<String, OAuthExpiration>,
    pub assertion_max_lifetime: u64,
    pub allow_public_client_prelogin: bool,
    pub allow_unauthenticated_client_registration: bool,
    pub allow_dynamic_client_registration: bool,
    pub client_registration_default_scopes: Option<Vec<String>>,
    pub client_registration_allowed_scopes: Vec<String>,
    pub client_registration_require_pkce: bool,
    pub client_registration_client_secret_expiration: Option<OAuthExpiration>,
    pub grant_types: Vec<String>,
    pub login_page: String,
    pub consent_page: String,
    pub signup_page: Option<String>,
    pub select_account_page: Option<String>,
    pub post_login_page: Option<String>,
    pub store_client_secret: OAuthClientSecretStorage,
    pub store_tokens: OAuthTokenStorage,
    pub advertised_metadata: OAuthAdvertisedMetadata,
    pub prefix: OAuthTokenPrefixes,
    pub disable_jwt_plugin: bool,
    pub rate_limit: OAuthProviderRateLimits,
    pub pairwise_secret: Option<String>,
    pub dpop: OAuthDpopConfig,
    pub callbacks: OAuthProviderCallbacks,
    pub extensions: Vec<Arc<dyn OAuthProviderExtension>>,
}

impl OAuthProviderConfig {
    pub fn new(login_page: impl Into<String>, consent_page: impl Into<String>) -> Self {
        Self {
            runtime_instance_id: uuid::Uuid::nil(),
            schema: OAuthProviderSchema::default(),
            scopes: DEFAULT_SCOPES.iter().map(|value| (*value).into()).collect(),
            resources: Vec::new(),
            resource_seed_mode: OAuthResourceSeedMode::InsertOnly,
            cached_resources: BTreeSet::new(),
            enforce_per_client_resources: true,
            client_registration_default_resources: Vec::new(),
            client_registration_allowed_resources: Vec::new(),
            cached_trusted_clients: BTreeSet::new(),
            access_token_expires_in: 3600,
            m2m_access_token_expires_in: 3600,
            id_token_expires_in: 36_000,
            refresh_token_expires_in: 2_592_000,
            refresh_token_reuse_interval: 0,
            code_expires_in: 600,
            scope_expirations: BTreeMap::new(),
            assertion_max_lifetime: 300,
            allow_public_client_prelogin: false,
            allow_unauthenticated_client_registration: false,
            allow_dynamic_client_registration: false,
            client_registration_default_scopes: None,
            client_registration_allowed_scopes: Vec::new(),
            client_registration_require_pkce: true,
            client_registration_client_secret_expiration: None,
            grant_types: DEFAULT_GRANT_TYPES
                .iter()
                .map(|value| (*value).into())
                .collect(),
            login_page: login_page.into(),
            consent_page: consent_page.into(),
            signup_page: None,
            select_account_page: None,
            post_login_page: None,
            store_client_secret: OAuthClientSecretStorage::Automatic,
            store_tokens: OAuthTokenStorage::Hashed,
            advertised_metadata: OAuthAdvertisedMetadata::default(),
            prefix: OAuthTokenPrefixes::default(),
            disable_jwt_plugin: false,
            rate_limit: OAuthProviderRateLimits::default(),
            pairwise_secret: None,
            dpop: OAuthDpopConfig::default(),
            callbacks: OAuthProviderCallbacks::default(),
            extensions: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), OAuthProviderConfigError> {
        validate_pages(self)?;
        validate_scopes(self)?;
        validate_resources(self)?;
        validate_extensions(self)?;
        validate_security(self)
    }

    pub fn oidc_enabled(&self) -> bool {
        self.scopes.iter().any(|scope| scope == "openid")
    }

    pub fn effective_scopes(&self) -> Vec<String> {
        deduplicate(
            self.scopes
                .iter()
                .filter(|scope| !scope.is_empty())
                .cloned(),
        )
    }

    pub fn effective_client_registration_scopes(&self) -> Vec<String> {
        deduplicate(
            self.client_registration_default_scopes
                .as_ref()
                .unwrap_or(&self.scopes)
                .iter()
                .chain(&self.client_registration_allowed_scopes)
                .cloned(),
        )
    }

    pub fn effective_client_registration_resources(&self) -> Vec<String> {
        deduplicate(
            self.client_registration_default_resources
                .iter()
                .chain(&self.client_registration_allowed_resources)
                .cloned(),
        )
    }

    pub fn stores_hashed_client_secrets(&self) -> bool {
        match &self.store_client_secret {
            OAuthClientSecretStorage::Automatic => !self.disable_jwt_plugin,
            OAuthClientSecretStorage::Hashed | OAuthClientSecretStorage::CustomHashed(_) => true,
            OAuthClientSecretStorage::Encrypted | OAuthClientSecretStorage::CustomEncrypted(_) => {
                false
            }
        }
    }
}

fn validate_pages(config: &OAuthProviderConfig) -> Result<(), OAuthProviderConfigError> {
    if config.login_page.is_empty() {
        return Err(OAuthProviderConfigError::MissingLoginPage);
    }
    if config.consent_page.is_empty() {
        return Err(OAuthProviderConfigError::MissingConsentPage);
    }
    Ok(())
}

fn validate_scopes(config: &OAuthProviderConfig) -> Result<(), OAuthProviderConfigError> {
    let scopes: BTreeSet<&str> = config
        .scopes
        .iter()
        .filter(|scope| !scope.is_empty())
        .map(String::as_str)
        .collect();
    let allowed = config
        .client_registration_default_scopes
        .iter()
        .flatten()
        .chain(&config.client_registration_allowed_scopes);
    for scope in allowed {
        if !scopes.contains(scope.as_str()) {
            return Err(OAuthProviderConfigError::UnknownRegistrationScope(
                scope.clone(),
            ));
        }
    }
    for scope in config.advertised_metadata.scopes_supported.iter().flatten() {
        if !scopes.contains(scope.as_str()) {
            return Err(OAuthProviderConfigError::UnknownAdvertisedScope(
                scope.clone(),
            ));
        }
    }
    Ok(())
}

fn validate_resources(config: &OAuthProviderConfig) -> Result<(), OAuthProviderConfigError> {
    let resources: BTreeSet<&str> = config
        .resources
        .iter()
        .map(|resource| resource.identifier.as_str())
        .collect();
    for identifier in config
        .client_registration_default_resources
        .iter()
        .chain(&config.client_registration_allowed_resources)
    {
        if !resources.contains(identifier.as_str()) {
            return Err(OAuthProviderConfigError::UnknownRegistrationResource(
                identifier.clone(),
            ));
        }
    }
    Ok(())
}

include!("config/extension_validation.rs");
fn validate_security(config: &OAuthProviderConfig) -> Result<(), OAuthProviderConfigError> {
    super::schema::ResolvedOAuthProviderSchema::new(&config.schema)?;
    if config
        .pairwise_secret
        .as_ref()
        .is_some_and(|secret| secret.len() < 32)
    {
        return Err(OAuthProviderConfigError::PairwiseSecretTooShort);
    }
    if config
        .grant_types
        .iter()
        .any(|grant| grant == "refresh_token")
        && !config
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
    {
        return Err(OAuthProviderConfigError::RefreshRequiresAuthorizationCode);
    }
    let encrypted = matches!(
        config.store_client_secret,
        OAuthClientSecretStorage::Encrypted | OAuthClientSecretStorage::CustomEncrypted(_)
    );
    let hashed = matches!(
        config.store_client_secret,
        OAuthClientSecretStorage::Hashed | OAuthClientSecretStorage::CustomHashed(_)
    );
    if config.disable_jwt_plugin && hashed {
        return Err(OAuthProviderConfigError::HashedSecretWithoutJwt);
    }
    if !config.disable_jwt_plugin && encrypted {
        return Err(OAuthProviderConfigError::EncryptedSecretWithJwt);
    }
    Ok(())
}

fn deduplicate(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

impl fmt::Debug for OAuthProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthProviderConfig")
            .field("scopes", &self.scopes)
            .field("resources", &self.resources)
            .field("grant_types", &self.grant_types)
            .field("login_page", &self.login_page)
            .field("consent_page", &self.consent_page)
            .field("disable_jwt_plugin", &self.disable_jwt_plugin)
            .field("callbacks_configured", &true)
            .field("extensions", &self.extensions.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for OAuthClientSecretStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Automatic => "Automatic",
            Self::Hashed => "Hashed",
            Self::Encrypted => "Encrypted",
            Self::CustomHashed(_) => "CustomHashed(..)",
            Self::CustomEncrypted(_) => "CustomEncrypted(..)",
        })
    }
}

impl fmt::Debug for OAuthTokenStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Hashed => "Hashed",
            Self::Custom(_) => "Custom(..)",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct GrantExtension(&'static str);

    #[async_trait]
    impl OAuthProviderExtension for GrantExtension {
        fn grant_types(&self) -> Vec<String> {
            vec![self.0.into()]
        }
    }

    struct ReservedAuthExtension;

    #[async_trait]
    impl OAuthProviderExtension for ReservedAuthExtension {
        fn client_authentication_methods(&self) -> Vec<OAuthExtensionClientAuthenticationMethod> {
            vec![OAuthExtensionClientAuthenticationMethod {
                method: "client_secret_post".into(),
                assertion_types: vec!["urn:example:assertion".into()],
            }]
        }
    }

    #[test]
    fn defaults_match_better_auth_1_7_1() {
        let config = OAuthProviderConfig::new("/login", "/consent");
        assert_eq!(config.scopes, DEFAULT_SCOPES);
        assert_eq!(config.grant_types, DEFAULT_GRANT_TYPES);
        assert_eq!(config.access_token_expires_in, 3600);
        assert_eq!(config.id_token_expires_in, 36_000);
        assert_eq!(config.refresh_token_expires_in, 2_592_000);
        assert_eq!(config.code_expires_in, 600);
        assert!(config.enforce_per_client_resources);
        assert!(config.client_registration_require_pkce);
        assert_eq!(config.dpop.proof_max_age_seconds, 300);
    }

    #[test]
    fn validation_matches_upstream_cross_option_rules() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.grant_types = vec!["refresh_token".into()];
        assert_eq!(
            config.validate(),
            Err(OAuthProviderConfigError::RefreshRequiresAuthorizationCode)
        );
        config.grant_types.push("authorization_code".into());
        config.pairwise_secret = Some("short".into());
        assert_eq!(
            config.validate(),
            Err(OAuthProviderConfigError::PairwiseSecretTooShort)
        );
    }

    #[test]
    fn effective_registration_capabilities_are_deduplicated_in_input_order() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.client_registration_default_scopes = Some(vec!["openid".into(), "email".into()]);
        config.client_registration_allowed_scopes = vec!["email".into(), "profile".into()];
        assert_eq!(
            config.effective_client_registration_scopes(),
            vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned()
            ]
        );
        assert!(config.stores_hashed_client_secrets());
        config.disable_jwt_plugin = true;
        assert!(!config.stores_hashed_client_secrets());
    }

    #[test]
    fn registration_scopes_start_from_provider_scopes_when_defaults_are_omitted() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.client_registration_allowed_scopes = vec!["payments:read".into()];
        config.scopes.push("payments:read".into());
        assert_eq!(
            config.effective_client_registration_scopes(),
            vec![
                "openid",
                "profile",
                "email",
                "offline_access",
                "payments:read"
            ]
        );
    }

    #[test]
    fn extension_dispatch_keys_must_be_absolute_non_reserved_and_disjoint() {
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.extensions = vec![Arc::new(GrantExtension("not-a-uri"))];
        assert!(matches!(
            config.validate(),
            Err(OAuthProviderConfigError::InvalidExtension(_))
        ));
        config.extensions = vec![
            Arc::new(GrantExtension("urn:example:grant")),
            Arc::new(GrantExtension("urn:example:grant")),
        ];
        assert!(matches!(
            config.validate(),
            Err(OAuthProviderConfigError::InvalidExtension(_))
        ));
        config.extensions = vec![Arc::new(ReservedAuthExtension)];
        assert!(matches!(
            config.validate(),
            Err(OAuthProviderConfigError::InvalidExtension(_))
        ));
    }
}
