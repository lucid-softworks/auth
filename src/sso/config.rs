use serde_json::Value;

/// One non-persisted SSO provider with precedence over database providers.
#[derive(Debug, Clone, PartialEq)]
pub struct SsoDefaultProvider {
    pub domain: String,
    pub provider_id: String,
    pub oidc_config: Option<Value>,
    pub saml_config: Option<Value>,
    pub private_key: Option<super::SsoPrivateKey>,
}

impl SsoDefaultProvider {
    pub(crate) fn into_provider(self, domain_verification: bool) -> super::SsoProvider {
        let issuer = self
            .oidc_config
            .as_ref()
            .or(self.saml_config.as_ref())
            .and_then(Value::as_object)
            .and_then(|config| config.get("issuer"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        super::SsoProvider {
            id: format!("default-sso:{}", self.provider_id),
            issuer,
            oidc_config: self.oidc_config,
            saml_config: self.saml_config,
            user_id: "default".into(),
            provider_id: self.provider_id,
            organization_id: None,
            domain: self.domain,
            domain_verified: domain_verification.then_some(true),
        }
    }
}

/// Configuration for the pinned enterprise SSO plugin surface.
#[derive(Debug, Clone, PartialEq)]
pub struct SsoOptions {
    /// Non-persisted providers selected before database providers.
    pub default_sso: Vec<SsoDefaultProvider>,
    /// Enables the two published DNS domain-verification endpoints and field.
    pub domain_verification: bool,
    /// Maximum providers one user may register. Upstream defaults to ten.
    pub providers_limit: usize,
    /// Publishes SAML single-logout bindings in generated SP metadata.
    pub saml_enable_single_logout: bool,
    /// Requires signed inbound IdP LogoutRequest messages.
    pub saml_want_logout_request_signed: bool,
    /// Requires signed inbound IdP LogoutResponse messages.
    pub saml_want_logout_response_signed: bool,
    /// Lifetime of an SP-initiated LogoutRequest correlation record.
    pub saml_logout_request_ttl_ms: i64,
    /// Accepts signed unsolicited IdP-initiated SAML responses.
    pub saml_allow_idp_initiated: bool,
    /// Plugin-wide fallback callback for IdP-initiated SAML responses.
    pub saml_idp_initiated_callback_url: Option<String>,
    /// Shared OIDC callback URI. Relative values resolve below the auth base URL.
    pub redirect_uri: Option<String>,
    /// Trusts the provider's mapped `email_verified` claim.
    pub trust_email_verified: bool,
    /// Requires callers to opt into creating a new user with `requestSignUp`.
    pub disable_implicit_sign_up: bool,
    /// SAML signature, digest, and encryption algorithm policy.
    pub saml_algorithms: super::SamlAlgorithmOptions,
    /// SAML response-size ceiling in bytes. Upstream defaults to 256 KiB.
    pub saml_max_response_size: usize,
    /// SAML clock-skew tolerance in milliseconds.
    pub saml_clock_skew_ms: i64,
    /// Requires at least one assertion Conditions timestamp.
    pub saml_require_timestamps: bool,
}

impl Default for SsoOptions {
    fn default() -> Self {
        Self {
            default_sso: Vec::new(),
            domain_verification: false,
            providers_limit: 10,
            saml_enable_single_logout: false,
            saml_want_logout_request_signed: false,
            saml_want_logout_response_signed: false,
            saml_logout_request_ttl_ms: 300_000,
            saml_allow_idp_initiated: false,
            saml_idp_initiated_callback_url: None,
            redirect_uri: None,
            trust_email_verified: false,
            disable_implicit_sign_up: false,
            saml_algorithms: super::SamlAlgorithmOptions::default(),
            saml_max_response_size: super::DEFAULT_MAX_SAML_RESPONSE_SIZE,
            saml_clock_skew_ms: super::DEFAULT_CLOCK_SKEW_MS,
            saml_require_timestamps: false,
        }
    }
}
