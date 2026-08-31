/// Configuration for the pinned enterprise SSO plugin surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoOptions {
    /// Enables the two published DNS domain-verification endpoints and field.
    pub domain_verification: bool,
    /// Maximum providers one user may register. Upstream defaults to ten.
    pub providers_limit: usize,
    /// Publishes SAML single-logout bindings in generated SP metadata.
    pub saml_enable_single_logout: bool,
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
            domain_verification: false,
            providers_limit: 10,
            saml_enable_single_logout: false,
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
