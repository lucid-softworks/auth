/// Better Auth 1.7 account configuration.
#[derive(Debug, Clone, Default)]
pub struct AccountConfig {
    pub account_linking: AccountLinkingConfig,
    pub additional_fields: crate::AdditionalFieldSet,
    /// Stores the selected provider account in Better Auth's encrypted
    /// `account_data` cookie. Disabled by default when a database is present.
    pub store_account_cookie: bool,
    /// Encrypt persisted OAuth access and refresh tokens. Better Auth defaults
    /// this to false; ID tokens are stored as returned by the provider.
    pub encrypt_oauth_tokens: bool,
    /// Better Auth OAuth-state storage strategy. Stateful configurations use
    /// the database by default; stateless hosts may select the encrypted cookie.
    pub store_state_strategy: OAuthStateStrategy,
    pub skip_state_cookie_check: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OAuthStateStrategy {
    #[default]
    Database,
    Cookie,
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
