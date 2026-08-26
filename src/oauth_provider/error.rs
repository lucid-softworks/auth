/// Invalid Better Auth OAuth Provider option combinations detected at startup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthProviderConfigError {
    #[error("loginPage must not be empty")]
    MissingLoginPage,
    #[error("consentPage must not be empty")]
    MissingConsentPage,
    #[error("client registration scope `{0}` was not found in scopes")]
    UnknownRegistrationScope(String),
    #[error("advertised metadata scope `{0}` was not found in scopes")]
    UnknownAdvertisedScope(String),
    #[error("client registration resource `{0}` was not found in resources")]
    UnknownRegistrationResource(String),
    #[error("pairwiseSecret must be at least 32 characters long for adequate HMAC-SHA256 security")]
    PairwiseSecretTooShort,
    #[error("refresh_token grant requires authorization_code grant")]
    RefreshRequiresAuthorizationCode,
    #[error("unable to store hashed secrets because id tokens will be signed with secret")]
    HashedSecretWithoutJwt,
    #[error(
        "encryption method not recommended, please use hashed secret storage with the JWT plugin"
    )]
    EncryptedSecretWithJwt,
    #[error("invalid OAuth Provider extension: {0}")]
    InvalidExtension(String),
}

/// OAuth 2.0, OAuth 2.1, OIDC, and DPoP protocol failures emitted on the wire.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OAuthProviderError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("invalid_redirect_uri: {0}")]
    InvalidRedirectUri(String),
    #[error("invalid_request: {0}")]
    UnauthorizedInvalidRequest(String),
    #[error("invalid_user: {0}")]
    InvalidUser(String),
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    #[error("invalid_client: {0}")]
    UnauthorizedInvalidClient(String),
    #[error("invalid_client: {0}")]
    BasicInvalidClient(String),
    #[error("invalid_client: {description}")]
    ChallengedInvalidClient { description: String, scheme: String },
    #[error("{0}")]
    UnsupportedMediaType(String),
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),
    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_target: {0}")]
    InvalidTarget(String),
    #[error("access_denied: {0}")]
    AccessDenied(String),
    #[error("authorization_pending: {0}")]
    AuthorizationPending(String),
    #[error("slow_down: {0}")]
    SlowDown(String),
    #[error("expired_token: {0}")]
    ExpiredToken(String),
    #[error("interaction_required: {0}")]
    InteractionRequired(String),
    #[error("login_required: {0}")]
    LoginRequired(String),
    #[error("account_selection_required: {0}")]
    AccountSelectionRequired(String),
    #[error("consent_required: {0}")]
    ConsentRequired(String),
    #[error("request_not_supported: {0}")]
    RequestNotSupported(String),
    #[error("invalid_request_uri: {0}")]
    InvalidRequestUri(String),
    #[error("request_uri_not_supported: {0}")]
    RequestUriNotSupported(String),
    #[error("invalid_token: {0}")]
    InvalidToken(String),
    #[error("invalid_token: {0}")]
    UnchallengedInvalidToken(String),
    #[error("insufficient_scope: {description}")]
    InsufficientScope {
        description: String,
        required_scopes: Vec<String>,
    },
    #[error("invalid_dpop_proof: {0}")]
    InvalidDpopProof(String),
    #[error("use_dpop_nonce: {0}")]
    UseDpopNonce(String),
    #[error("unsupported_token_type: {0}")]
    UnsupportedTokenType(String),
    #[error("server_error: {0}")]
    ServerError(String),
    #[error("temporarily_unavailable: {0}")]
    TemporarilyUnavailable(String),
}

impl OAuthProviderError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidRedirectUri(_) => "invalid_redirect_uri",
            Self::UnauthorizedInvalidRequest(_) => "invalid_request",
            Self::InvalidUser(_) => "invalid_user",
            Self::InvalidClient(_) => "invalid_client",
            Self::UnauthorizedInvalidClient(_) => "invalid_client",
            Self::BasicInvalidClient(_) => "invalid_client",
            Self::ChallengedInvalidClient { .. } => "invalid_client",
            Self::UnsupportedMediaType(_) => "UNSUPPORTED_MEDIA_TYPE",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::UnsupportedGrantType(_) => "unsupported_grant_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::InvalidTarget(_) => "invalid_target",
            Self::AccessDenied(_) => "access_denied",
            Self::AuthorizationPending(_) => "authorization_pending",
            Self::SlowDown(_) => "slow_down",
            Self::ExpiredToken(_) => "expired_token",
            Self::InteractionRequired(_) => "interaction_required",
            Self::LoginRequired(_) => "login_required",
            Self::AccountSelectionRequired(_) => "account_selection_required",
            Self::ConsentRequired(_) => "consent_required",
            Self::RequestNotSupported(_) => "request_not_supported",
            Self::InvalidRequestUri(_) => "invalid_request_uri",
            Self::RequestUriNotSupported(_) => "request_uri_not_supported",
            Self::InvalidToken(_) => "invalid_token",
            Self::UnchallengedInvalidToken(_) => "invalid_token",
            Self::InsufficientScope { .. } => "insufficient_scope",
            Self::InvalidDpopProof(_) => "invalid_dpop_proof",
            Self::UseDpopNonce(_) => "use_dpop_nonce",
            Self::UnsupportedTokenType(_) => "unsupported_token_type",
            Self::ServerError(_) => "server_error",
            Self::TemporarilyUnavailable(_) => "temporarily_unavailable",
        }
    }

    pub const fn status_code(&self) -> u16 {
        match self {
            Self::UnauthorizedInvalidClient(_)
            | Self::BasicInvalidClient(_)
            | Self::ChallengedInvalidClient { .. }
            | Self::InvalidToken(_)
            | Self::UnchallengedInvalidToken(_)
            | Self::UnauthorizedInvalidRequest(_) => 401,
            Self::UnsupportedMediaType(_) => 415,
            Self::InsufficientScope { .. } => 403,
            Self::ServerError(_) => 500,
            Self::TemporarilyUnavailable(_) => 503,
            _ => 400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_errors_have_standards_status_codes() {
        let invalid = OAuthProviderError::InvalidToken("expired".into());
        assert_eq!(invalid.code(), "invalid_token");
        assert_eq!(invalid.status_code(), 401);
        assert_eq!(
            OAuthProviderError::InsufficientScope {
                description: "access token is missing required scope: write".into(),
                required_scopes: vec!["write".into()],
            }
            .status_code(),
            403
        );
        let pkce =
            OAuthProviderError::UnauthorizedInvalidRequest("code verification failed".into());
        assert_eq!(pkce.code(), "invalid_request");
        assert_eq!(pkce.status_code(), 401);
        assert_eq!(
            OAuthProviderError::InvalidClient("post".into()).status_code(),
            400
        );
        assert_eq!(
            OAuthProviderError::BasicInvalidClient("basic".into()).status_code(),
            401
        );
        assert_eq!(
            OAuthProviderError::InvalidUser("deleted".into()).code(),
            "invalid_user"
        );
    }
}
