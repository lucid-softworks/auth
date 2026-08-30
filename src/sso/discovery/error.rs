#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryErrorCode {
    InvalidUrl,
    PrivateHost,
    UntrustedOrigin,
    Incomplete,
    IssuerMismatch,
    NotFound,
    Timeout,
    InvalidJson,
    Unexpected,
    EndpointRedirect,
}

impl DiscoveryErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUrl => "discovery_invalid_url",
            Self::PrivateHost => "discovery_private_host",
            Self::UntrustedOrigin => "discovery_untrusted_origin",
            Self::Incomplete => "discovery_incomplete",
            Self::IssuerMismatch => "issuer_mismatch",
            Self::NotFound => "discovery_not_found",
            Self::Timeout => "discovery_timeout",
            Self::InvalidJson => "discovery_invalid_json",
            Self::Unexpected => "discovery_unexpected_error",
            Self::EndpointRedirect => "oidc_endpoint_redirect",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DiscoveryError {
    pub code: DiscoveryErrorCode,
    pub message: String,
}

impl DiscoveryError {
    pub(super) fn new(code: DiscoveryErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
