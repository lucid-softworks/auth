#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryErrorCode {
    InvalidUrl,
    PrivateHost,
    UntrustedOrigin,
    Incomplete,
    IssuerMismatch,
}

impl DiscoveryErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUrl => "discovery_invalid_url",
            Self::PrivateHost => "discovery_private_host",
            Self::UntrustedOrigin => "discovery_untrusted_origin",
            Self::Incomplete => "discovery_incomplete",
            Self::IssuerMismatch => "issuer_mismatch",
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
