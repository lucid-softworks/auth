use crate::AuthError;

/// Stable error codes published by Better Auth's MongoDB adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MongoAdapterErrorCode {
    InvalidId,
    UnsupportedOperator,
}

impl MongoAdapterErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidId => "INVALID_ID",
            Self::UnsupportedOperator => "UNSUPPORTED_OPERATOR",
        }
    }
}

/// MongoDB adapter contract error with the upstream stable code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct MongoAdapterError {
    pub code: MongoAdapterErrorCode,
    pub message: String,
}

impl MongoAdapterError {
    pub(crate) fn invalid_id() -> Self {
        Self {
            code: MongoAdapterErrorCode::InvalidId,
            message: "Invalid id value".into(),
        }
    }

    pub(crate) fn unsupported_operator(operator: &str) -> Self {
        Self {
            code: MongoAdapterErrorCode::UnsupportedOperator,
            message: format!("Unsupported operator: {operator}"),
        }
    }
}

impl From<MongoAdapterError> for AuthError {
    fn from(error: MongoAdapterError) -> Self {
        Self::Storage(format!("{}: {}", error.code.as_str(), error.message))
    }
}
