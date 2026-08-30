use super::SCIM_ERROR_SCHEMA;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScimErrorType {
    InvalidFilter,
    TooMany,
    Uniqueness,
    Mutability,
    InvalidSyntax,
    InvalidPath,
    NoTarget,
    InvalidValue,
    Sensitive,
}

impl ScimErrorType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidFilter => "invalidFilter",
            Self::TooMany => "tooMany",
            Self::Uniqueness => "uniqueness",
            Self::Mutability => "mutability",
            Self::InvalidSyntax => "invalidSyntax",
            Self::InvalidPath => "invalidPath",
            Self::NoTarget => "noTarget",
            Self::InvalidValue => "invalidValue",
            Self::Sensitive => "sensitive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorBody {
    pub schemas: [&'static str; 1],
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<ScimErrorType>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{detail}")]
pub struct ScimError {
    pub status: u16,
    pub detail: String,
    pub scim_type: Option<ScimErrorType>,
    pub authenticate: bool,
}

impl ScimError {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
            scim_type: None,
            authenticate: false,
        }
    }

    pub fn typed(
        status: u16,
        detail: impl Into<String>,
        scim_type: ScimErrorType,
    ) -> Self {
        Self {
            status,
            detail: detail.into(),
            scim_type: Some(scim_type),
            authenticate: false,
        }
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self {
            status: 401,
            detail: detail.into(),
            scim_type: None,
            authenticate: true,
        }
    }

    pub fn body(&self) -> ScimErrorBody {
        ScimErrorBody {
            schemas: [SCIM_ERROR_SCHEMA],
            status: self.status.to_string(),
            detail: Some(self.detail.clone()),
            scim_type: self.scim_type,
        }
    }
}
