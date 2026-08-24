#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrganizationErrorStatus {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    InternalServerError,
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct OrganizationError {
    pub status: OrganizationErrorStatus,
    pub code: &'static str,
    pub message: String,
}

impl OrganizationError {
    pub fn new(
        status: OrganizationErrorStatus,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }

    pub(crate) fn bad_request(code: &'static str, message: &'static str) -> Self {
        Self::new(OrganizationErrorStatus::BadRequest, code, message)
    }

    pub(crate) fn unauthorized(code: &'static str, message: &'static str) -> Self {
        Self::new(OrganizationErrorStatus::Unauthorized, code, message)
    }

    pub(crate) fn forbidden(code: &'static str, message: &'static str) -> Self {
        Self::new(OrganizationErrorStatus::Forbidden, code, message)
    }

    pub(crate) fn not_found(code: &'static str, message: &'static str) -> Self {
        Self::new(OrganizationErrorStatus::NotFound, code, message)
    }
}
