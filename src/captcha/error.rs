#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CaptchaError {
    #[error("Captcha verification failed")]
    VerificationFailed,
    #[error("Missing CAPTCHA response")]
    MissingResponse,
    #[error("Something went wrong")]
    UnknownError,
}

impl CaptchaError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::VerificationFailed => "VERIFICATION_FAILED",
            Self::MissingResponse => "MISSING_RESPONSE",
            Self::UnknownError => "UNKNOWN_ERROR",
        }
    }

    pub const fn status(self) -> u16 {
        match self {
            Self::MissingResponse => 400,
            Self::VerificationFailed => 403,
            Self::UnknownError => 500,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_codes_messages_and_statuses_are_exact() {
        assert_eq!(CaptchaError::MissingResponse.code(), "MISSING_RESPONSE");
        assert_eq!(
            CaptchaError::MissingResponse.to_string(),
            "Missing CAPTCHA response"
        );
        assert_eq!(CaptchaError::MissingResponse.status(), 400);
        assert_eq!(
            CaptchaError::VerificationFailed.code(),
            "VERIFICATION_FAILED"
        );
        assert_eq!(CaptchaError::VerificationFailed.status(), 403);
        assert_eq!(CaptchaError::UnknownError.code(), "UNKNOWN_ERROR");
        assert_eq!(CaptchaError::UnknownError.status(), 500);
    }
}
