use crate::stripe::StripeErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StripeWebhookError {
    #[error("Invalid request body")]
    InvalidRequestBody,
    #[error("Stripe signature not found")]
    SignatureNotFound,
    #[error("Stripe webhook secret not found")]
    WebhookSecretNotFound,
    #[error("Failed to construct Stripe event")]
    FailedToConstructEvent,
    #[error("Stripe webhook error")]
    EventCallback,
}

impl StripeWebhookError {
    pub const fn code(self) -> StripeErrorCode {
        match self {
            Self::InvalidRequestBody => StripeErrorCode::InvalidRequestBody,
            Self::SignatureNotFound => StripeErrorCode::StripeSignatureNotFound,
            Self::WebhookSecretNotFound => StripeErrorCode::StripeWebhookSecretNotFound,
            Self::FailedToConstructEvent => StripeErrorCode::FailedToConstructStripeEvent,
            Self::EventCallback => StripeErrorCode::StripeWebhookError,
        }
    }

    pub const fn status(self) -> u16 {
        match self {
            Self::WebhookSecretNotFound => 500,
            Self::InvalidRequestBody
            | Self::SignatureNotFound
            | Self::FailedToConstructEvent
            | Self::EventCallback => 400,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_outer_callback_failures_have_exact_better_auth_codes() {
        assert_eq!(
            StripeWebhookError::SignatureNotFound.code(),
            StripeErrorCode::StripeSignatureNotFound
        );
        assert_eq!(StripeWebhookError::WebhookSecretNotFound.status(), 500);
        assert_eq!(
            StripeWebhookError::EventCallback.code(),
            StripeErrorCode::StripeWebhookError
        );
    }
}
