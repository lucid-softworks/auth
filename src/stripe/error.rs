use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{message}")]
#[serde(rename_all = "camelCase")]
pub struct StripeError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl StripeError {
    pub fn from_code(status: u16, code: StripeErrorCode) -> Self {
        Self {
            status,
            code: code.as_str().to_owned(),
            message: code.message().to_owned(),
        }
    }

    pub fn provider_bad_request(code: Option<&str>, message: impl Into<String>) -> Self {
        Self {
            status: 400,
            code: code.unwrap_or("BAD_REQUEST").to_owned(),
            message: message.into(),
        }
    }
}

/// Better Auth Stripe 1.7.1's complete exported error dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StripeErrorCode {
    Unauthorized,
    InvalidRequestBody,
    SubscriptionNotFound,
    SubscriptionPlanNotFound,
    AlreadySubscribedPlan,
    ReferenceIdNotAllowed,
    CustomerNotFound,
    UnableToCreateCustomer,
    UnableToCreateBillingPortal,
    StripeSignatureNotFound,
    StripeWebhookSecretNotFound,
    StripeWebhookError,
    FailedToConstructStripeEvent,
    FailedToFetchPlans,
    EmailVerificationRequired,
    SubscriptionNotActive,
    SubscriptionNotScheduledForCancellation,
    SubscriptionNotPendingChange,
    OrganizationNotFound,
    OrganizationSubscriptionNotEnabled,
    AuthorizeReferenceRequired,
    OrganizationHasActiveSubscription,
    OrganizationReferenceIdRequired,
}

impl StripeErrorCode {
    pub const ALL: [Self; 23] = [
        Self::Unauthorized,
        Self::InvalidRequestBody,
        Self::SubscriptionNotFound,
        Self::SubscriptionPlanNotFound,
        Self::AlreadySubscribedPlan,
        Self::ReferenceIdNotAllowed,
        Self::CustomerNotFound,
        Self::UnableToCreateCustomer,
        Self::UnableToCreateBillingPortal,
        Self::StripeSignatureNotFound,
        Self::StripeWebhookSecretNotFound,
        Self::StripeWebhookError,
        Self::FailedToConstructStripeEvent,
        Self::FailedToFetchPlans,
        Self::EmailVerificationRequired,
        Self::SubscriptionNotActive,
        Self::SubscriptionNotScheduledForCancellation,
        Self::SubscriptionNotPendingChange,
        Self::OrganizationNotFound,
        Self::OrganizationSubscriptionNotEnabled,
        Self::AuthorizeReferenceRequired,
        Self::OrganizationHasActiveSubscription,
        Self::OrganizationReferenceIdRequired,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidRequestBody => "INVALID_REQUEST_BODY",
            Self::SubscriptionNotFound => "SUBSCRIPTION_NOT_FOUND",
            Self::SubscriptionPlanNotFound => "SUBSCRIPTION_PLAN_NOT_FOUND",
            Self::AlreadySubscribedPlan => "ALREADY_SUBSCRIBED_PLAN",
            Self::ReferenceIdNotAllowed => "REFERENCE_ID_NOT_ALLOWED",
            Self::CustomerNotFound => "CUSTOMER_NOT_FOUND",
            Self::UnableToCreateCustomer => "UNABLE_TO_CREATE_CUSTOMER",
            Self::UnableToCreateBillingPortal => "UNABLE_TO_CREATE_BILLING_PORTAL",
            Self::StripeSignatureNotFound => "STRIPE_SIGNATURE_NOT_FOUND",
            Self::StripeWebhookSecretNotFound => "STRIPE_WEBHOOK_SECRET_NOT_FOUND",
            Self::StripeWebhookError => "STRIPE_WEBHOOK_ERROR",
            Self::FailedToConstructStripeEvent => "FAILED_TO_CONSTRUCT_STRIPE_EVENT",
            Self::FailedToFetchPlans => "FAILED_TO_FETCH_PLANS",
            Self::EmailVerificationRequired => "EMAIL_VERIFICATION_REQUIRED",
            Self::SubscriptionNotActive => "SUBSCRIPTION_NOT_ACTIVE",
            Self::SubscriptionNotScheduledForCancellation => {
                "SUBSCRIPTION_NOT_SCHEDULED_FOR_CANCELLATION"
            }
            Self::SubscriptionNotPendingChange => "SUBSCRIPTION_NOT_PENDING_CHANGE",
            Self::OrganizationNotFound => "ORGANIZATION_NOT_FOUND",
            Self::OrganizationSubscriptionNotEnabled => "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED",
            Self::AuthorizeReferenceRequired => "AUTHORIZE_REFERENCE_REQUIRED",
            Self::OrganizationHasActiveSubscription => "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION",
            Self::OrganizationReferenceIdRequired => "ORGANIZATION_REFERENCE_ID_REQUIRED",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::Unauthorized => "Unauthorized access",
            Self::InvalidRequestBody => "Invalid request body",
            Self::SubscriptionNotFound => "Subscription not found",
            Self::SubscriptionPlanNotFound => "Subscription plan not found",
            Self::AlreadySubscribedPlan => "You're already subscribed to this plan",
            Self::ReferenceIdNotAllowed => "Reference id is not allowed",
            Self::CustomerNotFound => "Stripe customer not found for this user",
            Self::UnableToCreateCustomer => "Unable to create customer",
            Self::UnableToCreateBillingPortal => "Unable to create billing portal session",
            Self::StripeSignatureNotFound => "Stripe signature not found",
            Self::StripeWebhookSecretNotFound => "Stripe webhook secret not found",
            Self::StripeWebhookError => "Stripe webhook error",
            Self::FailedToConstructStripeEvent => "Failed to construct Stripe event",
            Self::FailedToFetchPlans => "Failed to fetch plans",
            Self::EmailVerificationRequired => {
                "Email verification is required before you can subscribe to a plan"
            }
            Self::SubscriptionNotActive => "Subscription is not active",
            Self::SubscriptionNotScheduledForCancellation => {
                "Subscription is not scheduled for cancellation"
            }
            Self::SubscriptionNotPendingChange => {
                "Subscription has no pending cancellation or scheduled plan change"
            }
            Self::OrganizationNotFound => "Organization not found",
            Self::OrganizationSubscriptionNotEnabled => "Organization subscription is not enabled",
            Self::AuthorizeReferenceRequired => {
                "Organization subscriptions require authorizeReference callback to be configured"
            }
            Self::OrganizationHasActiveSubscription => {
                "Cannot delete organization with active subscription"
            }
            Self::OrganizationReferenceIdRequired => {
                "Reference ID is required. Provide referenceId or set activeOrganizationId in session"
            }
        }
    }
}

impl std::fmt::Display for StripeErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_the_exact_deprecated_and_current_pending_change_codes() {
        assert_eq!(StripeErrorCode::ALL.len(), 23);
        assert_eq!(
            StripeErrorCode::SubscriptionNotScheduledForCancellation.message(),
            "Subscription is not scheduled for cancellation"
        );
        assert_eq!(
            StripeErrorCode::SubscriptionNotPendingChange.message(),
            "Subscription has no pending cancellation or scheduled plan change"
        );
    }
}
