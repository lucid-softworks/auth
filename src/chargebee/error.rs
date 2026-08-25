use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChargebeeErrorCode {
    AlreadySubscribed,
    SubscriptionNotFound,
    PlanNotFound,
    CustomerNotFound,
    OrganizationNotFound,
    UnauthorizedReference,
    ActiveSubscriptionExists,
    OrganizationHasActiveSubscriptions,
    WebhookVerificationFailed,
    EmailVerificationRequired,
    UnableToCreateCustomer,
    OrganizationSubscriptionNotEnabled,
    AuthorizeReferenceRequired,
    OrganizationReferenceIdRequired,
}

impl ChargebeeErrorCode {
    pub const ALL: [Self; 14] = [
        Self::AlreadySubscribed,
        Self::SubscriptionNotFound,
        Self::PlanNotFound,
        Self::CustomerNotFound,
        Self::OrganizationNotFound,
        Self::UnauthorizedReference,
        Self::ActiveSubscriptionExists,
        Self::OrganizationHasActiveSubscriptions,
        Self::WebhookVerificationFailed,
        Self::EmailVerificationRequired,
        Self::UnableToCreateCustomer,
        Self::OrganizationSubscriptionNotEnabled,
        Self::AuthorizeReferenceRequired,
        Self::OrganizationReferenceIdRequired,
    ];

    pub const fn code(self) -> &'static str {
        match self {
            Self::AlreadySubscribed => "ALREADY_SUBSCRIBED",
            Self::SubscriptionNotFound => "SUBSCRIPTION_NOT_FOUND",
            Self::PlanNotFound => "PLAN_NOT_FOUND",
            Self::CustomerNotFound => "CUSTOMER_NOT_FOUND",
            Self::OrganizationNotFound => "ORGANIZATION_NOT_FOUND",
            Self::UnauthorizedReference => "UNAUTHORIZED_REFERENCE",
            Self::ActiveSubscriptionExists => "ACTIVE_SUBSCRIPTION_EXISTS",
            Self::OrganizationHasActiveSubscriptions => "ORG_HAS_ACTIVE_SUBSCRIPTIONS",
            Self::WebhookVerificationFailed => "WEBHOOK_VERIFICATION_FAILED",
            Self::EmailVerificationRequired => "EMAIL_VERIFICATION_REQUIRED",
            Self::UnableToCreateCustomer => "UNABLE_TO_CREATE_CUSTOMER",
            Self::OrganizationSubscriptionNotEnabled => "ORGANIZATION_SUBSCRIPTION_NOT_ENABLED",
            Self::AuthorizeReferenceRequired => "AUTHORIZE_REFERENCE_REQUIRED",
            Self::OrganizationReferenceIdRequired => "ORGANIZATION_REFERENCE_ID_REQUIRED",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::AlreadySubscribed => "You're already subscribed to this plan",
            Self::SubscriptionNotFound => "Subscription not found",
            Self::PlanNotFound => "Plan not found",
            Self::CustomerNotFound => "Chargebee customer not found for this user",
            Self::OrganizationNotFound => "Organization not found",
            Self::UnauthorizedReference => "Unauthorized access to this reference",
            Self::ActiveSubscriptionExists => "An active subscription already exists",
            Self::OrganizationHasActiveSubscriptions => {
                "Cannot delete organization with active subscriptions"
            }
            Self::WebhookVerificationFailed => "Webhook verification failed",
            Self::EmailVerificationRequired => {
                "Email verification is required before you can subscribe to a plan"
            }
            Self::UnableToCreateCustomer => "Unable to create Chargebee customer",
            Self::OrganizationSubscriptionNotEnabled => "Organization subscription is not enabled",
            Self::AuthorizeReferenceRequired => {
                "Organization subscriptions require authorizeReference callback to be configured"
            }
            Self::OrganizationReferenceIdRequired => {
                "Reference ID is required. Provide referenceId or set activeOrganizationId in session"
            }
        }
    }
}

impl fmt::Display for ChargebeeErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ChargebeeApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ChargebeeApiError {
    pub fn code(status: u16, code: ChargebeeErrorCode) -> Self {
        Self {
            status,
            code: code.code(),
            message: code.message().to_owned(),
        }
    }

    pub fn literal(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ChargebeeErrorCode;

    #[test]
    fn published_error_catalog_has_exact_names_and_messages() {
        assert_eq!(ChargebeeErrorCode::ALL.len(), 14);
        assert_eq!(
            ChargebeeErrorCode::AlreadySubscribed.message(),
            "You're already subscribed to this plan"
        );
        assert_eq!(
            ChargebeeErrorCode::OrganizationHasActiveSubscriptions.code(),
            "ORG_HAS_ACTIVE_SUBSCRIPTIONS"
        );
        assert_eq!(
            ChargebeeErrorCode::OrganizationReferenceIdRequired.message(),
            "Reference ID is required. Provide referenceId or set activeOrganizationId in session"
        );
    }
}
