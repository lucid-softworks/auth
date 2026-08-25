use crate::autumn::schema::Operation;
use std::{fmt, sync::Arc};

/// Autumn operations exposed by the pinned Better Auth adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AutumnOperation {
    GetOrCreateCustomer,
    GetEntity,
    Attach,
    PreviewAttach,
    UpdateSubscription,
    PreviewUpdateSubscription,
    OpenCustomerPortal,
    CreateReferralCode,
    RedeemReferralCode,
    ListPlans,
    ListEvents,
    AggregateEvents,
    MultiAttach,
    PreviewMultiAttach,
    SetupPayment,
}

impl AutumnOperation {
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::GetOrCreateCustomer => "v1/customers.get_or_create",
            Self::GetEntity => "v1/entities.get",
            Self::Attach => "v1/billing.attach",
            Self::PreviewAttach => "v1/billing.preview_attach",
            Self::UpdateSubscription => "v1/billing.update",
            Self::PreviewUpdateSubscription => "v1/billing.preview_update",
            Self::OpenCustomerPortal => "v1/billing.open_customer_portal",
            Self::CreateReferralCode => "v1/referrals.create_code",
            Self::RedeemReferralCode => "v1/referrals.redeem_code",
            Self::ListPlans => "v1/plans.list",
            Self::ListEvents => "v1/events.list",
            Self::AggregateEvents => "v1/events.aggregate",
            Self::MultiAttach => "v1/billing.multi_attach",
            Self::PreviewMultiAttach => "v1/billing.preview_multi_attach",
            Self::SetupPayment => "v1/billing.setup_payment",
        }
    }

    pub(crate) const fn fails_open(self) -> bool {
        matches!(self, Self::GetOrCreateCustomer | Self::GetEntity)
    }

    pub(crate) const fn schema_operation(self) -> Operation {
        match self {
            Self::GetOrCreateCustomer => Operation::GetOrCreateCustomer,
            Self::GetEntity => Operation::GetEntity,
            Self::Attach => Operation::Attach,
            Self::PreviewAttach => Operation::PreviewAttach,
            Self::UpdateSubscription => Operation::UpdateSubscription,
            Self::PreviewUpdateSubscription => Operation::PreviewUpdateSubscription,
            Self::OpenCustomerPortal => Operation::OpenCustomerPortal,
            Self::CreateReferralCode => Operation::CreateReferralCode,
            Self::RedeemReferralCode => Operation::RedeemReferralCode,
            Self::ListPlans => Operation::ListPlans,
            Self::ListEvents => Operation::ListEvents,
            Self::AggregateEvents => Operation::AggregateEvents,
            Self::MultiAttach => Operation::MultiAttach,
            Self::PreviewMultiAttach => Operation::PreviewMultiAttach,
            Self::SetupPayment => Operation::SetupPayment,
        }
    }
}

/// An error returned by the generated Autumn SDK boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct AutumnProviderError {
    /// HTTP status retained from an Autumn response, or absent for request validation.
    pub status: Option<u16>,
    /// Message selected by Autumn's adapter error transformer.
    pub message: String,
    /// Stable adapter error code.
    pub code: String,
    pub(crate) response: Option<Arc<str>>,
}

impl AutumnProviderError {
    /// Construct an error from an injected Autumn client implementation.
    pub fn new(status: Option<u16>, message: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            code: code.into(),
            response: None,
        }
    }

    pub(crate) fn internal(message: impl Into<String>) -> Self {
        Self::new(None, message, "internal_error")
    }

    pub(crate) fn response(
        status: u16,
        message: impl Into<String>,
        code: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        Self {
            status: Some(status),
            message: message.into(),
            code: code.into(),
            response: Some(response.into().into()),
        }
    }
}

impl fmt::Debug for AutumnProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AutumnProviderError")
            .field("status", &self.status)
            .field("message", &self.message)
            .field("code", &self.code)
            .field("response", &self.response.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl fmt::Display for AutumnProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AutumnProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_catalog_has_the_exact_fifteen_paths() {
        let operations = [
            AutumnOperation::GetOrCreateCustomer,
            AutumnOperation::GetEntity,
            AutumnOperation::Attach,
            AutumnOperation::PreviewAttach,
            AutumnOperation::UpdateSubscription,
            AutumnOperation::PreviewUpdateSubscription,
            AutumnOperation::OpenCustomerPortal,
            AutumnOperation::CreateReferralCode,
            AutumnOperation::RedeemReferralCode,
            AutumnOperation::ListPlans,
            AutumnOperation::ListEvents,
            AutumnOperation::AggregateEvents,
            AutumnOperation::MultiAttach,
            AutumnOperation::PreviewMultiAttach,
            AutumnOperation::SetupPayment,
        ];
        let paths = operations.map(AutumnOperation::path);
        assert_eq!(
            paths,
            [
                "v1/customers.get_or_create",
                "v1/entities.get",
                "v1/billing.attach",
                "v1/billing.preview_attach",
                "v1/billing.update",
                "v1/billing.preview_update",
                "v1/billing.open_customer_portal",
                "v1/referrals.create_code",
                "v1/referrals.redeem_code",
                "v1/plans.list",
                "v1/events.list",
                "v1/events.aggregate",
                "v1/billing.multi_attach",
                "v1/billing.preview_multi_attach",
                "v1/billing.setup_payment",
            ]
        );
        assert_eq!(operations.iter().filter(|op| op.fails_open()).count(), 2);
    }

    #[test]
    fn debug_never_contains_a_provider_response() {
        let error = AutumnProviderError::response(
            401,
            "bad key",
            "invalid_key",
            "secret response contents",
        );
        let debug = format!("{error:?}");
        assert!(!debug.contains("secret response contents"));
        assert!(debug.contains("[REDACTED]"));
    }
}
