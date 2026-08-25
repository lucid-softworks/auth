use super::{
    StripeCustomer, StripeEvent, StripePlan, StripeRequestOptions, StripeSubscription, Subscription,
};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StripeCallbackContext {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StripeUserSnapshot {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub stripe_customer_id: Option<String>,
    pub additional_fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StripeSessionSnapshot {
    pub id: String,
    pub user_id: String,
    pub active_organization_id: Option<String>,
    pub additional_fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StripeOrganizationSnapshot {
    pub id: String,
    pub name: String,
    pub stripe_customer_id: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct StripeCallbackError {
    pub message: String,
}

impl StripeCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait PlansProvider: Send + Sync {
    async fn plans(&self) -> Result<Vec<StripePlan>, StripeCallbackError>;

    /// Exposes literal plan arrays so Better Auth's synchronous init warning
    /// remains synchronous. Dynamic providers keep the default async path.
    fn static_plans(&self) -> Option<&[StripePlan]> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct StaticPlans(pub Vec<StripePlan>);

#[async_trait]
impl PlansProvider for StaticPlans {
    async fn plans(&self) -> Result<Vec<StripePlan>, StripeCallbackError> {
        Ok(self.0.clone())
    }

    fn static_plans(&self) -> Option<&[StripePlan]> {
        Some(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizeReferenceAction {
    UpgradeSubscription,
    ListSubscription,
    CancelSubscription,
    RestoreSubscription,
    BillingPortal,
}

impl AuthorizeReferenceAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpgradeSubscription => "upgrade-subscription",
            Self::ListSubscription => "list-subscription",
            Self::CancelSubscription => "cancel-subscription",
            Self::RestoreSubscription => "restore-subscription",
            Self::BillingPortal => "billing-portal",
        }
    }
}

#[async_trait]
pub trait ReferenceAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        user: &StripeUserSnapshot,
        session: &StripeSessionSnapshot,
        reference_id: &str,
        action: AuthorizeReferenceAction,
        context: &StripeCallbackContext,
    ) -> Result<bool, StripeCallbackError>;
}

#[async_trait]
pub trait CustomerCreateParams: Send + Sync {
    async fn params(
        &self,
        user: &StripeUserSnapshot,
        context: &StripeCallbackContext,
    ) -> Result<Value, StripeCallbackError>;
}

#[async_trait]
pub trait CustomerCreateCallback: Send + Sync {
    async fn call(
        &self,
        customer: &StripeCustomer,
        user: &StripeUserSnapshot,
        context: &StripeCallbackContext,
    ) -> Result<(), StripeCallbackError>;
}

#[async_trait]
pub trait OrganizationCustomerCreateParams: Send + Sync {
    async fn params(
        &self,
        organization: &StripeOrganizationSnapshot,
        context: &StripeCallbackContext,
    ) -> Result<Value, StripeCallbackError>;
}

#[async_trait]
pub trait OrganizationCustomerCreateCallback: Send + Sync {
    async fn call(
        &self,
        customer: &StripeCustomer,
        organization: &StripeOrganizationSnapshot,
        context: &StripeCallbackContext,
    ) -> Result<(), StripeCallbackError>;
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CheckoutSessionOverrides {
    pub params: Value,
    pub options: Option<StripeRequestOptions>,
}

#[async_trait]
pub trait CheckoutSessionParams: Send + Sync {
    async fn params(
        &self,
        user: &StripeUserSnapshot,
        session: &StripeSessionSnapshot,
        plan: &StripePlan,
        subscription: &Subscription,
        context: &StripeCallbackContext,
    ) -> Result<CheckoutSessionOverrides, StripeCallbackError>;
}

#[async_trait]
pub trait SubscriptionCallbacks: Send + Sync {
    async fn on_subscription_complete(
        &self,
        _event: &StripeEvent,
        _stripe_subscription: &StripeSubscription,
        _subscription: &Subscription,
        _plan: &StripePlan,
        _context: &StripeCallbackContext,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }

    async fn on_subscription_created(
        &self,
        _event: &StripeEvent,
        _stripe_subscription: &StripeSubscription,
        _subscription: &Subscription,
        _plan: &StripePlan,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }

    async fn on_subscription_update(
        &self,
        _event: &StripeEvent,
        _stripe_subscription: &StripeSubscription,
        _subscription: &Subscription,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }

    async fn on_subscription_cancel(
        &self,
        _event: &StripeEvent,
        _stripe_subscription: &StripeSubscription,
        _subscription: &Subscription,
        _cancellation_details: Option<&Value>,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }

    async fn on_subscription_deleted(
        &self,
        _event: &StripeEvent,
        _stripe_subscription: &StripeSubscription,
        _subscription: &Subscription,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }
}

#[async_trait]
pub trait EventCallback: Send + Sync {
    async fn on_event(&self, event: &StripeEvent) -> Result<(), StripeCallbackError>;
}

#[async_trait]
pub trait TrialCallbacks: Send + Sync {
    async fn on_trial_start(
        &self,
        _subscription: &Subscription,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }

    async fn on_trial_end(
        &self,
        _subscription: &Subscription,
        _context: &StripeCallbackContext,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }

    async fn on_trial_expired(
        &self,
        _subscription: &Subscription,
        _context: &StripeCallbackContext,
    ) -> Result<(), StripeCallbackError> {
        Ok(())
    }
}
