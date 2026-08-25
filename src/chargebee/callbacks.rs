use super::{
    ChargebeePlan, ChargebeeProviderCustomer, ChargebeeProviderSubscription, ChargebeeSubscription,
    ChargebeeWebhookEvent,
};
use async_trait::async_trait;
use serde_json::Value;
use std::{collections::BTreeMap, sync::Arc};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChargebeeCallbackContext {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChargebeeUserSnapshot {
    pub id: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub chargebee_customer_id: Option<String>,
    pub additional_fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChargebeeSessionSnapshot {
    pub id: String,
    pub user_id: String,
    pub active_organization_id: Option<String>,
    pub additional_fields: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ChargebeeOrganizationSnapshot {
    pub id: String,
    pub name: String,
    pub chargebee_customer_id: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct ChargebeeCallbackError {
    pub message: String,
}

impl ChargebeeCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait ChargebeePlansProvider: Send + Sync {
    async fn plans(&self) -> Result<Vec<ChargebeePlan>, ChargebeeCallbackError>;

    fn static_plans(&self) -> Option<&[ChargebeePlan]> {
        None
    }
}

#[derive(Debug, Clone)]
pub struct StaticChargebeePlans(pub Vec<ChargebeePlan>);

#[async_trait]
impl ChargebeePlansProvider for StaticChargebeePlans {
    async fn plans(&self) -> Result<Vec<ChargebeePlan>, ChargebeeCallbackError> {
        Ok(self.0.clone())
    }

    fn static_plans(&self) -> Option<&[ChargebeePlan]> {
        Some(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargebeeReferenceAction {
    CreateSubscription,
    UpgradeSubscription,
    ListSubscription,
    CancelSubscription,
    RestoreSubscription,
    BillingPortal,
}

impl ChargebeeReferenceAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateSubscription => "create-subscription",
            Self::UpgradeSubscription => "upgrade-subscription",
            Self::ListSubscription => "list-subscription",
            Self::CancelSubscription => "cancel-subscription",
            Self::RestoreSubscription => "restore-subscription",
            Self::BillingPortal => "billing-portal",
        }
    }
}

#[async_trait]
pub trait ChargebeeReferenceAuthorizer: Send + Sync {
    async fn authorize(
        &self,
        user: &ChargebeeUserSnapshot,
        session: &ChargebeeSessionSnapshot,
        reference_id: &str,
        action: ChargebeeReferenceAction,
        context: &ChargebeeCallbackContext,
    ) -> Result<bool, ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeCustomerCreateParams: Send + Sync {
    async fn params(
        &self,
        user: &ChargebeeUserSnapshot,
        context: Option<&ChargebeeCallbackContext>,
    ) -> Result<Value, ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeCustomerCreateCallback: Send + Sync {
    async fn call(
        &self,
        customer: &ChargebeeProviderCustomer,
        user: &ChargebeeUserSnapshot,
    ) -> Result<(), ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeOrganizationCustomerCreateParams: Send + Sync {
    async fn params(
        &self,
        organization: &ChargebeeOrganizationSnapshot,
        context: &ChargebeeCallbackContext,
    ) -> Result<Value, ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeOrganizationCustomerCreateCallback: Send + Sync {
    async fn call(
        &self,
        customer: &ChargebeeProviderCustomer,
        organization: &ChargebeeOrganizationSnapshot,
        context: &ChargebeeCallbackContext,
    ) -> Result<(), ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeHostedPageParams: Send + Sync {
    async fn params(
        &self,
        user: &ChargebeeUserSnapshot,
        session: &ChargebeeSessionSnapshot,
        plan: Option<&ChargebeePlan>,
        subscription: &ChargebeeSubscription,
        context: &ChargebeeCallbackContext,
    ) -> Result<Value, ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeSubscriptionCallbacks: Send + Sync {
    async fn on_subscription_complete(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: &ChargebeeProviderSubscription,
        _plan: Option<&ChargebeePlan>,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }

    async fn on_subscription_created(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: &ChargebeeProviderSubscription,
        _plan: Option<&ChargebeePlan>,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }

    async fn on_subscription_update(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: Option<&ChargebeeProviderSubscription>,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }

    async fn on_subscription_cancel(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: &ChargebeeProviderSubscription,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }

    async fn on_subscription_deleted(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: Option<&ChargebeeProviderSubscription>,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }

    async fn on_trial_start(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: Option<&ChargebeeProviderSubscription>,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }

    async fn on_trial_end(
        &self,
        _subscription: &ChargebeeSubscription,
        _provider: Option<&ChargebeeProviderSubscription>,
    ) -> Result<(), ChargebeeCallbackError> {
        Ok(())
    }
}

#[async_trait]
pub trait ChargebeeWebhookEventBus: Send + Sync {
    async fn publish(&self, event: ChargebeeWebhookEvent) -> Result<(), ChargebeeCallbackError>;
}

#[async_trait]
pub trait ChargebeeWebhookListener: Send + Sync {
    async fn call(&self, event: &ChargebeeWebhookEvent) -> Result<(), ChargebeeCallbackError>;
}

pub trait ChargebeeWebhookRegistrar {
    fn on(&mut self, event_type: String, listener: Arc<dyn ChargebeeWebhookListener>);
}

pub trait ChargebeeWebhookHandler: Send + Sync {
    fn configure(&self, registrar: &mut dyn ChargebeeWebhookRegistrar);
}

#[cfg(test)]
mod tests {
    use super::ChargebeeReferenceAction;

    #[test]
    fn public_action_type_keeps_the_declared_unused_restore_variant() {
        assert_eq!(
            ChargebeeReferenceAction::RestoreSubscription.as_str(),
            "restore-subscription"
        );
    }
}
