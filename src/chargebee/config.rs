use super::{
    ChargebeeClient, ChargebeeCustomerCreateCallback, ChargebeeCustomerCreateParams,
    ChargebeeHostedPageParams, ChargebeeOrganizationCustomerCreateCallback,
    ChargebeeOrganizationCustomerCreateParams, ChargebeePlansProvider,
    ChargebeeReferenceAuthorizer, ChargebeeSubscriptionCallbacks, ChargebeeWebhookEventBus,
    ChargebeeWebhookHandler,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, sync::Arc};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChargebeePlanType {
    Plan,
    Addon,
    Charge,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargebeePlan {
    pub name: String,
    pub item_price_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_family_id: Option<String>,
    #[serde(rename = "type")]
    pub plan_type: ChargebeePlanType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_cycles: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_trial: Option<ChargebeeFreeTrial>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChargebeeFreeTrial {
    pub days: f64,
}

#[derive(Clone)]
pub struct ChargebeeOptions {
    pub client: Arc<dyn ChargebeeClient>,
    pub webhook_username: Option<Arc<str>>,
    pub webhook_password: Option<Arc<str>>,
    pub create_customer_on_sign_up: bool,
    pub get_customer_create_params: Option<Arc<dyn ChargebeeCustomerCreateParams>>,
    pub on_customer_create: Option<Arc<dyn ChargebeeCustomerCreateCallback>>,
    pub webhook_handler: Option<Arc<dyn ChargebeeWebhookHandler>>,
    pub webhook_event_bus: Option<Arc<dyn ChargebeeWebhookEventBus>>,
    pub subscription: Option<ChargebeeSubscriptionOptions>,
    pub organization: Option<ChargebeeOrganizationOptions>,
}

impl ChargebeeOptions {
    pub fn new(client: Arc<dyn ChargebeeClient>) -> Self {
        Self {
            client,
            webhook_username: None,
            webhook_password: None,
            create_customer_on_sign_up: false,
            get_customer_create_params: None,
            on_customer_create: None,
            webhook_handler: None,
            webhook_event_bus: None,
            subscription: None,
            organization: None,
        }
    }

    pub fn subscriptions_enabled(&self) -> bool {
        self.subscription
            .as_ref()
            .is_some_and(|subscription| subscription.enabled)
    }

    pub fn organization_enabled(&self) -> bool {
        self.organization
            .as_ref()
            .is_some_and(|organization| organization.enabled)
    }

    pub fn webhook_credentials(&self) -> Option<(&str, &str)> {
        Some((
            self.webhook_username.as_deref()?,
            self.webhook_password.as_deref()?,
        ))
        .filter(|(username, password)| !username.is_empty() && !password.is_empty())
    }

    pub async fn plans(&self) -> Result<Vec<ChargebeePlan>, super::ChargebeeCallbackError> {
        match self.subscription.as_ref() {
            Some(subscription) => subscription.plans.plans().await,
            None => Ok(Vec::new()),
        }
    }
}

impl fmt::Debug for ChargebeeOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargebeeOptions")
            .field("webhook_username", &self.webhook_username.as_deref())
            .field(
                "webhook_password",
                &self.webhook_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "create_customer_on_sign_up",
                &self.create_customer_on_sign_up,
            )
            .field("subscription", &self.subscription)
            .field("organization", &self.organization)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct ChargebeeSubscriptionOptions {
    pub enabled: bool,
    pub plans: Arc<dyn ChargebeePlansProvider>,
    pub prevent_duplicate_trials: bool,
    pub require_email_verification: bool,
    pub get_hosted_page_params: Option<Arc<dyn ChargebeeHostedPageParams>>,
    pub authorize_reference: Option<Arc<dyn ChargebeeReferenceAuthorizer>>,
    pub callbacks: Option<Arc<dyn ChargebeeSubscriptionCallbacks>>,
}

impl ChargebeeSubscriptionOptions {
    pub fn new(enabled: bool, plans: Arc<dyn ChargebeePlansProvider>) -> Self {
        Self {
            enabled,
            plans,
            prevent_duplicate_trials: false,
            require_email_verification: false,
            get_hosted_page_params: None,
            authorize_reference: None,
            callbacks: None,
        }
    }
}

impl fmt::Debug for ChargebeeSubscriptionOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargebeeSubscriptionOptions")
            .field("enabled", &self.enabled)
            .field("prevent_duplicate_trials", &self.prevent_duplicate_trials)
            .field(
                "require_email_verification",
                &self.require_email_verification,
            )
            .field(
                "has_get_hosted_page_params",
                &self.get_hosted_page_params.is_some(),
            )
            .field(
                "has_authorize_reference",
                &self.authorize_reference.is_some(),
            )
            .field("has_callbacks", &self.callbacks.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct ChargebeeOrganizationOptions {
    pub enabled: bool,
    pub get_customer_create_params: Option<Arc<dyn ChargebeeOrganizationCustomerCreateParams>>,
    pub on_customer_create: Option<Arc<dyn ChargebeeOrganizationCustomerCreateCallback>>,
}

impl fmt::Debug for ChargebeeOrganizationOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargebeeOrganizationOptions")
            .field("enabled", &self.enabled)
            .field(
                "has_get_customer_create_params",
                &self.get_customer_create_params.is_some(),
            )
            .field("has_on_customer_create", &self.on_customer_create.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    #[derive(Debug)]
    struct EmptyClient;

    #[async_trait]
    impl ChargebeeClient for EmptyClient {
        async fn list_customers(
            &self,
            _: super::super::ChargebeeCustomerListRequest,
        ) -> Result<
            Vec<super::super::ChargebeeProviderCustomer>,
            super::super::ChargebeeProviderError,
        > {
            unimplemented!()
        }
        async fn create_customer(
            &self,
            _: Value,
        ) -> Result<super::super::ChargebeeProviderCustomer, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn update_customer(
            &self,
            _: &str,
            _: Value,
        ) -> Result<super::super::ChargebeeProviderCustomer, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn delete_customer(
            &self,
            _: &str,
        ) -> Result<(), super::super::ChargebeeProviderError> {
            unimplemented!()
        }
        async fn list_subscriptions(
            &self,
            _: super::super::ChargebeeSubscriptionListRequest,
        ) -> Result<
            Vec<super::super::ChargebeeProviderSubscription>,
            super::super::ChargebeeProviderError,
        > {
            unimplemented!()
        }
        async fn retrieve_subscription(
            &self,
            _: &str,
        ) -> Result<super::super::ChargebeeProviderSubscription, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn cancel_subscription(
            &self,
            _: &str,
            _: bool,
        ) -> Result<super::super::ChargebeeProviderSubscription, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn checkout_new_for_items(
            &self,
            _: Value,
        ) -> Result<super::super::ChargebeeHostedPage, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn checkout_existing_for_items(
            &self,
            _: Value,
        ) -> Result<super::super::ChargebeeHostedPage, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn create_portal_session(
            &self,
            _: Value,
        ) -> Result<super::super::ChargebeePortalSession, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
        async fn parse_webhook(
            &self,
            _: &[u8],
            _: Option<&str>,
            _: Option<(&str, &str)>,
        ) -> Result<super::super::ChargebeeWebhookEvent, super::super::ChargebeeProviderError>
        {
            unimplemented!()
        }
    }

    #[test]
    fn credentials_are_enabled_only_when_both_are_truthy() {
        let mut options = ChargebeeOptions::new(Arc::new(EmptyClient));
        options.webhook_username = Some(Arc::from("user"));
        assert_eq!(options.webhook_credentials(), None);
        options.webhook_password = Some(Arc::from(""));
        assert_eq!(options.webhook_credentials(), None);
        options.webhook_password = Some(Arc::from("password"));
        assert_eq!(options.webhook_credentials(), Some(("user", "password")));
    }
}
