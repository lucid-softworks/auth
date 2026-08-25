use crate::{OpenApiEndpoint, PluginEndpoint, PluginHttpMethod};
use std::borrow::Cow;

/// Better Auth middleware callback action used to authorize a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceAction {
    UpgradeSubscription,
    CancelSubscription,
    RestoreSubscription,
    ListSubscription,
    BillingPortal,
}

impl ReferenceAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpgradeSubscription => "upgrade-subscription",
            Self::CancelSubscription => "cancel-subscription",
            Self::RestoreSubscription => "restore-subscription",
            Self::ListSubscription => "list-subscription",
            Self::BillingPortal => "billing-portal",
        }
    }
}

/// Exact request field inspected by Better Auth's origin middleware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginField {
    SuccessUrl,
    CancelUrl,
    ReturnUrl,
    CallbackUrl,
}

impl OriginField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SuccessUrl => "successUrl",
            Self::CancelUrl => "cancelUrl",
            Self::ReturnUrl => "returnUrl",
            Self::CallbackUrl => "callbackURL",
        }
    }
}

/// Runtime and inference metadata that the generic plugin descriptor cannot
/// represent on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StripeEndpointMetadata {
    pub key: &'static str,
    pub method: PluginHttpMethod,
    pub path: &'static str,
    pub operation_id: &'static str,
    pub client_action: Option<&'static str>,
    pub hidden: bool,
    pub clone_request: bool,
    pub body_parsing: bool,
    pub session_required: bool,
    pub reference_action: Option<ReferenceAction>,
    pub origin_fields: &'static [OriginField],
}

const NO_ORIGIN_FIELDS: &[OriginField] = &[];
const UPGRADE_ORIGIN_FIELDS: &[OriginField] = &[
    OriginField::SuccessUrl,
    OriginField::CancelUrl,
    OriginField::ReturnUrl,
];
const RETURN_URL_ORIGIN_FIELD: &[OriginField] = &[OriginField::ReturnUrl];
const CALLBACK_URL_ORIGIN_FIELD: &[OriginField] = &[OriginField::CallbackUrl];

pub const STRIPE_WEBHOOK_ENDPOINT: StripeEndpointMetadata = StripeEndpointMetadata {
    key: "stripeWebhook",
    method: PluginHttpMethod::Post,
    path: "/stripe/webhook",
    operation_id: "handleStripeWebhook",
    client_action: None,
    hidden: true,
    clone_request: true,
    body_parsing: false,
    session_required: false,
    reference_action: None,
    origin_fields: NO_ORIGIN_FIELDS,
};

pub const STRIPE_SUBSCRIPTION_ENDPOINTS: &[StripeEndpointMetadata] = &[
    StripeEndpointMetadata {
        key: "upgradeSubscription",
        method: PluginHttpMethod::Post,
        path: "/subscription/upgrade",
        operation_id: "upgradeSubscription",
        client_action: Some("subscription.upgrade"),
        hidden: false,
        clone_request: false,
        body_parsing: true,
        session_required: true,
        reference_action: Some(ReferenceAction::UpgradeSubscription),
        origin_fields: UPGRADE_ORIGIN_FIELDS,
    },
    StripeEndpointMetadata {
        key: "cancelSubscription",
        method: PluginHttpMethod::Post,
        path: "/subscription/cancel",
        operation_id: "cancelSubscription",
        client_action: Some("subscription.cancel"),
        hidden: false,
        clone_request: false,
        body_parsing: true,
        session_required: true,
        reference_action: Some(ReferenceAction::CancelSubscription),
        origin_fields: RETURN_URL_ORIGIN_FIELD,
    },
    StripeEndpointMetadata {
        key: "restoreSubscription",
        method: PluginHttpMethod::Post,
        path: "/subscription/restore",
        operation_id: "restoreSubscription",
        client_action: Some("subscription.restore"),
        hidden: false,
        clone_request: false,
        body_parsing: true,
        session_required: true,
        reference_action: Some(ReferenceAction::RestoreSubscription),
        origin_fields: NO_ORIGIN_FIELDS,
    },
    StripeEndpointMetadata {
        key: "listActiveSubscriptions",
        method: PluginHttpMethod::Get,
        path: "/subscription/list",
        operation_id: "listActiveSubscriptions",
        client_action: Some("subscription.list"),
        hidden: false,
        clone_request: false,
        body_parsing: true,
        session_required: true,
        reference_action: Some(ReferenceAction::ListSubscription),
        origin_fields: NO_ORIGIN_FIELDS,
    },
    StripeEndpointMetadata {
        key: "subscriptionSuccess",
        method: PluginHttpMethod::Get,
        path: "/subscription/success",
        operation_id: "handleSubscriptionSuccess",
        client_action: Some("subscription.success"),
        hidden: false,
        clone_request: false,
        body_parsing: true,
        session_required: false,
        reference_action: None,
        origin_fields: CALLBACK_URL_ORIGIN_FIELD,
    },
    StripeEndpointMetadata {
        key: "createBillingPortal",
        method: PluginHttpMethod::Post,
        path: "/subscription/billing-portal",
        operation_id: "createBillingPortal",
        client_action: Some("subscription.billingPortal"),
        hidden: false,
        clone_request: false,
        body_parsing: true,
        session_required: true,
        reference_action: Some(ReferenceAction::BillingPortal),
        origin_fields: RETURN_URL_ORIGIN_FIELD,
    },
];

/// The only paths explicitly declared by `stripeClient` 1.7.1. All other
/// client methods are inferred from server endpoint metadata.
pub const STRIPE_CLIENT_PATH_METHODS: &[(&str, PluginHttpMethod)] = &[
    ("/subscription/billing-portal", PluginHttpMethod::Post),
    ("/subscription/restore", PluginHttpMethod::Post),
];

pub fn endpoint_metadata(subscriptions_enabled: bool) -> Vec<StripeEndpointMetadata> {
    let mut endpoints = vec![STRIPE_WEBHOOK_ENDPOINT];
    if subscriptions_enabled {
        endpoints.extend_from_slice(STRIPE_SUBSCRIPTION_ENDPOINTS);
    }
    endpoints
}

pub fn descriptor_endpoints(subscriptions_enabled: bool) -> Vec<PluginEndpoint> {
    endpoint_metadata(subscriptions_enabled)
        .into_iter()
        .map(|endpoint| PluginEndpoint {
            method: endpoint.method,
            path: Cow::Borrowed(endpoint.path),
            client_method: endpoint.client_action.unwrap_or(endpoint.key),
        })
        .collect()
}

pub fn open_api_endpoints(subscriptions_enabled: bool) -> Vec<OpenApiEndpoint> {
    endpoint_metadata(subscriptions_enabled)
        .into_iter()
        .map(|endpoint| {
            let mut open_api = OpenApiEndpoint::new(endpoint.path, vec![endpoint.method]);
            open_api.server_only = endpoint.hidden;
            open_api.operation_id = Some(endpoint.operation_id.into());
            open_api
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_always_exists_and_is_hidden_raw_body() {
        let endpoints = endpoint_metadata(false);
        assert_eq!(endpoints, vec![STRIPE_WEBHOOK_ENDPOINT]);
        assert!(endpoints[0].hidden);
        assert!(endpoints[0].clone_request);
        assert!(!endpoints[0].body_parsing);
        assert!(!endpoints[0].session_required);
        assert_eq!(endpoints[0].client_action, None);
    }

    #[test]
    fn subscriptions_add_the_exact_six_endpoints() {
        let endpoints = endpoint_metadata(true);
        assert_eq!(endpoints.len(), 7);
        assert_eq!(endpoints[1..], *STRIPE_SUBSCRIPTION_ENDPOINTS);
        assert_eq!(
            endpoints
                .iter()
                .filter_map(|endpoint| endpoint.client_action)
                .collect::<Vec<_>>(),
            vec![
                "subscription.upgrade",
                "subscription.cancel",
                "subscription.restore",
                "subscription.list",
                "subscription.success",
                "subscription.billingPortal",
            ]
        );
    }

    #[test]
    fn success_has_no_session_or_reference_middleware() {
        let success = STRIPE_SUBSCRIPTION_ENDPOINTS
            .iter()
            .find(|endpoint| endpoint.key == "subscriptionSuccess")
            .expect("success endpoint exists");
        assert!(!success.session_required);
        assert_eq!(success.reference_action, None);
        assert_eq!(success.origin_fields, &[OriginField::CallbackUrl]);
        assert_eq!(success.origin_fields[0].as_str(), "callbackURL");
    }

    #[test]
    fn reference_actions_use_the_exact_upstream_strings() {
        assert_eq!(
            STRIPE_SUBSCRIPTION_ENDPOINTS
                .iter()
                .filter_map(|endpoint| endpoint.reference_action)
                .map(ReferenceAction::as_str)
                .collect::<Vec<_>>(),
            vec![
                "upgrade-subscription",
                "cancel-subscription",
                "restore-subscription",
                "list-subscription",
                "billing-portal",
            ]
        );
    }

    #[test]
    fn open_api_preserves_exact_operation_ids_and_hides_only_webhook() {
        let endpoints = open_api_endpoints(true);
        assert_eq!(
            endpoints
                .iter()
                .map(|endpoint| endpoint.operation_id.as_deref().expect("operation id"))
                .collect::<Vec<_>>(),
            vec![
                "handleStripeWebhook",
                "upgradeSubscription",
                "cancelSubscription",
                "restoreSubscription",
                "listActiveSubscriptions",
                "handleSubscriptionSuccess",
                "createBillingPortal",
            ]
        );
        assert!(endpoints[0].server_only);
        assert!(endpoints[1..].iter().all(|endpoint| !endpoint.server_only));
    }

    #[test]
    fn client_has_only_the_two_explicit_path_methods() {
        assert_eq!(
            STRIPE_CLIENT_PATH_METHODS,
            &[
                ("/subscription/billing-portal", PluginHttpMethod::Post),
                ("/subscription/restore", PluginHttpMethod::Post),
            ]
        );
    }
}
