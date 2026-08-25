use super::DodoPaymentsFeature;
use crate::{PluginEndpoint, PluginHttpMethod};
use std::{borrow::Cow, collections::BTreeSet};

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: Cow::Borrowed(path),
        client_method,
    }
}

const CHECKOUT: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Post, "/dodopayments/checkout", "checkout"),
    endpoint(
        PluginHttpMethod::Post,
        "/dodopayments/checkout-session",
        "checkoutSession",
    ),
];

const PORTAL: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Get,
        "/dodopayments/customer/portal",
        "customer.portal",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dodopayments/customer/subscriptions/list",
        "customer.subscriptions.list",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dodopayments/customer/payments/list",
        "customer.payments.list",
    ),
];

const USAGE: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Post,
        "/dodopayments/usage/ingest",
        "usage.ingest",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dodopayments/usage/meters/list",
        "usage.meters.list",
    ),
];

const WEBHOOKS: &[PluginEndpoint] = &[endpoint(
    PluginHttpMethod::Post,
    "/dodopayments/webhooks",
    "dodopaymentsWebhooks",
)];

pub(crate) fn descriptor_endpoints(features: &[DodoPaymentsFeature]) -> Vec<PluginEndpoint> {
    let mut endpoints = Vec::new();
    let mut seen = BTreeSet::new();
    for feature in features {
        let (name, group) = match feature {
            DodoPaymentsFeature::Checkout(_) => ("checkout", CHECKOUT),
            DodoPaymentsFeature::Portal => ("portal", PORTAL),
            DodoPaymentsFeature::Usage => ("usage", USAGE),
            DodoPaymentsFeature::Webhooks(_) => ("webhooks", WEBHOOKS),
        };
        if seen.insert(name) {
            endpoints.extend_from_slice(group);
        }
    }
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_groups_have_the_exact_pinned_surface() {
        assert_eq!(CHECKOUT.len(), 2);
        assert_eq!(PORTAL.len(), 3);
        assert_eq!(USAGE.len(), 2);
        assert_eq!(WEBHOOKS.len(), 1);
        assert_eq!(WEBHOOKS[0].path, "/dodopayments/webhooks");
        assert!(descriptor_endpoints(&[]).is_empty());

        let composed = descriptor_endpoints(&[
            DodoPaymentsFeature::Usage,
            DodoPaymentsFeature::Portal,
            DodoPaymentsFeature::Usage,
        ]);
        assert_eq!(composed.len(), 5);
        assert_eq!(composed[0].path, "/dodopayments/usage/ingest");
        assert_eq!(composed[2].path, "/dodopayments/customer/portal");
    }
}
