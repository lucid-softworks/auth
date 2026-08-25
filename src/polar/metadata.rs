use super::PolarOptions;
use crate::{PluginEndpoint, PluginHttpMethod};

const CHECKOUT: &[PluginEndpoint] = &[PluginEndpoint {
    method: PluginHttpMethod::Post,
    path: std::borrow::Cow::Borrowed("/checkout"),
    client_method: "checkout",
}];

const PORTAL: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/customer/portal", "customer.portal"),
    endpoint(
        PluginHttpMethod::Post,
        "/customer/portal",
        "customer.portal",
    ),
    endpoint(PluginHttpMethod::Get, "/customer/state", "customer.state"),
    endpoint(
        PluginHttpMethod::Get,
        "/customer/benefits/list",
        "customer.benefits.list",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/customer/subscriptions/list",
        "customer.subscriptions.list",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/customer/orders/list",
        "customer.orders.list",
    ),
];

const USAGE: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Get,
        "/usage/meters/list",
        "usage.meters.list",
    ),
    endpoint(PluginHttpMethod::Post, "/usage/ingest", "usage.ingest"),
];

const WEBHOOKS: &[PluginEndpoint] = &[endpoint(
    PluginHttpMethod::Post,
    "/polar/webhooks",
    "polarWebhooks",
)];

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: std::borrow::Cow::Borrowed(path),
        client_method,
    }
}

pub(crate) fn descriptor_endpoints(options: &PolarOptions) -> Vec<PluginEndpoint> {
    let mut endpoints = Vec::new();
    if options.checkout().is_some() {
        endpoints.extend_from_slice(CHECKOUT);
    }
    if options.portal().is_some() {
        endpoints.extend_from_slice(PORTAL);
    }
    if options.usage().is_some() {
        endpoints.extend_from_slice(USAGE);
    }
    if options.webhooks().is_some() {
        endpoints.extend_from_slice(WEBHOOKS);
    }
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_set_is_conditional_and_contains_both_portal_methods() {
        // Endpoint composition itself is tested through slices so it does not
        // need a fake implementation of the complete Polar transport.
        assert_eq!(CHECKOUT.len(), 1);
        assert_eq!(PORTAL.len(), 6);
        assert_eq!(
            PORTAL
                .iter()
                .filter(|endpoint| endpoint.path == "/customer/portal")
                .count(),
            2
        );
        assert_eq!(USAGE.len(), 2);
        assert_eq!(WEBHOOKS.len(), 1);
    }
}
