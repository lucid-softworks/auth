use crate::{PluginEndpoint, PluginHttpMethod};
use std::borrow::Cow;

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

const ORDINARY_ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Post,
        "/creem/create-checkout",
        "createCheckout",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/creem/create-portal",
        "createPortal",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/creem/cancel-subscription",
        "cancelSubscription",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/creem/retrieve-subscription",
        "retrieveSubscription",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/creem/search-transactions",
        "searchTransactions",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/creem/has-access-granted",
        "hasAccessGranted",
    ),
];

const WEBHOOK_ENDPOINT: PluginEndpoint =
    endpoint(PluginHttpMethod::Post, "/creem/webhook", "creemWebhook");

pub(crate) fn endpoints(webhook_enabled: bool) -> Vec<PluginEndpoint> {
    let mut endpoints = ORDINARY_ENDPOINTS.to_vec();
    if webhook_enabled {
        endpoints.push(WEBHOOK_ENDPOINT);
    }
    endpoints
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_is_the_only_conditional_endpoint() {
        assert_eq!(endpoints(false), ORDINARY_ENDPOINTS);
        let enabled = endpoints(true);
        assert_eq!(enabled.len(), 7);
        assert_eq!(enabled.last(), Some(&WEBHOOK_ENDPOINT));
    }
}
