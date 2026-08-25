use crate::{PluginClientPathMethod, PluginEndpoint, PluginHttpMethod};

pub const CHARGEBEE_ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/chargebee/webhook"),
        client_method: "chargebeeWebhook",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/subscription/create"),
        client_method: "subscription.create",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/subscription/update"),
        client_method: "subscription.update",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/subscription/success"),
        client_method: "subscriptionSuccess",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/subscription/cancel"),
        client_method: "subscription.cancel",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/subscription/cancel/callback"),
        client_method: "subscription.cancel.callback",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/subscription/portal"),
        client_method: "subscription.portal",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/subscription/list"),
        client_method: "subscription.list",
    },
];

pub const CHARGEBEE_CLIENT_PATH_METHODS: &[PluginClientPathMethod] = &[
    PluginClientPathMethod::new("/subscription/create", PluginHttpMethod::Post),
    PluginClientPathMethod::new("/subscription/update", PluginHttpMethod::Post),
    PluginClientPathMethod::new("/subscription/cancel", PluginHttpMethod::Post),
    PluginClientPathMethod::new("/subscription/portal", PluginHttpMethod::Post),
    PluginClientPathMethod::new("/subscription/list", PluginHttpMethod::Get),
];

pub const CHARGEBEE_NON_ACTION_PATHS: &[&str] = &["/chargebee/webhook", "/subscription/success"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_and_official_client_surfaces_are_distinct_and_exact() {
        assert_eq!(CHARGEBEE_ENDPOINTS.len(), 8);
        assert_eq!(CHARGEBEE_CLIENT_PATH_METHODS.len(), 5);
        assert!(
            CHARGEBEE_ENDPOINTS
                .iter()
                .any(|endpoint| endpoint.client_method == "subscription.cancel.callback")
        );
        assert!(
            CHARGEBEE_CLIENT_PATH_METHODS
                .iter()
                .all(|entry| entry.path != "/subscription/cancel/callback")
        );
    }
}
