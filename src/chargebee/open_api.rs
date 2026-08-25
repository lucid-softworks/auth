use crate::{OpenApiEndpoint, PluginHttpMethod};

pub(crate) fn endpoints() -> Vec<OpenApiEndpoint> {
    [
        (
            "/chargebee/webhook",
            PluginHttpMethod::Post,
            "chargebeeWebhook",
            true,
        ),
        (
            "/subscription/create",
            PluginHttpMethod::Post,
            "createSubscription",
            false,
        ),
        (
            "/subscription/update",
            PluginHttpMethod::Post,
            "updateSubscription",
            false,
        ),
        (
            "/subscription/success",
            PluginHttpMethod::Get,
            "subscriptionSuccess",
            false,
        ),
        (
            "/subscription/cancel",
            PluginHttpMethod::Post,
            "cancelSubscription",
            false,
        ),
        (
            "/subscription/cancel/callback",
            PluginHttpMethod::Get,
            "cancelSubscriptionCallback",
            false,
        ),
        (
            "/subscription/portal",
            PluginHttpMethod::Post,
            "createPortalSession",
            false,
        ),
        (
            "/subscription/list",
            PluginHttpMethod::Get,
            "listActiveSubscriptions",
            false,
        ),
    ]
    .into_iter()
    .map(|(path, method, operation_id, server_only)| {
        let mut endpoint = OpenApiEndpoint::new(path, vec![method]);
        endpoint.operation_id = Some(operation_id.into());
        endpoint.server_only = server_only;
        endpoint
    })
    .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn operation_ids_match_the_published_endpoint_metadata() {
        let endpoints = super::endpoints();
        assert_eq!(endpoints.len(), 8);
        assert_eq!(
            endpoints[1].operation_id.as_deref(),
            Some("createSubscription")
        );
        assert_eq!(
            endpoints[7].operation_id.as_deref(),
            Some("listActiveSubscriptions")
        );
        assert!(endpoints[0].server_only);
    }
}
