use super::{CommetFeature, CommetFeatureKind};
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

const PORTAL: &[PluginEndpoint] = &[endpoint(
    PluginHttpMethod::Get,
    "/commet/portal",
    "customer.portal",
)];
const SUBSCRIPTIONS: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Get,
        "/commet/subscription",
        "subscription.get",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/commet/subscription/cancel",
        "subscription.cancel",
    ),
];
const FEATURES: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/commet/features", "features.list"),
    endpoint(
        PluginHttpMethod::Get,
        "/commet/features/:code",
        "features.get",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/commet/features/:code/check",
        "features.check",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/commet/features/:code/can-use",
        "features.canUse",
    ),
];
const USAGE: &[PluginEndpoint] = &[endpoint(
    PluginHttpMethod::Post,
    "/commet/usage/track",
    "usage.track",
)];
const SEATS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/commet/seats", "seats.list"),
    endpoint(PluginHttpMethod::Post, "/commet/seats/add", "seats.add"),
    endpoint(
        PluginHttpMethod::Post,
        "/commet/seats/remove",
        "seats.remove",
    ),
    endpoint(PluginHttpMethod::Post, "/commet/seats/set", "seats.set"),
    endpoint(
        PluginHttpMethod::Post,
        "/commet/seats/set-all",
        "seats.setAll",
    ),
];
const WEBHOOKS: &[PluginEndpoint] = &[endpoint(
    PluginHttpMethod::Post,
    "/commet/webhooks",
    "commetWebhooks",
)];

pub(crate) fn descriptor_endpoints(features: &[CommetFeature]) -> Vec<PluginEndpoint> {
    let mut endpoints = Vec::new();
    let mut seen = BTreeSet::new();
    for feature in features {
        let kind = feature.kind();
        if !seen.insert(kind) {
            continue;
        }
        endpoints.extend_from_slice(match kind {
            CommetFeatureKind::Portal => PORTAL,
            CommetFeatureKind::Subscriptions => SUBSCRIPTIONS,
            CommetFeatureKind::Features => FEATURES,
            CommetFeatureKind::Usage => USAGE,
            CommetFeatureKind::Seats => SEATS,
            CommetFeatureKind::Webhooks => WEBHOOKS,
        });
    }
    endpoints
}
