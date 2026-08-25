mod input;
mod routes;
mod support;
mod webhook;

use crate::polar::{CheckoutOptions, PolarClient, PolarPlugin, PortalOptions};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct PolarRouteState {
    pub(super) client: Arc<dyn PolarClient>,
    pub(super) checkout: Option<CheckoutOptions>,
    pub(super) portal: Option<PortalOptions>,
    pub(super) usage: bool,
    pub(super) webhook: Option<webhook::WebhookRouteState>,
}

impl PolarRouteState {
    pub(crate) fn from_plugin(plugin: &PolarPlugin) -> Self {
        let options = plugin.options();
        Self {
            client: options.client.clone(),
            checkout: options.checkout().cloned(),
            portal: options.portal().cloned(),
            usage: options.usage().is_some(),
            webhook: options.webhooks().map(|webhooks| {
                webhook::WebhookRouteState::new(
                    Some(Arc::from(webhooks.secret())),
                    webhooks.callbacks.clone(),
                )
            }),
        }
    }
}

pub(crate) fn routes(
    service: Arc<crate::AuthService>,
    state: PolarRouteState,
) -> Vec<crate::AxumPluginRoute> {
    routes::routes(service, state)
}
