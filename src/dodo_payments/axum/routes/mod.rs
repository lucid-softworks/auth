mod checkout;
mod portal;
mod usage;

use crate::{AxumPluginRoute, dodo_payments::DodoPaymentsPlugin};
use axum::{Extension, routing::MethodRouter};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<crate::AuthService>,
    plugin: DodoPaymentsPlugin,
) -> Vec<AxumPluginRoute> {
    let layer =
        |route: MethodRouter| route.layer::<_, std::convert::Infallible>(Extension(plugin.clone()));
    let mut routes = Vec::new();
    if plugin.options().checkout().is_some() {
        routes.extend(checkout::routes(&layer));
    }
    if plugin.options().portal_enabled() {
        routes.extend(portal::routes(&layer));
    }
    if plugin.options().usage_enabled() {
        routes.extend(usage::routes(&layer));
    }
    if let Some(options) = plugin.options().webhooks() {
        routes.push(super::webhook::webhook_route(
            super::webhook::DodoWebhookRouteState::new(
                Arc::<str>::from(options.webhook_key()),
                options.callbacks.clone(),
            ),
        ));
    }
    routes
}
