use crate::{AuthService, AxumPluginRoute, StripePlugin};
use std::sync::Arc;

mod cancel;
mod list;
mod portal;
mod restore;
mod success;
mod support;
mod upgrade;
mod webhook;

pub(crate) fn routes(_service: Arc<AuthService>, plugin: StripePlugin) -> Vec<AxumPluginRoute> {
    let mut routes = vec![webhook::route(plugin.clone())];
    if plugin.subscriptions_enabled() {
        routes.extend([
            upgrade::route(plugin.clone()),
            cancel::route(plugin.clone()),
            restore::route(plugin.clone()),
            list::route(plugin.clone()),
            success::route(plugin.clone()),
            portal::route(plugin),
        ]);
    }
    routes
}
