mod checkout;
mod subscription;
mod webhook;

use super::CreemRouteState;
use crate::AxumPluginRoute;
use axum::{
    Extension,
    routing::{get, post},
};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<crate::AuthService>,
    state: CreemRouteState,
) -> Vec<AxumPluginRoute> {
    let layer = |route: axum::routing::MethodRouter| {
        route.layer::<_, std::convert::Infallible>(Extension(state.clone()))
    };
    let mut routes = vec![
        AxumPluginRoute::new("/creem/create-checkout", layer(post(checkout::create))),
        AxumPluginRoute::new("/creem/create-portal", layer(post(checkout::portal))),
        AxumPluginRoute::new(
            "/creem/cancel-subscription",
            layer(post(subscription::cancel)),
        ),
        AxumPluginRoute::new(
            "/creem/retrieve-subscription",
            layer(post(subscription::retrieve)),
        ),
        AxumPluginRoute::new(
            "/creem/search-transactions",
            layer(post(subscription::search)),
        ),
        AxumPluginRoute::new(
            "/creem/has-access-granted",
            layer(get(subscription::access)),
        ),
    ];
    if state.options.webhook_enabled() {
        routes.push(AxumPluginRoute::new(
            "/creem/webhook",
            layer(post(webhook::receive)),
        ));
    }
    routes
}
