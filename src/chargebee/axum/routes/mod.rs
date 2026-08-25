mod callbacks;
mod cancel;
mod create;
mod list;
mod portal;
mod update;
mod webhook;

use super::ChargebeeRouteState;
use crate::{AuthService, AxumPluginRoute};
use axum::{Extension, routing::MethodRouter};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    state: ChargebeeRouteState,
) -> Vec<AxumPluginRoute> {
    let layer =
        |route: MethodRouter| route.layer::<_, std::convert::Infallible>(Extension(state.clone()));
    vec![
        AxumPluginRoute::new("/chargebee/webhook", layer(webhook::route())),
        AxumPluginRoute::new("/subscription/create", layer(create::route())),
        AxumPluginRoute::new("/subscription/update", layer(update::route())),
        AxumPluginRoute::new("/subscription/success", layer(callbacks::success_route())),
        AxumPluginRoute::new("/subscription/cancel", layer(cancel::route())),
        AxumPluginRoute::new(
            "/subscription/cancel/callback",
            layer(callbacks::cancel_route()),
        ),
        AxumPluginRoute::new("/subscription/portal", layer(portal::route())),
        AxumPluginRoute::new("/subscription/list", layer(list::route())),
    ]
}
