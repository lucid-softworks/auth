mod cookies;
mod hooks;
mod input;
mod oauth_proxy;
mod token;
mod transfer_user;

use super::ElectronOptions;
use crate::{AuthService, AxumPluginRoute, PluginRequestContext};
use axum::{
    Extension,
    routing::{get, post},
};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    options: Arc<ElectronOptions>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/electron/token",
            post(token::exchange).layer(Extension(options.clone())),
        ),
        AxumPluginRoute::new(
            "/electron/init-oauth-proxy",
            get(oauth_proxy::initialize).layer(Extension(options.clone())),
        ),
        AxumPluginRoute::new(
            "/electron/transfer-user",
            post(transfer_user::transfer).layer(Extension(options)),
        ),
    ]
}

pub(super) async fn after_response(
    service: &AuthService,
    options: &ElectronOptions,
    request: &PluginRequestContext,
    response: axum::response::Response,
) -> axum::response::Response {
    hooks::after_response(service, options, request, response).await
}
