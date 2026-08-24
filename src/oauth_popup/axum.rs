use crate::{AuthService, AxumPluginRoute, PluginRequestContext};
use axum::{response::Response, routing::get};

pub(super) fn routes() -> Vec<AxumPluginRoute> {
    vec![AxumPluginRoute::new(
        "/oauth-popup/start",
        get(super::start::start),
    )]
}

pub(super) async fn after_response(
    service: &AuthService,
    request: &PluginRequestContext,
    response: Response,
) -> Response {
    super::callback::after_response(service, request, response).await
}
