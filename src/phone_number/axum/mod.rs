mod account;
mod verification;

use crate::{AuthService, AxumPluginRoute, PhoneNumberRequestContext};
use axum::{
    http::{HeaderMap, header},
    routing::post,
};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    _config: Arc<super::PhoneNumberConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/sign-in/phone-number", post(account::sign_in)),
        AxumPluginRoute::new("/phone-number/send-otp", post(verification::send)),
        AxumPluginRoute::new("/phone-number/verify", post(verification::verify)),
        AxumPluginRoute::new(
            "/phone-number/request-password-reset",
            post(account::request_reset),
        ),
        AxumPluginRoute::new(
            "/phone-number/reset-password",
            post(account::reset_password),
        ),
    ]
}

fn context(
    service: &AuthService,
    headers: &HeaderMap,
    peer: crate::axum::http::PeerAddress,
) -> PhoneNumberRequestContext {
    PhoneNumberRequestContext {
        origin: headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        ip_address: crate::axum::http::client_ip(service, headers, peer),
        user_agent: crate::axum::http::user_agent(headers),
    }
}

#[derive(serde::Serialize)]
struct StatusResponse {
    status: bool,
}

fn status() -> StatusResponse {
    StatusResponse { status: true }
}
