mod proxy;
mod redirect;

use super::ExpoOptions;
use axum::{
    extract::Request,
    http::{HeaderValue, header},
};
use std::sync::Arc;

pub(super) fn routes(service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
    vec![crate::AxumPluginRoute::new(
        "/expo-authorization-proxy",
        axum::routing::get(proxy::authorization_proxy).with_state(service),
    )]
}

pub(super) fn bridge_origin(options: &ExpoOptions, mut request: Request) -> Request {
    if options.disable_origin_override || request.headers().contains_key(header::ORIGIN) {
        return request;
    }
    let Some(origin) = request.headers().get("expo-origin").cloned() else {
        return request;
    };
    request.headers_mut().insert(header::ORIGIN, origin);
    request
}

pub(in crate::expo) use redirect::handoff_redirect_cookie;

fn location_header(value: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(value).ok()
}
