use super::{clear_account_cookie, clear_session_data_cookie, serialize_cookie, with_cookie};
use crate::AuthService;
use axum::{
    http::HeaderMap,
    response::{IntoResponse, Response},
};

pub(crate) fn clear_session_cookie_from_request(
    service: &AuthService,
    headers: &HeaderMap,
    body: impl IntoResponse,
) -> Response {
    let response = with_cookie(
        body,
        serialize_cookie(&service.session_cookie(), "", Some(0)),
    );
    let response = clear_session_data_cookie(service, headers, response);
    let response = with_cookie(
        response,
        serialize_cookie(&service.dont_remember_cookie(), "", Some(0)),
    );
    let response = if service.oauth_state_cookie_name() == "oauth_state" {
        with_cookie(
            response,
            serialize_cookie(&service.plugin_cookie("oauth_state"), "", Some(0)),
        )
    } else {
        response
    };
    if service.account_cookie_enabled() {
        clear_account_cookie(service, Some(headers), response)
    } else {
        response
    }
}
