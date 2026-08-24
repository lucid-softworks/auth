use super::{
    http::{serialize_cookie, with_cookie},
    oauth::{OAuthCallbackQuery, redirect, redirect_error},
};
use crate::AuthService;
use axum::response::Response;

pub(super) async fn idp_initiated_response(
    service: &AuthService,
    provider_id: &str,
    query: &OAuthCallbackQuery,
    default_error_url: &str,
) -> Option<Response> {
    if query.state.is_some()
        || query.code.is_none()
        || !service
            .social_provider(provider_id)
            .is_some_and(|provider| provider.allow_idp_initiated())
    {
        return None;
    }
    Some(
        match service
            .restart_idp_initiated_authorization(provider_id)
            .await
        {
            Ok((url, cookie_name, cookie_value, max_age)) => with_cookie(
                redirect(&url),
                serialize_cookie(
                    &service.plugin_cookie(cookie_name),
                    &cookie_value,
                    Some(max_age),
                ),
            ),
            Err(_) => redirect_error(default_error_url, "internal_server_error", None),
        },
    )
}
