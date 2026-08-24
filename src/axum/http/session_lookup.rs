use super::{session_data_cookie, session_token};
use crate::{AuthService, SessionWithUser};
use axum::http::HeaderMap;

pub(crate) async fn current_session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    if let Some(token) = session_token(service, headers) {
        if let Some(session) = service.session(&token).await.ok().flatten() {
            return Some(session);
        }
        if service.cookie_cache_enabled()
            && let Some(cache) = session_data_cookie(service, headers)
            && let Some(session) = service.decode_cookie_cached_session(&token, &cache).await
        {
            return Some(session);
        }
    }
    plugin_session(service, headers).await
}

pub(crate) async fn current_session_cache_first(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<SessionWithUser> {
    if let Some(token) = session_token(service, headers) {
        if service.cookie_cache_enabled()
            && let Some(cache) = session_data_cookie(service, headers)
            && let Some(session) = service.decode_cookie_cached_session(&token, &cache).await
        {
            return Some(session);
        }
        if let Some(session) = service.session(&token).await.ok().flatten() {
            return Some(session);
        }
    }
    plugin_session(service, headers).await
}

async fn plugin_session(service: &AuthService, headers: &HeaderMap) -> Option<SessionWithUser> {
    service
        .plugin_session(headers)
        .await
        .ok()
        .flatten()
        .map(|session| session.session)
}
