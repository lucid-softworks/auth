use super::input::EndSessionInput;
use crate::{AuthService, oauth_provider::OAuthProviderClient};
use axum::{http::HeaderMap, response::Response};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const CONFIRMATION_TTL_SECONDS: i64 = 300;
const COOKIE_SUFFIX: &str = ".oauth_logout_confirmation";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConfirmationState {
    pub(super) session_id: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) post_logout_redirect_uri: Option<String>,
    pub(super) state: Option<String>,
    #[serde(default)]
    pub(super) redirect_invalid: bool,
    pub(super) expires_at: i64,
}

pub(super) fn confirmation_context(
    client: &OAuthProviderClient,
    input: &EndSessionInput,
) -> ConfirmationState {
    let Some(requested) = input.post_logout_redirect_uri.as_ref() else {
        return ConfirmationState::default();
    };
    if !client
        .post_logout_redirect_uris
        .as_ref()
        .is_some_and(|registered| registered.contains(requested))
    {
        return ConfirmationState {
            redirect_invalid: true,
            ..Default::default()
        };
    }
    ConfirmationState {
        client_id: Some(client.client_id.clone()),
        post_logout_redirect_uri: Some(requested.clone()),
        state: input.state.clone(),
        ..Default::default()
    }
}

pub(super) fn set_confirmation(
    service: &AuthService,
    mut state: ConfirmationState,
    response: Response,
) -> Response {
    state.expires_at = (Utc::now().timestamp_millis()) + CONFIRMATION_TTL_SECONDS * 1000;
    let encoded = serde_json::to_string(&state).unwrap_or_default();
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &confirmation_cookie(service),
            &service.signed_cookie_value(&encoded),
            Some(CONFIRMATION_TTL_SECONDS),
        ),
    )
}

pub(super) fn read_confirmation(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<ConfirmationState> {
    let name = confirmation_cookie_name(service);
    let encoded = crate::axum::http::signed_cookie_token(service, headers, &name)?;
    let state: ConfirmationState = serde_json::from_str(&encoded).ok()?;
    (state.expires_at > Utc::now().timestamp_millis()
        && state.post_logout_redirect_uri.is_none() == state.client_id.is_none())
    .then_some(state)
}

pub(super) fn clear_confirmation(service: &AuthService, response: Response) -> Response {
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(&confirmation_cookie(service), "", Some(0)),
    )
}

fn confirmation_cookie_name(service: &AuthService) -> String {
    format!("{}{}", service.session_cookie().name, COOKIE_SUFFIX)
}

fn confirmation_cookie(service: &AuthService) -> crate::cookie::ResolvedCookie {
    let mut cookie = service.session_cookie();
    cookie.name = confirmation_cookie_name(service);
    cookie.attributes.http_only = true;
    cookie.attributes.same_site = crate::SameSite::Lax;
    cookie.attributes.path = format!(
        "{}/oauth2/end-session/confirm",
        service.base_path().trim_end_matches('/')
    );
    cookie
}
