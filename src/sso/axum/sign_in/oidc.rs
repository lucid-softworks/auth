use super::{SignInBody, authorization, support};
use crate::{AuthService, SsoProvider, service::OAuthState};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use chrono::{Duration, Utc};
use rand::RngExt as _;
use serde::Serialize;
use serde_json::{Map, Value, json};

#[derive(Serialize)]
struct SignInResponse {
    url: String,
    redirect: bool,
}

struct SavedState {
    state: String,
    code_verifier: String,
    cookie_name: &'static str,
    cookie_value: String,
    max_age: i64,
}

pub(super) async fn start(
    service: &AuthService,
    provider: &SsoProvider,
    config: &Map<String, Value>,
    body: SignInBody,
) -> Response {
    let Some(endpoint) = config.get("authorizationEndpoint").and_then(Value::as_str) else {
        return support::error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid OIDC configuration. Authorization URL not found.",
        );
    };
    let Some(client_id) = config.get("clientId").and_then(Value::as_str) else {
        return support::error(
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "OAuth provider requires clientId",
        );
    };
    let additional = match authorization::additional_params(body.additional_params.as_ref()) {
        Ok(additional) => additional,
        Err(response) => return *response,
    };
    let saved = match create_state(service, provider, &body).await {
        Ok(saved) => saved,
        Err(response) => return *response,
    };
    let scopes = body.scopes.unwrap_or_else(|| configured_scopes(config));
    let redirect_uri = format!(
        "{}/sso/callback/{}",
        support::base_url(service),
        provider.provider_id
    );
    let authorization_url = match authorization::build(authorization::Input {
        endpoint,
        client_id,
        state: &saved.state,
        scopes: &scopes,
        redirect_uri: &redirect_uri,
        login_hint: body.login_hint.as_deref().or(body.email.as_deref()),
        code_verifier: config
            .get("pkce")
            .and_then(Value::as_bool)
            .unwrap_or(true)
            .then_some(saved.code_verifier.as_str()),
        additional: &additional,
    }) {
        Ok(url) => url,
        Err(response) => return *response,
    };
    let response = Json(SignInResponse {
        url: authorization_url,
        redirect: true,
    })
    .into_response();
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie(saved.cookie_name),
            &saved.cookie_value,
            Some(saved.max_age),
        ),
    )
}

async fn create_state(
    service: &AuthService,
    provider: &SsoProvider,
    body: &SignInBody,
) -> Result<SavedState, Box<Response>> {
    let state = random_string(32);
    let code_verifier = random_string(128);
    let reference = super::super::super::provider_reference::persisted(provider);
    let state_data = OAuthState {
        oauth_state: Some(state.clone()),
        callback_url: body.callback_url.clone(),
        code_verifier: code_verifier.clone(),
        error_url: body.error_callback_url.clone(),
        new_user_url: body.new_user_callback_url.clone(),
        expires_at: (Utc::now() + Duration::minutes(10)).timestamp_millis(),
        request_sign_up: body.request_sign_up.unwrap_or(false),
        id_token_nonce: None,
        additional_data: Map::from_iter([(
            "serverContext".into(),
            json!({"ssoProviderReference": reference}),
        )]),
        link: None,
        anonymous_user_id: None,
    };
    let (cookie_name, cookie_value, max_age) = service
        .save_oauth_state(&state, &state_data)
        .await
        .map_err(|_| {
            Box::new(support::error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                "State error: Unable to create verification for state",
            ))
        })?;
    Ok(SavedState {
        state,
        code_verifier,
        cookie_name,
        cookie_value,
        max_age,
    })
}

fn configured_scopes(config: &Map<String, Value>) -> Vec<String> {
    config
        .get("scopes")
        .and_then(Value::as_array)
        .map(|scopes| {
            scopes
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_else(|| {
            ["openid", "email", "profile", "offline_access"]
                .map(str::to_owned)
                .into()
        })
}

fn random_string(length: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    let mut rng = rand::rng();
    (0..length)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}
