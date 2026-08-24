use crate::{AuthError, oauth::AuthorizationRequest, service::OAuthState};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use rand::RngExt as _;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

const INTERNAL_STATE_KEYS: &[&str] = &[
    "callbackURL",
    "codeVerifier",
    "errorURL",
    "newUserURL",
    "expiresAt",
    "oauthState",
    "link",
    "requestSignUp",
    "idTokenNonce",
    "serverContext",
];

pub(super) struct PopupAuthorization {
    pub state_cookie_name: &'static str,
    pub state_cookie_value: String,
    pub state_cookie_max_age: i64,
    pub authorization_url: Result<String, AuthError>,
}

pub(super) struct PopupAuthorizationInput {
    pub provider: String,
    pub callback_url: String,
    pub error_callback_url: Option<String>,
    pub new_user_callback_url: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub request_sign_up: bool,
    pub additional_data: Map<String, Value>,
}

impl crate::AuthService {
    pub(super) async fn start_popup_authorization(
        &self,
        input: PopupAuthorizationInput,
    ) -> Result<PopupAuthorization, AuthError> {
        let provider = self
            .social_provider(&input.provider)
            .ok_or(AuthError::OAuthProviderNotFound)?;
        let state = random_string(32);
        let code_verifier = random_string(128);
        let id_token_nonce = provider
            .requires_id_token_nonce()
            .then(|| random_string(32));
        let mut additional_data = input.additional_data;
        additional_data.retain(|key, _| !INTERNAL_STATE_KEYS.contains(&key.as_str()));
        let state_data = OAuthState {
            oauth_state: Some(state.clone()),
            callback_url: input.callback_url,
            code_verifier: code_verifier.clone(),
            error_url: input.error_callback_url,
            new_user_url: input.new_user_callback_url,
            expires_at: (Utc::now() + Duration::minutes(10)).timestamp_millis(),
            request_sign_up: input.request_sign_up,
            id_token_nonce: id_token_nonce.clone(),
            additional_data,
            link: None,
            anonymous_user_id: None,
        };
        let (state_cookie_name, state_cookie_value, state_cookie_max_age) =
            self.save_oauth_state(&state, &state_data).await?;
        let authorization_url = provider
            .create_authorization_url(&AuthorizationRequest {
                state,
                code_verifier,
                id_token_nonce,
                redirect_uri: self.oauth_callback_url(provider.id())?,
                scopes: input.scopes,
                login_hint: None,
                additional_params: BTreeMap::new(),
            })
            .map(|url| url.to_string());
        Ok(PopupAuthorization {
            state_cookie_name,
            state_cookie_value,
            state_cookie_max_age,
            authorization_url,
        })
    }
}

pub(super) fn additional_data(value: Option<&str>) -> Map<String, Value> {
    let value = value
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .unwrap_or(Value::Object(Map::new()));
    match value {
        Value::Object(map) => map,
        Value::Array(values) => values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (index.to_string(), value))
            .collect(),
        Value::String(value) => value
            .chars()
            .enumerate()
            .map(|(index, value)| (index.to_string(), Value::String(value.to_string())))
            .collect(),
        Value::Null | Value::Bool(_) | Value::Number(_) => Map::new(),
    }
}

fn random_string(length: usize) -> String {
    let mut value = String::new();
    while value.len() < length {
        let bytes: [u8; 32] = rand::rng().random();
        value.push_str(&URL_SAFE_NO_PAD.encode(bytes));
    }
    value.truncate(length);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn additional_data_matches_object_entries_and_filters_later() {
        assert_eq!(
            additional_data(Some(r#"["a",2]"#)),
            Map::from_iter([("0".into(), json!("a")), ("1".into(), json!(2))])
        );
        assert_eq!(
            additional_data(Some(r#""ab""#)),
            Map::from_iter([("0".into(), json!("a")), ("1".into(), json!("b"))])
        );
        assert!(additional_data(Some("null")).is_empty());
        assert!(additional_data(Some("{")).is_empty());
    }
}
