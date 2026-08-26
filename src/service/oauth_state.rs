use super::SignInResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct OAuthCallbackResult {
    pub session: Option<SignInResult>,
    pub redirect_url: String,
    pub is_new_user: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthState {
    #[serde(default)]
    pub oauth_state: Option<String>,
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    pub code_verifier: String,
    #[serde(rename = "errorURL", skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,
    #[serde(rename = "newUserURL", skip_serializing_if = "Option::is_none")]
    pub new_user_url: Option<String>,
    pub expires_at: i64,
    pub request_sign_up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_nonce: Option<String>,
    #[serde(flatten)]
    pub additional_data: serde_json::Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<OAuthLinkState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymous_user_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthLinkState {
    pub user_id: String,
    pub email: String,
}
