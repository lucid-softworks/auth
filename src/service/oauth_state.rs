use super::SignInResult;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct OAuthCallbackResult {
    pub session: Option<SignInResult>,
    pub redirect_url: String,
    pub is_new_user: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthState {
    pub provider: String,
    pub callback_url: String,
    pub code_verifier: String,
    pub error_url: Option<String>,
    pub new_user_url: Option<String>,
    pub request_sign_up: bool,
    pub id_token_nonce: Option<String>,
    pub additional_data: serde_json::Map<String, Value>,
    pub link: Option<OAuthLinkState>,
    pub anonymous_user_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthLinkState {
    pub user_id: Uuid,
    pub email: String,
}
