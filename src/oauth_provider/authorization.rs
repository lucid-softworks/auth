use serde::{Deserialize, Serialize};

/// Authorization request persisted inside Better Auth core verification
/// storage for a single-use authorization code.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct OAuthAuthorizationQuery {
    pub response_type: Option<String>,
    pub request: Option<String>,
    pub request_uri: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub client_id: Option<String>,
    pub prompt: Option<String>,
    pub display: Option<String>,
    pub ui_locales: Option<String>,
    pub max_age: Option<u64>,
    pub acr_values: Option<String>,
    pub login_hint: Option<String>,
    pub id_token_hint: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub claims: Option<serde_json::Value>,
    pub dpop_jkt: Option<String>,
    #[serde(default)]
    pub resource: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OAuthAuthorizationCodePayload {
    #[serde(rename = "type")]
    pub kind: String,
    pub query: OAuthAuthorizationQuery,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "referenceId", skip_serializing_if = "Option::is_none")]
    pub reference_id: Option<String>,
    #[serde(rename = "authTime", skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource: Vec<String>,
}
