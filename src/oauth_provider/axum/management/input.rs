use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Clone, Default, Deserialize, Serialize)]
pub(super) struct ClientMetadataInput {
    pub(super) redirect_uris: Option<Vec<String>>,
    pub(super) scope: Option<String>,
    pub(super) client_name: Option<String>,
    pub(super) client_uri: Option<String>,
    pub(super) logo_uri: Option<String>,
    pub(super) contacts: Option<Vec<String>>,
    pub(super) tos_uri: Option<String>,
    pub(super) policy_uri: Option<String>,
    pub(super) software_id: Option<String>,
    pub(super) software_version: Option<String>,
    pub(super) software_statement: Option<String>,
    pub(super) post_logout_redirect_uris: Option<Vec<String>>,
    pub(super) backchannel_logout_uri: Option<String>,
    pub(super) backchannel_logout_session_required: Option<bool>,
    pub(super) token_endpoint_auth_method: Option<String>,
    pub(super) application_type: Option<String>,
    pub(super) jwks: Option<Value>,
    pub(super) jwks_uri: Option<String>,
    pub(super) grant_types: Option<Vec<String>>,
    pub(super) response_types: Option<Vec<String>>,
    pub(super) require_pkce: Option<bool>,
    pub(super) dpop_bound_access_tokens: Option<bool>,
    pub(super) subject_type: Option<String>,
    pub(super) resources: Option<Vec<String>>,
    #[serde(default, flatten)]
    pub(super) extensions: Map<String, Value>,
}

#[derive(Deserialize)]
pub(super) struct ClientIdInput {
    pub(super) client_id: String,
}

#[derive(Deserialize)]
pub(super) struct ClientQuery {
    pub(super) client_id: String,
}

#[derive(Deserialize)]
pub(super) struct PublicClientPreloginInput {
    pub(super) client_id: String,
    pub(super) oauth_query: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct UpdateClientInput {
    pub(super) client_id: String,
    pub(super) update: ClientMetadataInput,
}
