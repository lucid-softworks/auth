use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OAuthProviderClientAdminCreateInput {
    pub redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub software_statement: Option<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub token_endpoint_auth_method: Option<String>,
    pub application_type: Option<String>,
    pub jwks: Option<Value>,
    pub jwks_uri: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub client_credentials_scopes: Vec<String>,
    pub response_types: Option<Vec<String>>,
    pub client_secret_expires_at: Option<DateTime<Utc>>,
    pub skip_consent: Option<bool>,
    pub enable_end_session: Option<bool>,
    pub require_pkce: Option<bool>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub subject_type: Option<String>,
    pub metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OAuthProviderClientAdminUpdateInput {
    pub redirect_uris: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub client_name: Option<String>,
    pub client_uri: Option<String>,
    pub logo_uri: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub tos_uri: Option<String>,
    pub policy_uri: Option<String>,
    pub software_id: Option<String>,
    pub software_version: Option<String>,
    pub software_statement: Option<String>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    pub backchannel_logout_uri: Option<String>,
    pub backchannel_logout_session_required: Option<bool>,
    pub application_type: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub client_credentials_scopes: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub client_secret_expires_at: Option<Option<DateTime<Utc>>>,
    pub skip_consent: Option<bool>,
    pub enable_end_session: Option<bool>,
    pub dpop_bound_access_tokens: Option<bool>,
    pub metadata: Option<Map<String, Value>>,
}

impl OAuthProviderClientAdminUpdateInput {
    pub(super) fn only_client_credentials_scopes(&self) -> bool {
        self.client_credentials_scopes.is_some()
            && self.redirect_uris.is_none()
            && self.scopes.is_none()
            && self.client_name.is_none()
            && self.client_uri.is_none()
            && self.logo_uri.is_none()
            && self.contacts.is_none()
            && self.tos_uri.is_none()
            && self.policy_uri.is_none()
            && self.software_id.is_none()
            && self.software_version.is_none()
            && self.software_statement.is_none()
            && self.post_logout_redirect_uris.is_none()
            && self.backchannel_logout_uri.is_none()
            && self.backchannel_logout_session_required.is_none()
            && self.application_type.is_none()
            && self.grant_types.is_none()
            && self.response_types.is_none()
            && self.client_secret_expires_at.is_none()
            && self.skip_consent.is_none()
            && self.enable_end_session.is_none()
            && self.dpop_bound_access_tokens.is_none()
            && self.metadata.is_none()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthProviderClientAdminRegistration {
    pub client: super::super::OAuthProviderClient,
    pub client_secret: Option<String>,
}
