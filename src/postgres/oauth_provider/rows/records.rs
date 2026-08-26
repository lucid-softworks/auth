use crate::oauth_provider::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderClientResource,
    OAuthProviderConsent, OAuthProviderRefreshToken, OAuthProviderResource,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, types::Json};
use uuid::Uuid;

#[derive(FromRow)]
pub(in crate::postgres::oauth_provider) struct ClientRow {
    id: Uuid,
    client_id: String,
    client_secret: Option<String>,
    client_discovery_id: Option<String>,
    disabled: bool,
    skip_consent: Option<bool>,
    enable_end_session: Option<bool>,
    subject_type: Option<String>,
    scopes: Option<Json<Vec<String>>>,
    client_credentials_scopes: Json<Vec<String>>,
    user_id: Option<String>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    name: Option<String>,
    uri: Option<String>,
    icon: Option<String>,
    contacts: Option<Json<Vec<String>>>,
    tos: Option<String>,
    policy: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    software_statement: Option<String>,
    redirect_uris: Json<Vec<String>>,
    post_logout_redirect_uris: Option<Json<Vec<String>>>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    token_endpoint_auth_method: Option<String>,
    application_type: Option<String>,
    jwks: Option<String>,
    jwks_uri: Option<String>,
    grant_types: Option<Json<Vec<String>>>,
    response_types: Option<Json<Vec<String>>>,
    require_pkce: Option<bool>,
    dpop_bound_access_tokens: bool,
    reference_id: Option<String>,
    metadata: Option<serde_json::Value>,
}

impl From<ClientRow> for OAuthProviderClient {
    fn from(row: ClientRow) -> Self {
        Self {
            id: row.id,
            client_id: row.client_id,
            client_secret: row.client_secret,
            client_discovery_id: row.client_discovery_id,
            disabled: row.disabled,
            skip_consent: row.skip_consent,
            enable_end_session: row.enable_end_session,
            subject_type: row.subject_type,
            scopes: row.scopes.map(|value| value.0),
            client_credentials_scopes: row.client_credentials_scopes.0,
            user_id: row.user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: None,
            name: row.name,
            uri: row.uri,
            icon: row.icon,
            contacts: row.contacts.map(|value| value.0),
            tos: row.tos,
            policy: row.policy,
            software_id: row.software_id,
            software_version: row.software_version,
            software_statement: row.software_statement,
            redirect_uris: row.redirect_uris.0,
            post_logout_redirect_uris: row.post_logout_redirect_uris.map(|value| value.0),
            backchannel_logout_uri: row.backchannel_logout_uri,
            backchannel_logout_session_required: row.backchannel_logout_session_required,
            token_endpoint_auth_method: row.token_endpoint_auth_method,
            application_type: row.application_type,
            jwks: row.jwks,
            jwks_uri: row.jwks_uri,
            grant_types: row.grant_types.map(|value| value.0),
            response_types: row.response_types.map(|value| value.0),
            require_pkce: row.require_pkce,
            dpop_bound_access_tokens: row.dpop_bound_access_tokens,
            reference_id: row.reference_id,
            metadata: row.metadata,
        }
    }
}

#[derive(FromRow)]
pub(in crate::postgres::oauth_provider) struct ResourceRow {
    id: Uuid,
    identifier: String,
    name: String,
    access_token_ttl: Option<i32>,
    refresh_token_ttl: Option<i32>,
    signing_algorithm: Option<String>,
    signing_key_id: Option<String>,
    allowed_scopes: Option<Json<Vec<String>>>,
    custom_claims: Option<serde_json::Value>,
    dpop_bound_access_tokens_required: bool,
    disabled: bool,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    policy_version: i32,
    metadata: Option<serde_json::Value>,
}

impl From<ResourceRow> for OAuthProviderResource {
    fn from(row: ResourceRow) -> Self {
        Self {
            id: row.id,
            identifier: row.identifier,
            name: row.name,
            access_token_ttl: row.access_token_ttl.map(i64::from),
            refresh_token_ttl: row.refresh_token_ttl.map(i64::from),
            signing_algorithm: row.signing_algorithm,
            signing_key_id: row.signing_key_id,
            allowed_scopes: row.allowed_scopes.map(|value| value.0),
            custom_claims: row.custom_claims,
            dpop_bound_access_tokens_required: row.dpop_bound_access_tokens_required,
            disabled: row.disabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            policy_version: i64::from(row.policy_version),
            metadata: row.metadata,
        }
    }
}

#[derive(FromRow)]
pub(in crate::postgres::oauth_provider) struct LinkRow {
    id: Uuid,
    client_id: String,
    resource_id: String,
    metadata: Option<serde_json::Value>,
    created_at: Option<DateTime<Utc>>,
}

impl From<LinkRow> for OAuthProviderClientResource {
    fn from(row: LinkRow) -> Self {
        Self {
            id: row.id,
            client_id: row.client_id,
            resource_id: row.resource_id,
            metadata: row.metadata,
            created_at: row.created_at,
        }
    }
}

#[derive(FromRow)]
pub(in crate::postgres::oauth_provider) struct RefreshRow {
    id: Uuid,
    token: String,
    client_id: String,
    session_id: Option<String>,
    user_id: String,
    reference_id: Option<String>,
    authorization_code_id: Option<String>,
    resources: Option<Json<Vec<String>>>,
    requested_user_info_claims: Option<Json<Vec<String>>>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked: Option<DateTime<Utc>>,
    rotated_at: Option<DateTime<Utc>>,
    rotation_replay_response: Option<String>,
    rotation_replay_expires_at: Option<DateTime<Utc>>,
    auth_time: Option<DateTime<Utc>>,
    confirmation: Option<serde_json::Value>,
    scopes: Json<Vec<String>>,
}

impl From<RefreshRow> for OAuthProviderRefreshToken {
    fn from(row: RefreshRow) -> Self {
        Self {
            id: row.id,
            token: row.token,
            client_id: row.client_id,
            session_id: row.session_id,
            user_id: row.user_id,
            reference_id: row.reference_id,
            authorization_code_id: row.authorization_code_id,
            resources: row.resources.map(|value| value.0),
            requested_user_info_claims: row.requested_user_info_claims.map(|value| value.0),
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked: row.revoked,
            rotated_at: row.rotated_at,
            rotation_replay_response: row.rotation_replay_response,
            rotation_replay_expires_at: row.rotation_replay_expires_at,
            auth_time: row.auth_time,
            confirmation: row.confirmation,
            scopes: row.scopes.0,
        }
    }
}

#[derive(FromRow)]
pub(in crate::postgres::oauth_provider) struct AccessRow {
    id: Uuid,
    token: String,
    client_id: String,
    session_id: Option<String>,
    user_id: Option<String>,
    reference_id: Option<String>,
    authorization_code_id: Option<String>,
    resources: Option<Json<Vec<String>>>,
    requested_user_info_claims: Option<Json<Vec<String>>>,
    refresh_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked: Option<DateTime<Utc>>,
    confirmation: Option<serde_json::Value>,
    scopes: Json<Vec<String>>,
}

impl From<AccessRow> for OAuthProviderAccessToken {
    fn from(row: AccessRow) -> Self {
        Self {
            id: row.id,
            token: row.token,
            client_id: row.client_id,
            session_id: row.session_id,
            user_id: row.user_id,
            reference_id: row.reference_id,
            authorization_code_id: row.authorization_code_id,
            resources: row.resources.map(|value| value.0),
            requested_user_info_claims: row.requested_user_info_claims.map(|value| value.0),
            refresh_id: row.refresh_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked: row.revoked,
            confirmation: row.confirmation,
            scopes: row.scopes.0,
        }
    }
}

#[derive(FromRow)]
pub(in crate::postgres::oauth_provider) struct ConsentRow {
    id: Uuid,
    client_id: String,
    user_id: Option<String>,
    reference_id: Option<String>,
    resources: Option<Json<Vec<String>>>,
    requested_user_info_claims: Option<Json<Vec<String>>>,
    scopes: Json<Vec<String>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<ConsentRow> for OAuthProviderConsent {
    fn from(row: ConsentRow) -> Self {
        Self {
            id: row.id,
            client_id: row.client_id,
            user_id: row.user_id,
            reference_id: row.reference_id,
            resources: row.resources.map(|value| value.0),
            requested_user_info_claims: row.requested_user_info_claims.map(|value| value.0),
            scopes: row.scopes.0,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
