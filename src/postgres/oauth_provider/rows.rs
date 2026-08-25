use crate::oauth_provider::{
    OAuthProviderAccessToken, OAuthProviderClient, OAuthProviderClientResource,
    OAuthProviderConsent, OAuthProviderRefreshToken, OAuthProviderResource,
};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

pub(super) const CLIENT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("clientId", "client_id"),
    ("clientSecret", "client_secret"),
    ("clientDiscoveryId", "client_discovery_id"),
    ("disabled", "disabled"),
    ("skipConsent", "skip_consent"),
    ("enableEndSession", "enable_end_session"),
    ("subjectType", "subject_type"),
    ("scopes", "scopes"),
    ("clientCredentialsScopes", "client_credentials_scopes"),
    ("userId", "user_id"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
    ("__clientExpiresAt", "expires_at"),
    ("name", "name"),
    ("uri", "uri"),
    ("icon", "icon"),
    ("contacts", "contacts"),
    ("tos", "tos"),
    ("policy", "policy"),
    ("softwareId", "software_id"),
    ("softwareVersion", "software_version"),
    ("softwareStatement", "software_statement"),
    ("redirectUris", "redirect_uris"),
    ("postLogoutRedirectUris", "post_logout_redirect_uris"),
    ("backchannelLogoutUri", "backchannel_logout_uri"),
    (
        "backchannelLogoutSessionRequired",
        "backchannel_logout_session_required",
    ),
    ("tokenEndpointAuthMethod", "token_endpoint_auth_method"),
    ("applicationType", "application_type"),
    ("jwks", "jwks"),
    ("jwksUri", "jwks_uri"),
    ("grantTypes", "grant_types"),
    ("responseTypes", "response_types"),
    ("requirePKCE", "require_pkce"),
    ("dpopBoundAccessTokens", "dpop_bound_access_tokens"),
    ("referenceId", "reference_id"),
    ("metadata", "metadata"),
];
pub(super) const RESOURCE_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("identifier", "identifier"),
    ("name", "name"),
    ("accessTokenTtl", "access_token_ttl"),
    ("refreshTokenTtl", "refresh_token_ttl"),
    ("signingAlgorithm", "signing_algorithm"),
    ("signingKeyId", "signing_key_id"),
    ("allowedScopes", "allowed_scopes"),
    ("customClaims", "custom_claims"),
    (
        "dpopBoundAccessTokensRequired",
        "dpop_bound_access_tokens_required",
    ),
    ("disabled", "disabled"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
    ("policyVersion", "policy_version"),
    ("metadata", "metadata"),
];
pub(super) const LINK_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("clientId", "client_id"),
    ("resourceId", "resource_id"),
    ("metadata", "metadata"),
    ("createdAt", "created_at"),
];
pub(super) const REFRESH_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("token", "token"),
    ("clientId", "client_id"),
    ("sessionId", "session_id"),
    ("userId", "user_id"),
    ("referenceId", "reference_id"),
    ("authorizationCodeId", "authorization_code_id"),
    ("resources", "resources"),
    ("requestedUserInfoClaims", "requested_user_info_claims"),
    ("expiresAt", "expires_at"),
    ("createdAt", "created_at"),
    ("revoked", "revoked"),
    ("rotatedAt", "rotated_at"),
    ("rotationReplayResponse", "rotation_replay_response"),
    ("rotationReplayExpiresAt", "rotation_replay_expires_at"),
    ("authTime", "auth_time"),
    ("confirmation", "confirmation"),
    ("scopes", "scopes"),
];
pub(super) const ACCESS_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("token", "token"),
    ("clientId", "client_id"),
    ("sessionId", "session_id"),
    ("userId", "user_id"),
    ("referenceId", "reference_id"),
    ("authorizationCodeId", "authorization_code_id"),
    ("resources", "resources"),
    ("requestedUserInfoClaims", "requested_user_info_claims"),
    ("refreshId", "refresh_id"),
    ("expiresAt", "expires_at"),
    ("createdAt", "created_at"),
    ("revoked", "revoked"),
    ("confirmation", "confirmation"),
    ("scopes", "scopes"),
];
pub(super) const CONSENT_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("clientId", "client_id"),
    ("userId", "user_id"),
    ("referenceId", "reference_id"),
    ("resources", "resources"),
    ("requestedUserInfoClaims", "requested_user_info_claims"),
    ("scopes", "scopes"),
    ("createdAt", "created_at"),
    ("updatedAt", "updated_at"),
];

#[derive(FromRow)]
pub(super) struct ClientRow {
    id: Uuid,
    client_id: String,
    client_secret: Option<String>,
    client_discovery_id: Option<String>,
    disabled: bool,
    skip_consent: Option<bool>,
    enable_end_session: Option<bool>,
    subject_type: Option<String>,
    scopes: Option<Vec<String>>,
    client_credentials_scopes: Vec<String>,
    user_id: Option<Uuid>,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    name: Option<String>,
    uri: Option<String>,
    icon: Option<String>,
    contacts: Option<Vec<String>>,
    tos: Option<String>,
    policy: Option<String>,
    software_id: Option<String>,
    software_version: Option<String>,
    software_statement: Option<String>,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Option<Vec<String>>,
    backchannel_logout_uri: Option<String>,
    backchannel_logout_session_required: Option<bool>,
    token_endpoint_auth_method: Option<String>,
    application_type: Option<String>,
    jwks: Option<String>,
    jwks_uri: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
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
            scopes: row.scopes,
            client_credentials_scopes: row.client_credentials_scopes,
            user_id: row.user_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
            expires_at: row.expires_at,
            name: row.name,
            uri: row.uri,
            icon: row.icon,
            contacts: row.contacts,
            tos: row.tos,
            policy: row.policy,
            software_id: row.software_id,
            software_version: row.software_version,
            software_statement: row.software_statement,
            redirect_uris: row.redirect_uris,
            post_logout_redirect_uris: row.post_logout_redirect_uris,
            backchannel_logout_uri: row.backchannel_logout_uri,
            backchannel_logout_session_required: row.backchannel_logout_session_required,
            token_endpoint_auth_method: row.token_endpoint_auth_method,
            application_type: row.application_type,
            jwks: row.jwks,
            jwks_uri: row.jwks_uri,
            grant_types: row.grant_types,
            response_types: row.response_types,
            require_pkce: row.require_pkce,
            dpop_bound_access_tokens: row.dpop_bound_access_tokens,
            reference_id: row.reference_id,
            metadata: row.metadata,
        }
    }
}

#[derive(FromRow)]
pub(super) struct ResourceRow {
    id: Uuid,
    identifier: String,
    name: String,
    access_token_ttl: Option<i64>,
    refresh_token_ttl: Option<i64>,
    signing_algorithm: Option<String>,
    signing_key_id: Option<String>,
    allowed_scopes: Option<Vec<String>>,
    custom_claims: Option<serde_json::Value>,
    dpop_bound_access_tokens_required: bool,
    disabled: bool,
    created_at: Option<DateTime<Utc>>,
    updated_at: Option<DateTime<Utc>>,
    policy_version: i64,
    metadata: Option<serde_json::Value>,
}

impl From<ResourceRow> for OAuthProviderResource {
    fn from(row: ResourceRow) -> Self {
        Self {
            id: row.id,
            identifier: row.identifier,
            name: row.name,
            access_token_ttl: row.access_token_ttl,
            refresh_token_ttl: row.refresh_token_ttl,
            signing_algorithm: row.signing_algorithm,
            signing_key_id: row.signing_key_id,
            allowed_scopes: row.allowed_scopes,
            custom_claims: row.custom_claims,
            dpop_bound_access_tokens_required: row.dpop_bound_access_tokens_required,
            disabled: row.disabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
            policy_version: row.policy_version,
            metadata: row.metadata,
        }
    }
}

#[derive(FromRow)]
pub(super) struct LinkRow {
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
pub(super) struct RefreshRow {
    id: Uuid,
    token: String,
    client_id: String,
    session_id: Option<Uuid>,
    user_id: Uuid,
    reference_id: Option<String>,
    authorization_code_id: Option<String>,
    resources: Option<Vec<String>>,
    requested_user_info_claims: Option<Vec<String>>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked: Option<DateTime<Utc>>,
    rotated_at: Option<DateTime<Utc>>,
    rotation_replay_response: Option<String>,
    rotation_replay_expires_at: Option<DateTime<Utc>>,
    auth_time: Option<DateTime<Utc>>,
    confirmation: Option<serde_json::Value>,
    scopes: Vec<String>,
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
            resources: row.resources,
            requested_user_info_claims: row.requested_user_info_claims,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked: row.revoked,
            rotated_at: row.rotated_at,
            rotation_replay_response: row.rotation_replay_response,
            rotation_replay_expires_at: row.rotation_replay_expires_at,
            auth_time: row.auth_time,
            confirmation: row.confirmation,
            scopes: row.scopes,
        }
    }
}

#[derive(FromRow)]
pub(super) struct AccessRow {
    id: Uuid,
    token: String,
    client_id: String,
    session_id: Option<Uuid>,
    user_id: Option<Uuid>,
    reference_id: Option<String>,
    authorization_code_id: Option<String>,
    resources: Option<Vec<String>>,
    requested_user_info_claims: Option<Vec<String>>,
    refresh_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    revoked: Option<DateTime<Utc>>,
    confirmation: Option<serde_json::Value>,
    scopes: Vec<String>,
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
            resources: row.resources,
            requested_user_info_claims: row.requested_user_info_claims,
            refresh_id: row.refresh_id,
            expires_at: row.expires_at,
            created_at: row.created_at,
            revoked: row.revoked,
            confirmation: row.confirmation,
            scopes: row.scopes,
        }
    }
}

#[derive(FromRow)]
pub(super) struct ConsentRow {
    id: Uuid,
    client_id: String,
    user_id: Option<Uuid>,
    reference_id: Option<String>,
    resources: Option<Vec<String>>,
    requested_user_info_claims: Option<Vec<String>>,
    scopes: Vec<String>,
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
            resources: row.resources,
            requested_user_info_claims: row.requested_user_info_claims,
            scopes: row.scopes,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}
