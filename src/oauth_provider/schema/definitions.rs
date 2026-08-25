use super::{OAuthProviderConfigError, OAuthProviderModelSchema, OAuthProviderSchema};
use crate::PluginMigration;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OAuthProviderModel {
    Client,
    Resource,
    ClientResource,
    RefreshToken,
    AccessToken,
    Consent,
    ClientAssertion,
}

#[derive(Clone, Copy)]
enum Reference {
    Core(&'static str),
    Provider(OAuthProviderModel, &'static str),
}

#[derive(Clone, Copy)]
struct FieldDefinition {
    logical: &'static str,
    default_column: &'static str,
    sql: &'static str,
    reference: Option<Reference>,
    on_delete: Option<&'static str>,
    index: bool,
}

struct ModelDefinition {
    model: OAuthProviderModel,
    logical_name: &'static str,
    default_table: &'static str,
    id_sql: &'static str,
    fields: &'static [FieldDefinition],
    extra_columns: &'static [(&'static str, &'static str)],
    unique: &'static [&'static [&'static str]],
}

macro_rules! field {
    ($logical:literal, $column:literal, $sql:literal) => {
        FieldDefinition {
            logical: $logical,
            default_column: $column,
            sql: $sql,
            reference: None,
            on_delete: None,
            index: false,
        }
    };
    ($logical:literal, $column:literal, $sql:literal, index) => {
        FieldDefinition {
            index: true,
            ..field!($logical, $column, $sql)
        }
    };
    ($logical:literal, $column:literal, $sql:literal, ref $reference:expr, $on_delete:expr, $index:expr) => {
        FieldDefinition {
            logical: $logical,
            default_column: $column,
            sql: $sql,
            reference: Some($reference),
            on_delete: $on_delete,
            index: $index,
        }
    };
}

const CLIENT_FIELDS: &[FieldDefinition] = &[
    field!("clientId", "client_id", "TEXT NOT NULL UNIQUE"),
    field!("clientSecret", "client_secret", "TEXT"),
    field!("clientDiscoveryId", "client_discovery_id", "TEXT"),
    field!("disabled", "disabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
    field!("skipConsent", "skip_consent", "BOOLEAN"),
    field!("enableEndSession", "enable_end_session", "BOOLEAN"),
    field!("subjectType", "subject_type", "TEXT"),
    field!("scopes", "scopes", "TEXT[]"),
    field!(
        "clientCredentialsScopes",
        "client_credentials_scopes",
        "TEXT[] NOT NULL DEFAULT '{}'"
    ),
    field!(
        "userId",
        "user_id",
        "UUID",
        ref Reference::Core("lucid_auth_users"),
        None,
        true
    ),
    field!("createdAt", "created_at", "TIMESTAMPTZ"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ"),
    field!("name", "name", "TEXT"),
    field!("uri", "uri", "TEXT"),
    field!("icon", "icon", "TEXT"),
    field!("contacts", "contacts", "TEXT[]"),
    field!("tos", "tos", "TEXT"),
    field!("policy", "policy", "TEXT"),
    field!("softwareId", "software_id", "TEXT"),
    field!("softwareVersion", "software_version", "TEXT"),
    field!("softwareStatement", "software_statement", "TEXT"),
    field!("redirectUris", "redirect_uris", "TEXT[] NOT NULL"),
    field!(
        "postLogoutRedirectUris",
        "post_logout_redirect_uris",
        "TEXT[]"
    ),
    field!("backchannelLogoutUri", "backchannel_logout_uri", "TEXT"),
    field!(
        "backchannelLogoutSessionRequired",
        "backchannel_logout_session_required",
        "BOOLEAN"
    ),
    field!(
        "tokenEndpointAuthMethod",
        "token_endpoint_auth_method",
        "TEXT"
    ),
    field!("applicationType", "application_type", "TEXT"),
    field!("jwks", "jwks", "TEXT"),
    field!("jwksUri", "jwks_uri", "TEXT"),
    field!("grantTypes", "grant_types", "TEXT[]"),
    field!("responseTypes", "response_types", "TEXT[]"),
    field!("requirePKCE", "require_pkce", "BOOLEAN"),
    field!(
        "dpopBoundAccessTokens",
        "dpop_bound_access_tokens",
        "BOOLEAN NOT NULL DEFAULT FALSE"
    ),
    field!("referenceId", "reference_id", "TEXT"),
    field!("metadata", "metadata", "JSONB"),
];

const RESOURCE_FIELDS: &[FieldDefinition] = &[
    field!("identifier", "identifier", "TEXT NOT NULL UNIQUE"),
    field!("name", "name", "TEXT NOT NULL"),
    field!("accessTokenTtl", "access_token_ttl", "BIGINT"),
    field!("refreshTokenTtl", "refresh_token_ttl", "BIGINT"),
    field!("signingAlgorithm", "signing_algorithm", "TEXT"),
    field!("signingKeyId", "signing_key_id", "TEXT"),
    field!("allowedScopes", "allowed_scopes", "TEXT[]"),
    field!("customClaims", "custom_claims", "JSONB"),
    field!(
        "dpopBoundAccessTokensRequired",
        "dpop_bound_access_tokens_required",
        "BOOLEAN NOT NULL DEFAULT FALSE"
    ),
    field!("disabled", "disabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
    field!("createdAt", "created_at", "TIMESTAMPTZ"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ"),
    field!(
        "policyVersion",
        "policy_version",
        "BIGINT NOT NULL DEFAULT 1"
    ),
    field!("metadata", "metadata", "JSONB"),
];

const CLIENT_RESOURCE_FIELDS: &[FieldDefinition] = &[
    field!(
        "clientId",
        "client_id",
        "TEXT NOT NULL",
        ref Reference::Provider(OAuthProviderModel::Client, "clientId"),
        Some("CASCADE"),
        true
    ),
    field!(
        "resourceId",
        "resource_id",
        "TEXT NOT NULL",
        ref Reference::Provider(OAuthProviderModel::Resource, "identifier"),
        Some("CASCADE"),
        true
    ),
    field!("metadata", "metadata", "JSONB"),
    field!("createdAt", "created_at", "TIMESTAMPTZ"),
];

const REFRESH_FIELDS: &[FieldDefinition] = &[
    field!("token", "token", "TEXT NOT NULL UNIQUE"),
    field!(
        "clientId",
        "client_id",
        "TEXT NOT NULL",
        ref Reference::Provider(OAuthProviderModel::Client, "clientId"),
        None,
        true
    ),
    field!(
        "sessionId",
        "session_id",
        "UUID",
        ref Reference::Core("lucid_auth_sessions"),
        Some("SET NULL"),
        true
    ),
    field!(
        "userId",
        "user_id",
        "UUID NOT NULL",
        ref Reference::Core("lucid_auth_users"),
        None,
        true
    ),
    field!("referenceId", "reference_id", "TEXT"),
    field!(
        "authorizationCodeId",
        "authorization_code_id",
        "TEXT",
        index
    ),
    field!("resources", "resources", "TEXT[]"),
    field!(
        "requestedUserInfoClaims",
        "requested_user_info_claims",
        "TEXT[]"
    ),
    field!("expiresAt", "expires_at", "TIMESTAMPTZ NOT NULL"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("revoked", "revoked", "TIMESTAMPTZ"),
    field!("rotatedAt", "rotated_at", "TIMESTAMPTZ"),
    field!("rotationReplayResponse", "rotation_replay_response", "TEXT"),
    field!(
        "rotationReplayExpiresAt",
        "rotation_replay_expires_at",
        "TIMESTAMPTZ"
    ),
    field!("authTime", "auth_time", "TIMESTAMPTZ"),
    field!("confirmation", "confirmation", "JSONB"),
    field!("scopes", "scopes", "TEXT[] NOT NULL"),
];

const ACCESS_FIELDS: &[FieldDefinition] = &[
    field!("token", "token", "TEXT NOT NULL UNIQUE"),
    field!(
        "clientId",
        "client_id",
        "TEXT NOT NULL",
        ref Reference::Provider(OAuthProviderModel::Client, "clientId"),
        None,
        true
    ),
    field!(
        "sessionId",
        "session_id",
        "UUID",
        ref Reference::Core("lucid_auth_sessions"),
        Some("SET NULL"),
        true
    ),
    field!(
        "userId",
        "user_id",
        "UUID",
        ref Reference::Core("lucid_auth_users"),
        None,
        true
    ),
    field!("referenceId", "reference_id", "TEXT"),
    field!(
        "authorizationCodeId",
        "authorization_code_id",
        "TEXT",
        index
    ),
    field!("resources", "resources", "TEXT[]"),
    field!(
        "requestedUserInfoClaims",
        "requested_user_info_claims",
        "TEXT[]"
    ),
    field!(
        "refreshId",
        "refresh_id",
        "UUID",
        ref Reference::Provider(OAuthProviderModel::RefreshToken, "id"),
        None,
        true
    ),
    field!("expiresAt", "expires_at", "TIMESTAMPTZ NOT NULL"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("revoked", "revoked", "TIMESTAMPTZ"),
    field!("confirmation", "confirmation", "JSONB"),
    field!("scopes", "scopes", "TEXT[] NOT NULL"),
];

const CONSENT_FIELDS: &[FieldDefinition] = &[
    field!(
        "clientId",
        "client_id",
        "TEXT NOT NULL",
        ref Reference::Provider(OAuthProviderModel::Client, "clientId"),
        None,
        true
    ),
    field!(
        "userId",
        "user_id",
        "UUID",
        ref Reference::Core("lucid_auth_users"),
        None,
        true
    ),
    field!("referenceId", "reference_id", "TEXT"),
    field!("resources", "resources", "TEXT[]"),
    field!(
        "requestedUserInfoClaims",
        "requested_user_info_claims",
        "TEXT[]"
    ),
    field!("scopes", "scopes", "TEXT[] NOT NULL"),
    field!("createdAt", "created_at", "TIMESTAMPTZ NOT NULL"),
    field!("updatedAt", "updated_at", "TIMESTAMPTZ NOT NULL"),
];

const ASSERTION_FIELDS: &[FieldDefinition] =
    &[field!("expiresAt", "expires_at", "TIMESTAMPTZ NOT NULL")];

const DEFINITIONS: &[ModelDefinition] = &[
    ModelDefinition {
        model: OAuthProviderModel::Client,
        logical_name: "oauthClient",
        default_table: "lucid_auth_oauth_clients",
        id_sql: "UUID",
        fields: CLIENT_FIELDS,
        extra_columns: &[("expires_at", "TIMESTAMPTZ")],
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::Resource,
        logical_name: "oauthResource",
        default_table: "lucid_auth_oauth_resources",
        id_sql: "UUID",
        fields: RESOURCE_FIELDS,
        extra_columns: &[],
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::ClientResource,
        logical_name: "oauthClientResource",
        default_table: "lucid_auth_oauth_client_resources",
        id_sql: "UUID",
        fields: CLIENT_RESOURCE_FIELDS,
        extra_columns: &[],
        unique: &[&["clientId", "resourceId"]],
    },
    ModelDefinition {
        model: OAuthProviderModel::RefreshToken,
        logical_name: "oauthRefreshToken",
        default_table: "lucid_auth_oauth_refresh_tokens",
        id_sql: "UUID",
        fields: REFRESH_FIELDS,
        extra_columns: &[],
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::AccessToken,
        logical_name: "oauthAccessToken",
        default_table: "lucid_auth_oauth_access_tokens",
        id_sql: "UUID",
        fields: ACCESS_FIELDS,
        extra_columns: &[],
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::Consent,
        logical_name: "oauthConsent",
        default_table: "lucid_auth_oauth_consents",
        id_sql: "UUID",
        fields: CONSENT_FIELDS,
        extra_columns: &[],
        unique: &[],
    },
    ModelDefinition {
        model: OAuthProviderModel::ClientAssertion,
        logical_name: "oauthClientAssertion",
        default_table: "lucid_auth_oauth_client_assertions",
        id_sql: "TEXT",
        fields: ASSERTION_FIELDS,
        extra_columns: &[],
        unique: &[],
    },
];
