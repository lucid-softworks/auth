use crate::postgres::{PostgresModel, PostgresWrite};
use serde::Serialize;
use serde_json::Value;

mod records;

pub(super) use records::{AccessRow, ClientRow, ConsentRow, LinkRow, RefreshRow, ResourceRow};

pub(super) fn client_projection(model: &PostgresModel<'_>) -> Result<String, crate::AuthError> {
    projection_with_text_ids(model, CLIENT_FIELDS, &["id", "userId"])
}

pub(super) fn refresh_projection(model: &PostgresModel<'_>) -> Result<String, crate::AuthError> {
    projection_with_text_ids(model, REFRESH_FIELDS, &["id", "sessionId", "userId"])
}

pub(super) fn access_projection(model: &PostgresModel<'_>) -> Result<String, crate::AuthError> {
    projection_with_text_ids(
        model,
        ACCESS_FIELDS,
        &["id", "sessionId", "userId", "refreshId"],
    )
}

pub(super) fn consent_projection(model: &PostgresModel<'_>) -> Result<String, crate::AuthError> {
    projection_with_text_ids(model, CONSENT_FIELDS, &["id", "userId"])
}

pub(super) fn resource_projection(model: &PostgresModel<'_>) -> Result<String, crate::AuthError> {
    projection_with_text_ids(model, RESOURCE_FIELDS, &["id"])
}

pub(super) fn link_projection(model: &PostgresModel<'_>) -> Result<String, crate::AuthError> {
    projection_with_text_ids(model, LINK_FIELDS, &["id"])
}

fn projection_with_text_ids(
    model: &PostgresModel<'_>,
    fields: &[(&str, &str)],
    text_ids: &[&str],
) -> Result<String, crate::AuthError> {
    if text_ids.is_empty() {
        return model.projection_as(fields);
    }
    fields
        .iter()
        .map(|(logical, alias)| {
            let column = model.quoted_column(logical)?;
            let cast = if text_ids.contains(logical) {
                "::TEXT"
            } else {
                ""
            };
            Ok(format!("{column}{cast} AS \"{alias}\""))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|fields| fields.join(", "))
}

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

pub(super) fn writes<'a, T: Serialize>(
    model: &'a PostgresModel<'_>,
    record: &T,
    extras: impl IntoIterator<Item = (&'static str, Value)>,
) -> Result<Vec<PostgresWrite<'a>>, crate::AuthError> {
    let mut values = record_values(record)?;
    values.remove("id");
    values.extend(
        extras
            .into_iter()
            .map(|(logical, value)| (logical.to_owned(), value)),
    );
    encode_values(model, &values)
}

pub(super) fn insert_writes<'a, T: Serialize>(
    model: &'a PostgresModel<'_>,
    record: &T,
    id: &crate::PreparedDatabaseId,
    extras: impl IntoIterator<Item = (&'static str, Value)>,
) -> Result<Vec<PostgresWrite<'a>>, crate::AuthError> {
    let mut values = record_values(record)?;
    values.remove("id");
    super::super::rows::insert_prepared_id(&mut values, id)?;
    values.extend(
        extras
            .into_iter()
            .map(|(logical, value)| (logical.to_owned(), value)),
    );
    encode_values(model, &values)
}

fn record_values<T: Serialize>(
    record: &T,
) -> Result<serde_json::Map<String, Value>, crate::AuthError> {
    serde_json::to_value(record)
        .map_err(|error| crate::AuthError::Storage(error.to_string()))?
        .as_object()
        .cloned()
        .ok_or_else(|| crate::AuthError::Storage("OAuth Provider record is not an object".into()))
}

fn encode_values<'a>(
    model: &'a PostgresModel<'_>,
    values: &serde_json::Map<String, Value>,
) -> Result<Vec<PostgresWrite<'a>>, crate::AuthError> {
    model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )
}
