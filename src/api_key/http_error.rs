use crate::{ApiKeyError, protocol::better_auth::ErrorResponse};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) fn api_key_error(error: &ApiKeyError) -> Response {
    use ApiKeyError::*;
    let (status, code, message) = match error {
        UnauthorizedSession => details(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED_SESSION",
            "Unauthorized or invalid session",
        ),
        NotFound | PermissionDenied => {
            details(StatusCode::NOT_FOUND, "KEY_NOT_FOUND", "API Key not found")
        }
        Disabled => details(
            StatusCode::UNAUTHORIZED,
            "KEY_DISABLED",
            "API Key is disabled",
        ),
        Expired => details(
            StatusCode::UNAUTHORIZED,
            "KEY_EXPIRED",
            "API Key has expired",
        ),
        Invalid => details(
            StatusCode::UNAUTHORIZED,
            "INVALID_API_KEY",
            "Invalid API key.",
        ),
        UsageExceeded => details(
            StatusCode::TOO_MANY_REQUESTS,
            "USAGE_EXCEEDED",
            "API Key has reached its usage limit",
        ),
        RateLimited {
            retry_after_milliseconds,
        } => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "code": "RATE_LIMITED",
                    "message": "Rate limit exceeded.",
                    "details": { "tryAgainIn": retry_after_milliseconds }
                })),
            )
                .into_response();
        }
        error => request_error_details(error),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

fn request_error_details(error: &ApiKeyError) -> (StatusCode, &'static str, &'static str) {
    use ApiKeyError::*;
    if let Some(details) = organization_error_details(error) {
        return details;
    }
    match error {
        ServerOnlyProperty => details(
            StatusCode::BAD_REQUEST,
            "SERVER_ONLY_PROPERTY",
            "The property you're trying to set can only be set from the server auth instance only.",
        ),
        NoValuesToUpdate => details(
            StatusCode::BAD_REQUEST,
            "NO_VALUES_TO_UPDATE",
            "No values to update.",
        ),
        MetadataDisabled => details(
            StatusCode::BAD_REQUEST,
            "METADATA_DISABLED",
            "Metadata is disabled.",
        ),
        InvalidMetadata => details(
            StatusCode::BAD_REQUEST,
            "INVALID_METADATA_TYPE",
            "metadata must be an object or undefined",
        ),
        InvalidPrefixLength => details(
            StatusCode::BAD_REQUEST,
            "INVALID_PREFIX_LENGTH",
            "The prefix length is either too large or too small.",
        ),
        InvalidNameLength => details(
            StatusCode::BAD_REQUEST,
            "INVALID_NAME_LENGTH",
            "The name length is either too large or too small.",
        ),
        NameRequired => details(
            StatusCode::BAD_REQUEST,
            "NAME_REQUIRED",
            "API Key name is required.",
        ),
        ExpiresTooSmall => details(
            StatusCode::BAD_REQUEST,
            "EXPIRES_IN_IS_TOO_SMALL",
            "The expiresIn is smaller than the predefined minimum value.",
        ),
        ExpiresTooLarge => details(
            StatusCode::BAD_REQUEST,
            "EXPIRES_IN_IS_TOO_LARGE",
            "The expiresIn is larger than the predefined maximum value.",
        ),
        ExpirationDisabled => details(
            StatusCode::BAD_REQUEST,
            "KEY_DISABLED_EXPIRATION",
            "Custom key expiration values are disabled.",
        ),
        RefillAmountRequired => details(
            StatusCode::BAD_REQUEST,
            "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
            "refillAmount is required when refillInterval is provided",
        ),
        RefillIntervalRequired => details(
            StatusCode::BAD_REQUEST,
            "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
            "refillInterval is required when refillAmount is provided",
        ),
        _ => details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
    }
}

fn organization_error_details(
    error: &ApiKeyError,
) -> Option<(StatusCode, &'static str, &'static str)> {
    use ApiKeyError::*;
    Some(match error {
        OrganizationPluginRequired => details(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ORGANIZATION_PLUGIN_REQUIRED",
            "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
        ),
        OrganizationIdRequired => details(
            StatusCode::BAD_REQUEST,
            "ORGANIZATION_ID_REQUIRED",
            "Organization ID is required for organization-owned API keys.",
        ),
        UserNotOrganizationMember => details(
            StatusCode::FORBIDDEN,
            "USER_NOT_MEMBER_OF_ORGANIZATION",
            "You are not a member of the organization that owns this API key.",
        ),
        InsufficientOrganizationPermission => details(
            StatusCode::FORBIDDEN,
            "INSUFFICIENT_API_KEY_PERMISSIONS",
            "You do not have permission to perform this action on organization API keys.",
        ),
        InvalidReferenceId => details(
            StatusCode::UNAUTHORIZED,
            "INVALID_REFERENCE_ID_FROM_API_KEY",
            "The reference id from the API key is invalid.",
        ),
        _ => return None,
    })
}

const fn details(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> (StatusCode, &'static str, &'static str) {
    (status, code, message)
}
