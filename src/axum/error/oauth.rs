use super::ErrorDetails;
use crate::AuthError;
use axum::{http::StatusCode, response::Response};

pub(super) fn response(error: &AuthError) -> Option<Response> {
    match error {
        AuthError::OAuthStateGenerationFailed => Some(super::dynamic_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Unable to create verification",
        )),
        AuthError::OAuthProviderNotSupported(provider) => Some(super::dynamic_error(
            StatusCode::BAD_REQUEST,
            "PROVIDER_NOT_SUPPORTED",
            &format!("Provider {provider} is not supported."),
        )),
        AuthError::OAuthTokenRefreshNotSupported(provider) => Some(super::dynamic_error(
            StatusCode::BAD_REQUEST,
            "TOKEN_REFRESH_NOT_SUPPORTED",
            &format!("Provider {provider} does not support token refreshing."),
        )),
        _ => None,
    }
}

pub(super) fn is_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::OAuthProviderNotFound
            | AuthError::OAuthIdTokenNotSupported
            | AuthError::OAuthInvalidCode
            | AuthError::OAuthInvalidToken
            | AuthError::OAuthUserInfoUnavailable
            | AuthError::OAuthEmailNotFound
            | AuthError::OAuthStateMismatch
            | AuthError::OAuthStateInvalid
            | AuthError::OAuthStateGenerationFailed
            | AuthError::OAuthIssuerMismatch
            | AuthError::OAuthNonceBindingMissing
            | AuthError::OAuthAccountNotLinked
            | AuthError::OAuthSignupDisabled
            | AuthError::AccountNotFound
            | AuthError::FailedToUnlinkLastAccount
            | AuthError::SocialAccountAlreadyLinked
            | AuthError::LinkingNotAllowed
            | AuthError::LinkingDifferentEmailsNotAllowed
            | AuthError::OAuthProviderNotSupported(_)
            | AuthError::OAuthTokenRefreshNotSupported(_)
            | AuthError::OAuthProviderNotConfigured
            | AuthError::OAuthRefreshTokenNotFound
            | AuthError::OAuthFailedToRefreshToken
            | AuthError::OAuthFailedToGetAccessToken
            | AuthError::OAuthAccessTokenNotFound
    )
}

pub(super) fn details(error: &AuthError) -> ErrorDetails {
    if let Some(details) = account_details(error) {
        return details;
    }
    match error {
        AuthError::OAuthProviderNotFound => (
            StatusCode::NOT_FOUND,
            "PROVIDER_NOT_FOUND",
            "Provider not found",
        ),
        AuthError::OAuthIdTokenNotSupported => (
            StatusCode::NOT_FOUND,
            "ID_TOKEN_NOT_SUPPORTED",
            "ID token sign in is not supported for this provider",
        ),
        AuthError::OAuthInvalidToken => {
            (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token")
        }
        AuthError::OAuthEmailNotFound => (
            StatusCode::UNAUTHORIZED,
            "USER_EMAIL_NOT_FOUND",
            "User email not found",
        ),
        AuthError::OAuthAccountNotLinked => (
            StatusCode::UNAUTHORIZED,
            "OAUTH_LINK_ERROR",
            "account not linked",
        ),
        AuthError::OAuthSignupDisabled => (
            StatusCode::UNAUTHORIZED,
            "OAUTH_LINK_ERROR",
            "signup disabled",
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            "FAILED_TO_GET_USER_INFO",
            "Failed to get user info",
        ),
    }
}

fn account_details(error: &AuthError) -> Option<ErrorDetails> {
    Some(match error {
        AuthError::AccountNotFound => (
            StatusCode::BAD_REQUEST,
            "ACCOUNT_NOT_FOUND",
            "Account not found",
        ),
        AuthError::FailedToUnlinkLastAccount => (
            StatusCode::BAD_REQUEST,
            "FAILED_TO_UNLINK_LAST_ACCOUNT",
            "You can't unlink your last account",
        ),
        AuthError::SocialAccountAlreadyLinked => (
            StatusCode::CONFLICT,
            "SOCIAL_ACCOUNT_ALREADY_LINKED",
            "Social account already linked",
        ),
        AuthError::LinkingNotAllowed => (
            StatusCode::UNAUTHORIZED,
            "LINKING_NOT_ALLOWED",
            "Account not linked - linking not allowed",
        ),
        AuthError::LinkingDifferentEmailsNotAllowed => (
            StatusCode::UNAUTHORIZED,
            "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
            "Account not linked - different emails not allowed",
        ),
        AuthError::OAuthProviderNotSupported(_) => (
            StatusCode::BAD_REQUEST,
            "PROVIDER_NOT_SUPPORTED",
            "Provider is not supported",
        ),
        AuthError::OAuthTokenRefreshNotSupported(_) => (
            StatusCode::BAD_REQUEST,
            "TOKEN_REFRESH_NOT_SUPPORTED",
            "Provider does not support token refreshing",
        ),
        AuthError::OAuthProviderNotConfigured => (
            StatusCode::BAD_REQUEST,
            "PROVIDER_NOT_CONFIGURED",
            "Account is not associated with a configured social provider.",
        ),
        AuthError::OAuthRefreshTokenNotFound => (
            StatusCode::BAD_REQUEST,
            "REFRESH_TOKEN_NOT_FOUND",
            "Refresh token not found",
        ),
        AuthError::OAuthFailedToRefreshToken => (
            StatusCode::BAD_REQUEST,
            "FAILED_TO_REFRESH_ACCESS_TOKEN",
            "Failed to refresh access token",
        ),
        AuthError::OAuthFailedToGetAccessToken => (
            StatusCode::BAD_REQUEST,
            "FAILED_TO_GET_ACCESS_TOKEN",
            "Failed to get a valid access token",
        ),
        AuthError::OAuthAccessTokenNotFound => (
            StatusCode::BAD_REQUEST,
            "ACCESS_TOKEN_NOT_FOUND",
            "Access token not found",
        ),
        _ => return None,
    })
}
