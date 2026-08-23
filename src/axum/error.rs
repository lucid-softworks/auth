use crate::{AuthError, protocol::better_auth::ErrorResponse};
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(crate) fn auth_error(error: AuthError) -> Response {
    let (status, code, message) = match &error {
        error if is_credential_error(error) => credential_error_details(error),
        AuthError::RateLimited => (
            StatusCode::TOO_MANY_REQUESTS,
            "TOO_MANY_REQUESTS",
            "Too many sign-in attempts",
        ),
        AuthError::AnonymousAccessDisabled => (
            StatusCode::FORBIDDEN,
            "ANONYMOUS_ACCESS_DISABLED",
            "Anonymous guest access is disabled",
        ),
        AuthError::AccountDisabled => (
            StatusCode::FORBIDDEN,
            "USER_BANNED",
            "The account is disabled",
        ),
        AuthError::Forbidden
        | AuthError::SessionNotFresh
        | AuthError::StepUpRequired
        | AuthError::NotFound
        | AuthError::UserAlreadyExists
        | AuthError::UserAlreadyExistsEmail
        | AuthError::LastOwner
        | AuthError::SoleOwnerRecoveryUnavailable
        | AuthError::InvalidGuestGrant
        | AuthError::InvalidRequest(_) => access_error_details(&error),
        AuthError::CredentialAccountNotFound
        | AuthError::InvalidPassword
        | AuthError::PasswordTooShort
        | AuthError::PasswordTooLong
        | AuthError::PasswordCompromised => password_error_details(&error),
        error if is_passkey_error(error) => passkey_error_details(error),
        AuthError::RecoveryCodesNotEnabled | AuthError::InvalidRecoveryCode => {
            recovery_error_details(&error)
        }
        AuthError::InvalidSession => (
            StatusCode::UNAUTHORIZED,
            "INVALID_SESSION",
            "The session is invalid or expired",
        ),
        AuthError::Unauthorized => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", "Unauthorized"),
        AuthError::InvalidApiKey => (
            StatusCode::UNAUTHORIZED,
            "INVALID_API_KEY",
            "The API key is invalid, expired, or revoked",
        ),
        AuthError::InvalidOrigin
        | AuthError::MissingOrigin
        | AuthError::InvalidCallbackUrl
        | AuthError::InvalidRedirectUrl
        | AuthError::InvalidErrorCallbackUrl
        | AuthError::InvalidNewUserCallbackUrl
        | AuthError::CrossSiteNavigationLogin => request_security_error_details(&error),
        AuthError::InvalidConfiguration(_)
        | AuthError::Storage(_)
        | AuthError::Worker
        | AuthError::PasswordCheckUnavailable => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            "Authentication failed",
        ),
    };
    (status, Json(ErrorResponse { code, message })).into_response()
}

fn is_passkey_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::PasskeyNotFound
            | AuthError::PasskeyAuthenticationNotFound
            | AuthError::LastPasskey
            | AuthError::PasskeyChallengeExpired
            | AuthError::PasskeyVerificationFailed
            | AuthError::PasskeyOriginMissing
            | AuthError::PasskeyRegistrationFailed
            | AuthError::PasskeySessionRequired
            | AuthError::PasskeyRegistrationForbidden
            | AuthError::PasskeyResolverRequired
            | AuthError::PasskeyResolvedUserInvalid
            | AuthError::CredentialAlreadyRegistered
    )
}

type ErrorDetails = (StatusCode, &'static str, &'static str);

fn is_credential_error(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::InvalidCredentials
            | AuthError::InvalidEmailOrPassword
            | AuthError::InvalidEmail
            | AuthError::EmailPasswordDisabled
            | AuthError::EmailPasswordSignUpDisabled
            | AuthError::EmailNotVerified
            | AuthError::VerificationEmailNotEnabled
            | AuthError::EmailMismatch
            | AuthError::EmailAlreadyVerified
            | AuthError::InvalidToken
            | AuthError::TokenExpired
            | AuthError::VerificationUserNotFound
            | AuthError::ResetPasswordDisabled
            | AuthError::InvalidPasswordResetToken
            | AuthError::PasswordResetUserNotFound
    )
}

fn credential_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::InvalidCredentials => (
            StatusCode::UNAUTHORIZED,
            "INVALID_USERNAME_OR_PASSWORD",
            "Invalid username or password",
        ),
        AuthError::InvalidEmailOrPassword => (
            StatusCode::UNAUTHORIZED,
            "INVALID_EMAIL_OR_PASSWORD",
            "Invalid email or password",
        ),
        AuthError::InvalidEmail => (StatusCode::BAD_REQUEST, "INVALID_EMAIL", "Invalid email"),
        AuthError::EmailPasswordDisabled => (
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_DISABLED",
            "Email and password is not enabled",
        ),
        AuthError::EmailPasswordSignUpDisabled => (
            StatusCode::BAD_REQUEST,
            "EMAIL_PASSWORD_SIGN_UP_DISABLED",
            "Email and password sign up is not enabled",
        ),
        AuthError::EmailNotVerified => (
            StatusCode::FORBIDDEN,
            "EMAIL_NOT_VERIFIED",
            "Email not verified",
        ),
        AuthError::VerificationEmailNotEnabled => (
            StatusCode::BAD_REQUEST,
            "VERIFICATION_EMAIL_NOT_ENABLED",
            "Verification email isn't enabled",
        ),
        AuthError::EmailMismatch => (StatusCode::BAD_REQUEST, "EMAIL_MISMATCH", "Email mismatch"),
        AuthError::EmailAlreadyVerified => (
            StatusCode::BAD_REQUEST,
            "EMAIL_ALREADY_VERIFIED",
            "Email is already verified",
        ),
        AuthError::TokenExpired => (StatusCode::UNAUTHORIZED, "TOKEN_EXPIRED", "Token expired"),
        AuthError::VerificationUserNotFound => {
            (StatusCode::UNAUTHORIZED, "USER_NOT_FOUND", "User not found")
        }
        AuthError::ResetPasswordDisabled => (
            StatusCode::BAD_REQUEST,
            "RESET_PASSWORD_DISABLED",
            "Reset password isn't enabled",
        ),
        AuthError::InvalidPasswordResetToken => {
            (StatusCode::BAD_REQUEST, "INVALID_TOKEN", "Invalid token")
        }
        AuthError::PasswordResetUserNotFound => {
            (StatusCode::BAD_REQUEST, "USER_NOT_FOUND", "User not found")
        }
        _ => (StatusCode::UNAUTHORIZED, "INVALID_TOKEN", "Invalid token"),
    }
}

fn request_security_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::InvalidOrigin => (
            StatusCode::FORBIDDEN,
            "INVALID_ORIGIN",
            "The request origin is not trusted",
        ),
        AuthError::MissingOrigin => (
            StatusCode::FORBIDDEN,
            "MISSING_OR_NULL_ORIGIN",
            "The request origin is missing or null",
        ),
        AuthError::InvalidCallbackUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_CALLBACK_URL",
            "The callback URL is not trusted",
        ),
        AuthError::InvalidRedirectUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_REDIRECT_URL",
            "The redirect URL is not trusted",
        ),
        AuthError::InvalidErrorCallbackUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_ERROR_CALLBACK_URL",
            "The error callback URL is not trusted",
        ),
        AuthError::InvalidNewUserCallbackUrl => (
            StatusCode::FORBIDDEN,
            "INVALID_NEW_USER_CALLBACK_URL",
            "The new-user callback URL is not trusted",
        ),
        _ => (
            StatusCode::FORBIDDEN,
            "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
            "Cross-site navigation login is blocked",
        ),
    }
}

fn access_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::Forbidden => (
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "You do not have permission to perform this action",
        ),
        AuthError::SessionNotFresh => (
            StatusCode::FORBIDDEN,
            "SESSION_NOT_FRESH",
            "Session is not fresh",
        ),
        AuthError::StepUpRequired => (
            StatusCode::FORBIDDEN,
            "STEP_UP_REQUIRED",
            "Verify a passkey or recovery code before performing this action",
        ),
        AuthError::NotFound => (
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "The requested authentication resource was not found",
        ),
        AuthError::UserAlreadyExists => (
            StatusCode::BAD_REQUEST,
            "USER_ALREADY_EXISTS",
            "A user with that username or email already exists",
        ),
        AuthError::UserAlreadyExistsEmail => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL",
            "User already exists. Use another email.",
        ),
        AuthError::LastOwner => (
            StatusCode::CONFLICT,
            "LAST_OWNER",
            "The final owner account cannot be removed or disabled",
        ),
        AuthError::SoleOwnerRecoveryUnavailable => (
            StatusCode::FORBIDDEN,
            "SOLE_OWNER_RECOVERY_UNAVAILABLE",
            "Local recovery requires the named account to be the sole owner",
        ),
        AuthError::InvalidGuestGrant => (
            StatusCode::UNAUTHORIZED,
            "INVALID_GUEST_GRANT",
            "The guest grant is invalid, expired, exhausted, or revoked",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "The authentication request is invalid",
        ),
    }
}

fn password_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::CredentialAccountNotFound => (
            StatusCode::BAD_REQUEST,
            "CREDENTIAL_ACCOUNT_NOT_FOUND",
            "The credential account was not found",
        ),
        AuthError::InvalidPassword => (
            StatusCode::BAD_REQUEST,
            "INVALID_PASSWORD",
            "Invalid password",
        ),
        AuthError::PasswordTooShort => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_SHORT",
            "Password too short",
        ),
        AuthError::PasswordCompromised => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_COMPROMISED",
            "The password has been compromised. Choose a different password",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "PASSWORD_TOO_LONG",
            "Password too long",
        ),
    }
}

fn passkey_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::PasskeyNotFound => (
            StatusCode::NOT_FOUND,
            "PASSKEY_NOT_FOUND",
            "Passkey not found",
        ),
        AuthError::PasskeyAuthenticationNotFound => (
            StatusCode::UNAUTHORIZED,
            "PASSKEY_NOT_FOUND",
            "Passkey not found",
        ),
        AuthError::LastPasskey => (
            StatusCode::CONFLICT,
            "LAST_PASSKEY",
            "An MFA-required account must keep at least one passkey",
        ),
        AuthError::PasskeyChallengeExpired => (
            StatusCode::BAD_REQUEST,
            "CHALLENGE_NOT_FOUND",
            "Challenge not found",
        ),
        AuthError::PasskeyVerificationFailed => (
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_FAILED",
            "Authentication failed",
        ),
        AuthError::PasskeyOriginMissing => {
            (StatusCode::BAD_REQUEST, "BAD_REQUEST", "origin missing")
        }
        AuthError::PasskeyRegistrationFailed => (
            StatusCode::BAD_REQUEST,
            "FAILED_TO_VERIFY_REGISTRATION",
            "Failed to verify registration",
        ),
        AuthError::PasskeySessionRequired => (
            StatusCode::UNAUTHORIZED,
            "SESSION_REQUIRED",
            "Passkey registration requires an authenticated session",
        ),
        AuthError::PasskeyRegistrationForbidden => (
            StatusCode::UNAUTHORIZED,
            "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY",
            "You are not allowed to register this passkey",
        ),
        AuthError::PasskeyResolverRequired => (
            StatusCode::BAD_REQUEST,
            "RESOLVE_USER_REQUIRED",
            "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false",
        ),
        AuthError::PasskeyResolvedUserInvalid => (
            StatusCode::BAD_REQUEST,
            "RESOLVED_USER_INVALID",
            "Resolved user is invalid",
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            "PREVIOUSLY_REGISTERED",
            "Previously registered",
        ),
    }
}

fn recovery_error_details(error: &AuthError) -> ErrorDetails {
    match error {
        AuthError::RecoveryCodesNotEnabled => (
            StatusCode::BAD_REQUEST,
            "BACKUP_CODES_NOT_ENABLED",
            "Recovery codes are not enabled for this account",
        ),
        _ => (
            StatusCode::UNAUTHORIZED,
            "INVALID_BACKUP_CODE",
            "The recovery code is invalid",
        ),
    }
}
