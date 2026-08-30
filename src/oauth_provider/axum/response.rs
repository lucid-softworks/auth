use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;

use super::super::OAuthProviderError;

#[derive(Serialize)]
struct OAuthErrorBody<'a> {
    error: &'a str,
    error_description: &'a str,
}

pub(crate) fn oauth_error(error: &OAuthProviderError) -> Response {
    if let OAuthProviderError::UnsupportedMediaType(message) = error {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(serde_json::json!({
                "message": message,
                "code": "UNSUPPORTED_MEDIA_TYPE"
            })),
        )
            .into_response();
    }
    if let OAuthProviderError::InsufficientScope {
        description,
        required_scopes,
    } = error
    {
        let scope = required_scopes.join(" ");
        let mut response = (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "insufficient_scope",
                "error_description": description,
                "scope": scope,
            })),
        )
            .into_response();
        let challenge = format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\"");
        if let Ok(value) = HeaderValue::from_str(&challenge) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        return no_store(response);
    }
    let status = StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::BAD_REQUEST);
    let description = description(error);
    let mut response = (
        status,
        Json(OAuthErrorBody {
            error: error.code(),
            error_description: description,
        }),
    )
        .into_response();
    if matches!(error, OAuthProviderError::BasicInvalidClient(_)) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Basic"));
    } else if let OAuthProviderError::ChallengedInvalidClient { scheme, .. } = error {
        if let Ok(value) = HeaderValue::from_str(scheme) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
    } else if matches!(error, OAuthProviderError::InvalidToken(_)) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer error=\"invalid_token\""),
        );
    }
    no_store(response)
}

pub(super) fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

pub(super) fn empty_no_store() -> Response {
    no_store(StatusCode::OK.into_response())
}

pub(super) fn description(error: &OAuthProviderError) -> &str {
    match error {
        OAuthProviderError::InvalidRequest(value)
        | OAuthProviderError::InvalidRedirectUri(value)
        | OAuthProviderError::UnauthorizedInvalidRequest(value)
        | OAuthProviderError::InvalidUser(value)
        | OAuthProviderError::InvalidClient(value)
        | OAuthProviderError::UnauthorizedInvalidClient(value)
        | OAuthProviderError::BasicInvalidClient(value)
        | OAuthProviderError::UnsupportedMediaType(value)
        | OAuthProviderError::InvalidGrant(value)
        | OAuthProviderError::UnauthorizedClient(value)
        | OAuthProviderError::UnsupportedGrantType(value)
        | OAuthProviderError::InvalidScope(value)
        | OAuthProviderError::InvalidTarget(value)
        | OAuthProviderError::AccessDenied(value)
        | OAuthProviderError::AuthorizationPending(value)
        | OAuthProviderError::SlowDown(value)
        | OAuthProviderError::ExpiredToken(value)
        | OAuthProviderError::InteractionRequired(value)
        | OAuthProviderError::LoginRequired(value)
        | OAuthProviderError::AccountSelectionRequired(value)
        | OAuthProviderError::ConsentRequired(value)
        | OAuthProviderError::RequestNotSupported(value)
        | OAuthProviderError::InvalidRequestUri(value)
        | OAuthProviderError::RequestUriNotSupported(value)
        | OAuthProviderError::InvalidToken(value)
        | OAuthProviderError::UnchallengedInvalidToken(value)
        | OAuthProviderError::InvalidDpopProof(value)
        | OAuthProviderError::UseDpopNonce(value)
        | OAuthProviderError::UnsupportedTokenType(value)
        | OAuthProviderError::ServerError(value)
        | OAuthProviderError::TemporarilyUnavailable(value)
        | OAuthProviderError::TooManyRequestsTemporarilyUnavailable(value) => value,
        OAuthProviderError::ChallengedInvalidClient { description, .. }
        | OAuthProviderError::InsufficientScope { description, .. } => description,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_basic_client_failures_receive_a_basic_challenge() {
        let post = oauth_error(&OAuthProviderError::InvalidClient(
            "invalid client_secret".into(),
        ));
        assert_eq!(post.status(), StatusCode::BAD_REQUEST);
        assert!(!post.headers().contains_key(header::WWW_AUTHENTICATE));

        let basic = oauth_error(&OAuthProviderError::BasicInvalidClient(
            "invalid client_secret".into(),
        ));
        assert_eq!(basic.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(basic.headers()[header::WWW_AUTHENTICATE], "Basic");
    }

    #[tokio::test]
    async fn insufficient_scope_preserves_description_and_required_scope() {
        let response = oauth_error(&OAuthProviderError::InsufficientScope {
            description: "access token is missing required scope: orders:write".into(),
            required_scopes: vec!["orders:write".into()],
        });
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"insufficient_scope\", scope=\"orders:write\""
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["scope"], "orders:write");
        assert_eq!(
            body["error_description"],
            "access token is missing required scope: orders:write"
        );
    }
}
