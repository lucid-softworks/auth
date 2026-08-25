use crate::support::{fixture, send};
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{
    AuthorizeReferenceAction, ReferenceAuthorizer, StripeCallbackContext, StripeCallbackError,
    StripeSessionSnapshot, StripeUserSnapshot,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
struct RecordingAuthorizer {
    calls: Mutex<Vec<(String, AuthorizeReferenceAction, StripeCallbackContext)>>,
}

#[async_trait]
impl ReferenceAuthorizer for RecordingAuthorizer {
    async fn authorize(
        &self,
        _user: &StripeUserSnapshot,
        _session: &StripeSessionSnapshot,
        reference_id: &str,
        action: AuthorizeReferenceAction,
        context: &StripeCallbackContext,
    ) -> Result<bool, StripeCallbackError> {
        self.calls
            .lock()
            .await
            .push((reference_id.into(), action, context.clone()));
        Ok(false)
    }
}

#[tokio::test]
async fn subscription_routes_require_a_session_and_authorize_foreign_references() {
    let without_callback = fixture(None).await;
    let unauthorized = send(
        &without_callback.app,
        Request::get("/api/auth/subscription/list")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(unauthorized.0, StatusCode::UNAUTHORIZED);
    assert_eq!(unauthorized.2["code"], "UNAUTHORIZED");

    let disallowed = send(
        &without_callback.app,
        Request::get("/api/auth/subscription/list?referenceId=someone-else")
            .header(header::COOKIE, &without_callback.cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(disallowed.0, StatusCode::BAD_REQUEST);
    assert_eq!(disallowed.2["code"], "REFERENCE_ID_NOT_ALLOWED");

    let authorizer = Arc::new(RecordingAuthorizer::default());
    let with_callback = fixture(Some(authorizer.clone())).await;
    let denied = send(
        &with_callback.app,
        Request::get("/api/auth/subscription/list?referenceId=shared-account")
            .header(header::COOKIE, &with_callback.cookie)
            .header("x-contract", "preserved")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(denied.0, StatusCode::UNAUTHORIZED);
    let calls = authorizer.calls.lock().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "shared-account");
    assert_eq!(calls[0].1, AuthorizeReferenceAction::ListSubscription);
    assert_eq!(calls[0].2.method.as_deref(), Some("GET"));
    assert_eq!(calls[0].2.path.as_deref(), Some("/subscription/list"));
    assert_eq!(
        calls[0].2.query.as_deref(),
        Some("referenceId=shared-account")
    );
    assert_eq!(
        calls[0].2.headers.get("x-contract").map(String::as_str),
        Some("preserved")
    );
}
