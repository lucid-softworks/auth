use super::{application_with_anonymous, json_response};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::json;
use tower::ServiceExt;

pub(super) async fn assert_empty_verify_body(app: Router) {
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(response).await,
        (
            StatusCode::BAD_REQUEST,
            json!({
                "code":"VALIDATION_ERROR",
                "message":"[body] Invalid input: expected object, received undefined"
            })
        )
    );
}

pub(super) async fn assert_verify_validation_cases(app: Router) {
    let cases = [
        (
            json!({}),
            "[body.message] Invalid input: expected string, received undefined; \
             [body.signature] Invalid input: expected string, received undefined",
        ),
        (
            json!({"message":1,"signature":false,"email":null}),
            "[body.message] Invalid input: expected string, received number; \
             [body.signature] Invalid input: expected string, received boolean; \
             [body.email] Invalid input: expected string, received null",
        ),
        (
            json!({"message":"","signature":"","email":"invalid"}),
            "[body.message] Too small: expected string to have >=1 characters; \
             [body.signature] Too small: expected string to have >=1 characters; \
             [body.email] Invalid email address",
        ),
        (
            json!({"message":"valid","signature":"valid","y":1,"x":2}),
            "[body] Unrecognized keys: \"y\", \"x\"",
        ),
    ];
    for (body, expected) in cases {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/auth/siwe/verify")
                    .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            json_response(response).await,
            (
                StatusCode::BAD_REQUEST,
                json!({"code":"VALIDATION_ERROR","message":expected})
            )
        );
    }
}

pub(super) async fn assert_unsupported_media_type(app: Router) {
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(response).await,
        (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            json!({
                "code":"UNSUPPORTED_MEDIA_TYPE",
                "message":"Content-Type \"text/plain\" is not allowed. Allowed types: application/json"
            })
        )
    );
}

pub(super) async fn assert_required_email_refinement() {
    let (non_anonymous, _) = application_with_anonymous("email001", false);
    assert_missing_email(non_anonymous.clone()).await;
    for (body, expected) in refinement_cases() {
        let response = non_anonymous
            .clone()
            .oneshot(
                Request::post("/api/auth/siwe/verify")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            json_response(response).await,
            (
                StatusCode::BAD_REQUEST,
                json!({"code":"VALIDATION_ERROR","message":expected})
            )
        );
    }
}

async fn assert_missing_email(app: Router) {
    let response = app
        .oneshot(
            Request::post("/api/auth/siwe/verify")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"message":"valid","signature":"valid"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json_response(response).await,
        (
            StatusCode::BAD_REQUEST,
            json!({
                "code":"VALIDATION_ERROR",
                "message":"[body.email] Email is required when the anonymous plugin option is disabled."
            })
        )
    );
}

fn refinement_cases() -> [(serde_json::Value, &'static str); 3] {
    [
        (
            json!({}),
            "[body.message] Invalid input: expected string, received undefined; \
             [body.signature] Invalid input: expected string, received undefined",
        ),
        (
            json!({"message":"","signature":""}),
            "[body.message] Too small: expected string to have >=1 characters; \
             [body.signature] Too small: expected string to have >=1 characters; \
             [body.email] Email is required when the anonymous plugin option is disabled.",
        ),
        (
            json!({"message":"valid","signature":"valid","extra":true}),
            "[body] Unrecognized key: \"extra\"",
        ),
    ]
}
