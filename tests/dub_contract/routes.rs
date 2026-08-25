use super::support::{configured_oauth, fixture, json, send};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::json as json_value;

const TRUSTED_CALLBACK: &str = concat!("http:", "//localhost/complete");
const TRUSTED_ORIGIN: &str = concat!("http:", "//localhost");
const HOSTILE_ORIGIN: &str = concat!("https:", "//evil.example");
const HOSTILE_CALLBACK: &str = concat!("https:", "//evil.example/complete");

fn link(body: serde_json::Value) -> Request<Body> {
    Request::post("/api/auth/dub/link")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn link_validation_and_absent_oauth_match_the_published_endpoint() {
    let fixture = fixture(false, |_| {});
    for (body, status, expected) in [
        (
            json_value!({}),
            StatusCode::BAD_REQUEST,
            json_value!({
                "message": "[body.callbackURL] Required",
                "code": "VALIDATION_ERROR"
            }),
        ),
        (
            json_value!({"callbackURL": "/dashboard"}),
            StatusCode::BAD_REQUEST,
            json_value!({
                "message": "[body.callbackURL] Invalid url",
                "code": "VALIDATION_ERROR"
            }),
        ),
        (
            json_value!({"callbackUrl": TRUSTED_CALLBACK}),
            StatusCode::BAD_REQUEST,
            json_value!({
                "message": "[body.callbackURL] Required",
                "code": "VALIDATION_ERROR"
            }),
        ),
        (
            json_value!({"callbackURL": TRUSTED_CALLBACK, "unknown": true}),
            StatusCode::NOT_FOUND,
            json_value!({"message": "Dub OAuth is not configured"}),
        ),
    ] {
        let (actual_status, _, body) = send(&fixture.app, link(body)).await;
        assert_eq!(actual_status, status);
        assert_eq!(json(&body), expected);
    }
}

#[tokio::test]
async fn cookie_requires_a_present_trusted_origin() {
    let fixture = fixture(false, |_| {});
    let missing_origin = Request::post("/api/auth/dub/link")
        .header(header::COOKIE, "session=caller-controlled")
        .body(Body::from(
            json_value!({"callbackURL": TRUSTED_CALLBACK}).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(&fixture.app, missing_origin).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        json(&body),
        json_value!({
            "message": "Missing or null Origin",
            "code": "MISSING_OR_NULL_ORIGIN"
        })
    );

    let hostile_origin = Request::post("/api/auth/dub/link")
        .header(header::COOKIE, "session=caller-controlled")
        .header(header::ORIGIN, HOSTILE_ORIGIN)
        .body(Body::from(
            json_value!({"callbackURL": TRUSTED_CALLBACK}).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(&fixture.app, hostile_origin).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        json(&body),
        json_value!({"message": "Invalid origin", "code": "INVALID_ORIGIN"})
    );
}

#[tokio::test]
async fn origin_and_fetch_metadata_are_ignored_without_a_cookie() {
    let fixture = fixture(false, |_| {});
    let no_cookie = Request::post("/api/auth/dub/link")
        .header(header::ORIGIN, HOSTILE_ORIGIN)
        .header("sec-fetch-site", "cross-site")
        .body(Body::from(
            json_value!({"callbackURL": TRUSTED_CALLBACK}).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(&fixture.app, no_cookie).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        json(&body),
        json_value!({"message": "Dub OAuth is not configured"})
    );
}

#[tokio::test]
async fn callback_origin_processing_runs_before_zod_validation() {
    let fixture = fixture(false, |_| {});
    let invalid_callback = Request::post("/api/auth/dub/link")
        .body(Body::from(
            json_value!({"callbackURL": HOSTILE_CALLBACK}).to_string(),
        ))
        .unwrap();
    let (status, _, body) = send(&fixture.app, invalid_callback).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        json(&body),
        json_value!({"message": "Invalid callbackURL", "code": "INVALID_CALLBACK_URL"})
    );

    let non_string = Request::post("/api/auth/dub/link")
        .body(Body::from(json_value!({"callbackURL": true}).to_string()))
        .unwrap();
    let (status, _, body) = send(&fixture.app, non_string).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(&body),
        json_value!({"message": "Invalid callbackURL: expected a string"})
    );
}

#[tokio::test]
async fn configured_oauth_is_the_upstream_empty_500_with_or_without_a_session() {
    let fixture = fixture(false, configured_oauth);
    for cookie in [None, Some("better-auth.session_token=not-a-real-session")] {
        let mut request = Request::post("/api/auth/dub/link")
            .header(header::ORIGIN, TRUSTED_ORIGIN)
            .body(Body::from(
                json_value!({"callbackURL": TRUSTED_CALLBACK}).to_string(),
            ))
            .unwrap();
        if let Some(cookie) = cookie {
            request
                .headers_mut()
                .insert(header::COOKIE, cookie.parse().unwrap());
        }
        let (status, _, body) = send(&fixture.app, request).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.is_empty());
    }
}
