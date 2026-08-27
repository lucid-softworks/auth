use super::support::application_with_redirects;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::ExpoOptions;
use tower::ServiceExt;

async fn location(path: &str) -> String {
    let (app, _) = application_with_redirects(Some(ExpoOptions::default()), true);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/auth{path}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn callback_family_redirects_handoff_the_complete_cookie_header() {
    let redirected = location("/magic-link/verify-oracle").await;
    let redirected = url::Url::parse(&redirected).unwrap();
    assert_eq!(redirected.scheme(), "oracle");
    assert_eq!(
        redirected
            .query_pairs()
            .find(|(name, _)| name == "existing")
            .unwrap()
            .1,
        "yes"
    );
    let cookies = redirected
        .query_pairs()
        .filter(|(name, _)| name == "cookie")
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    assert_eq!(cookies.len(), 1);
    assert_eq!(
        cookies[0],
        "better-auth.session_token=signed; HttpOnly; Path=/, better-auth.session_data=cached; HttpOnly; Path=/"
    );
}

#[tokio::test]
async fn untrusted_http_and_unrelated_redirects_never_receive_cookies() {
    assert_eq!(location("/verify-email-oracle").await, "evil:///complete");
    assert_eq!(
        location("/callback-oracle").await,
        "https://web.example/complete"
    );
    assert_eq!(
        location("/unrelated-redirect").await,
        "oracle:///complete?existing=yes&cookie=stale&cookie=duplicate"
    );
}
