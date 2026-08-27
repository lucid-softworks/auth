use super::support::{application, body_json, cookie_value, set_cookies};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::Value;
use tower::ServiceExt as _;

#[tokio::test]
async fn oauth_proxy_posts_in_process_and_forwards_each_inner_cookie() {
    let (app, service, evidence) = application(true, true);
    let response = app.oneshot(
        Request::get(
            "/api/auth/electron/init-oauth-proxy?provider=fixture&state=desktop-state&code_challenge=desktop-challenge",
        )
        .body(Body::empty())
        .unwrap(),
    ).await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .starts_with("https://provider.fixture/authorize?state=")
    );
    let cookies = set_cookies(&response);
    assert!(cookies.len() >= 2);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("better-auth.state="))
    );
    let transfer = cookie_value(&cookies, "better-auth.transfer_token").unwrap();
    let transfer = service.verify_cookie_value(&transfer).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&transfer).unwrap(),
        serde_json::json!({
            "client_id": "electron",
            "state": "desktop-state",
            "code_challenge": "desktop-challenge"
        })
    );
    assert_eq!(evidence.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn oauth_proxy_projects_inner_failures_as_http_500() {
    let (app, _, _) = application(true, false);
    let response = app
        .oneshot(
            Request::get(
                "/api/auth/electron/init-oauth-proxy?provider=missing&state=s&code_challenge=c",
            )
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = body_json(response).await;
    assert_eq!(body["code"], "INTERNAL_SERVER_ERROR");
    assert!(body["message"].is_string());
}
