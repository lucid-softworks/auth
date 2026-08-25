use super::support::{DELETE_COOKIE, fixture, json, send, set_cookies};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use lucid_auth::{AccessStore, AuthStore, DubCustomLeadError, FnDubCustomLeadTrack};
use serde_json::json as json_value;
use std::sync::Arc;
use tokio::sync::Mutex;

fn signup(email: &str, cookie: &str) -> Request<Body> {
    Request::post("/api/auth/sign-up/email")
        .header(header::ORIGIN, "http://localhost")
        .header(header::COOKIE, cookie)
        .body(Body::from(
            json_value!({
                "name": "Dub User",
                "email": email,
                "password": "correct horse battery staple"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn successful_default_tracking_is_post_commit_and_appends_the_exact_deletion_cookie() {
    let fixture = fixture(false, |options| {
        options.lead_event_name = Some("Registered".into());
    });
    let (status, headers, body) = send(
        &fixture.app,
        signup(
            "success@example.test",
            "dub_id=first%20click; dub_id=second",
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json(&body)["token"].is_string());
    let cookies = set_cookies(&headers);
    assert!(cookies.contains(&DELETE_COOKIE));
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.contains("session_token"))
    );
    let calls = fixture.tracker.calls().await;
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].click_id, "first click");
    assert_eq!(calls[0].event_name, "Registered");
    assert_eq!(calls[0].customer_name, "Dub User");
    assert_eq!(calls[0].customer_email, "success@example.test");
    assert_eq!(calls[0].customer_avatar, None);
}

#[tokio::test]
async fn rejected_default_tracking_is_swallowed_and_still_deletes_the_cookie() {
    let fixture = fixture(true, |_| {});
    let (status, headers, _) = send(
        &fixture.app,
        signup("provider-error@example.test", "dub_id=provider-error"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(set_cookies(&headers).contains(&DELETE_COOKIE));
    assert_eq!(fixture.tracker.calls().await.len(), 1);
}

#[tokio::test]
async fn rejected_custom_tracking_keeps_persistence_but_discards_every_response_cookie() {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let fixture = fixture(false, move |options| {
        options.custom_lead_track =
            Some(Arc::new(FnDubCustomLeadTrack::new(move |user, request| {
                let recorded = recorded.clone();
                async move {
                    recorded.lock().await.push((user, request));
                    Err(DubCustomLeadError::new("custom rejected"))
                }
            })));
    });
    let (status, headers, body) = send(
        &fixture.app,
        signup("custom-error@example.test", "dub_id=custom-error"),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.is_empty());
    assert!(set_cookies(&headers).is_empty());
    let user = fixture
        .store
        .find_user_by_email("custom-error@example.test")
        .await
        .unwrap()
        .unwrap();
    assert!(
        fixture
            .store
            .find_password_hash(user.id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(fixture.store.list_sessions(user.id).await.unwrap().len(), 1);
    assert_eq!(requests.lock().await.len(), 1);
    assert_eq!(requests.lock().await[0].1.path, "/sign-up/email");
    assert!(fixture.tracker.calls().await.is_empty());

    let (status, _, body) = send(
        &fixture.app,
        signup("custom-error@example.test", "dub_id=custom-error"),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json(&body)["code"], "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
}

#[tokio::test]
async fn disabled_missing_empty_and_case_mismatched_cookies_do_not_track_or_delete() {
    let disabled = fixture(false, |options| options.disable_lead_tracking = true);
    let (status, headers, _) = send(
        &disabled.app,
        signup("disabled@example.test", "dub_id=click"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!set_cookies(&headers).contains(&DELETE_COOKIE));
    assert!(disabled.tracker.calls().await.is_empty());

    for (index, cookie) in ["other=value", "dub_id=", "DUB_ID=wrong"]
        .into_iter()
        .enumerate()
    {
        let fixture = fixture(false, |_| {});
        let (status, headers, _) = send(
            &fixture.app,
            signup(&format!("missing-{index}@example.test"), cookie),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!set_cookies(&headers).contains(&DELETE_COOKIE));
        assert!(fixture.tracker.calls().await.is_empty());
    }
}
