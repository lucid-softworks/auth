use crate::support::{fixture, send};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};

#[tokio::test]
async fn success_uses_exact_callback_casing_and_replaces_only_after_session_lookup() {
    let fixture = fixture(None).await;
    let path = "/api/auth/subscription/success?callbackURL=%2Fdone%2F%7BCHECKOUT_SESSION_ID%7D%2F%7BCHECKOUT_SESSION_ID%7D&checkoutSessionId=cs_exact&callbackUrl=%2Fwrong";
    let anonymous = send(
        &fixture.app,
        Request::get(path).body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(anonymous.0, StatusCode::FOUND);
    assert_eq!(
        anonymous.1[header::LOCATION],
        "http://localhost/api/auth/done/{CHECKOUT_SESSION_ID}/{CHECKOUT_SESSION_ID}"
    );
    assert!(
        fixture
            .client
            .calls("retrieve_checkout_session:cs_exact")
            .await
            .is_empty()
    );

    let authenticated = send(
        &fixture.app,
        Request::get(path)
            .header(header::COOKIE, &fixture.cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(authenticated.0, StatusCode::FOUND);
    assert_eq!(
        authenticated.1[header::LOCATION],
        "http://localhost/api/auth/done/cs_exact/cs_exact"
    );
    assert_eq!(
        fixture
            .client
            .calls("retrieve_checkout_session:cs_exact")
            .await
            .len(),
        1
    );

    let aliases = send(
        &fixture.app,
        Request::get(
            "/api/auth/subscription/success?callbackUrl=%2Fwrong&callback_url=%2Falso-wrong&checkout_session_id=cs_wrong",
        )
        .header(header::COOKIE, &fixture.cookie)
        .body(Body::empty())
        .unwrap(),
    )
    .await;
    assert_eq!(aliases.1[header::LOCATION], "http://localhost/api/auth/");
}
