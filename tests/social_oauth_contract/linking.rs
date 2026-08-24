use super::*;

#[tokio::test]
async fn implicit_linking_requires_verified_local_and_provider_email_unless_trusted() {
    let (app, store, _) = application_with_policy(true, false);
    insert_local_email_owner(&store, false).await;
    let (cookie, state, _) = begin(&app).await;
    let response = app
        .oneshot(
            Request::get(format!(
                "/api/auth/callback/fixture?code=valid-code&state={state}"
            ))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost/oauth-error?source=test&error=account_not_linked"
    );

    let (app, store, _) = application_with_policy(false, false);
    insert_local_email_owner(&store, true).await;
    let (cookie, state, _) = begin(&app).await;
    let response = app
        .oneshot(
            Request::get(format!(
                "/api/auth/callback/fixture?code=valid-code&state={state}"
            ))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.headers()[header::LOCATION],
        "http://localhost/oauth-error?source=test&error=account_not_linked"
    );

    let (app, store, _) = application_with_policy(false, true);
    insert_local_email_owner(&store, true).await;
    let (cookie, state, _) = begin(&app).await;
    let response = app
        .oneshot(
            Request::get(format!(
                "/api/auth/callback/fixture?code=valid-code&state={state}"
            ))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::LOCATION], "/dashboard");
}
