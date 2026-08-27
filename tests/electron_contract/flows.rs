use super::support::{
    application, body_json, challenge, cookie_header, cookie_value, set_cookies, sign_up_request,
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use tower::ServiceExt as _;

async fn start(app: &axum::Router, verifier: &str, state: &str) -> (String, Vec<String>, Value) {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "electron")
        .append_pair("state", state)
        .append_pair("code_challenge", &challenge(verifier))
        .finish();
    let response = app
        .clone()
        .oneshot(sign_up_request(
            Some(&query),
            Some((header::ORIGIN.as_str(), "myapp:/")),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookies = set_cookies(&response);
    let body = body_json(response).await;
    (
        body["electron_authorization_code"]
            .as_str()
            .unwrap_or_else(|| panic!("missing code in {body:?}; cookies: {cookies:?}"))
            .to_owned(),
        cookies,
        body,
    )
}

fn exchange(code: &str, state: &str, verifier: &str) -> Request<Body> {
    Request::post("/api/auth/electron/token")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ORIGIN, "myapp:/")
        .body(Body::from(
            json!({
                "token": code,
                "state": state,
                "code_verifier": verifier,
                "ignored": "stripped"
            })
            .to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn sign_up_issues_exact_raw_and_encoded_codes_then_exchanges_once() {
    let (app, service, _) = application(true, false);
    let verifier = "electron-verifier";
    let (code, cookies, _) = start(&app, verifier, "state-one").await;
    assert_eq!(code.len(), 32);
    assert!(code.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    assert!(cookies.iter().any(|cookie| {
        cookie.starts_with("better-auth.electron=")
            && cookie.contains("; Max-Age=120")
            && !cookie.contains("HttpOnly")
    }));
    assert!(cookies.iter().any(|cookie| {
        cookie.starts_with("better-auth.transfer_token=")
            && cookie.contains("; Max-Age=300")
            && cookie.contains("; HttpOnly")
    }));
    let redirect = cookie_value(&cookies, "better-auth.electron").unwrap();
    let decoded: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(redirect).unwrap()).unwrap();
    assert_eq!(decoded, json!({ "identifier": code, "state": "state-one" }));
    let stored = service
        .find_verification_value(&format!("electron:{code}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored.value).unwrap(),
        json!({
            "userId": body_user_id(&app, &code, "state-one", verifier).await,
            "codeChallenge": challenge(verifier),
            "state": "state-one"
        })
    );
}

async fn body_user_id(app: &axum::Router, code: &str, state: &str, verifier: &str) -> String {
    let response = app
        .clone()
        .oneshot(exchange(code, state, verifier))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookies(&response).iter().any(|cookie| {
        cookie.starts_with("better-auth.session_token=") && cookie.contains("HttpOnly")
    }));
    let body = body_json(response).await;
    assert_eq!(body["token"].as_str().unwrap().len(), 32);
    let replay = app
        .clone()
        .oneshot(exchange(code, state, verifier))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_json(replay).await,
        json!({
            "code": "INVALID_TOKEN", "message": "Invalid or expired token."
        })
    );
    body["user"]["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn concurrent_exchange_has_one_winner_and_failures_burn_the_code() {
    let (app, _, _) = application(true, false);
    let verifier = "race-verifier";
    let (code, _, _) = start(&app, verifier, "race-state").await;
    let (left, right) = tokio::join!(
        app.clone().oneshot(exchange(&code, "race-state", verifier)),
        app.clone().oneshot(exchange(&code, "race-state", verifier)),
    );
    let statuses = [left.unwrap().status(), right.unwrap().status()];
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NOT_FOUND)
            .count(),
        1
    );

    let (burned, _, _) = start(&app, verifier, "expected").await;
    let mismatch = app
        .clone()
        .oneshot(exchange(&burned, "wrong", verifier))
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    assert_eq!(body_json(mismatch).await["code"], "STATE_MISMATCH");
    assert_eq!(
        app.oneshot(exchange(&burned, "expected", verifier))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_nonmatching_new_session_refreshes_the_signed_transfer_cookie() {
    let (app, service, _) = application(true, false);
    let verifier = "refresh-verifier";
    let (code, _, _) = start(&app, verifier, "refresh-state").await;
    let transfer = service.signed_cookie_value(
        &json!({
            "client_id": "electron",
            "state": "later-state",
            "code_challenge": challenge("later-verifier")
        })
        .to_string(),
    );
    let response = app
        .oneshot(
            Request::post("/api/auth/electron/token")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "myapp:/")
                .header(
                    header::COOKIE,
                    format!("better-auth.transfer_token={transfer}"),
                )
                .body(Body::from(
                    json!({
                        "token": code,
                        "state": "refresh-state",
                        "code_verifier": verifier
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(set_cookies(&response).iter().any(|cookie| {
        cookie.starts_with("better-auth.transfer_token=")
            && cookie.contains("; Max-Age=300")
            && cookie.contains("; HttpOnly")
    }));
}

#[tokio::test]
async fn authenticated_transfer_echoes_only_callback_url_and_uses_shared_verification() {
    let (app, service, _) = application(true, false);
    let signed_up = app
        .clone()
        .oneshot(sign_up_request(
            None,
            Some((header::ORIGIN.as_str(), "myapp:/")),
        ))
        .await
        .unwrap();
    let cookies = set_cookies(&signed_up);
    let session_cookie = cookie_header(&cookies);
    let query = "client_id=electron&state=transfer-state&code_challenge=challenge";
    let response = app
        .clone()
        .oneshot(
            Request::post(format!("/api/auth/electron/transfer-user?{query}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, "myapp:/")
                .header(header::COOKIE, session_cookie)
                .body(Body::from(
                    r#"{"callbackURL":"myapp:/still-echoed","callbackUrl":"ignored"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let redirect_cookie = cookie_value(&set_cookies(&response), "better-auth.electron").unwrap();
    let body = body_json(response).await;
    assert_eq!(body["url"], "myapp:/still-echoed");
    assert_eq!(body["redirect"], true);
    let code = body["electron_authorization_code"].as_str().unwrap();
    assert_eq!(code.len(), 32);
    let stored = service
        .find_verification_value(&format!("electron:{code}"))
        .await
        .unwrap()
        .unwrap();
    let stored: Value = serde_json::from_str(&stored.value).unwrap();
    assert_eq!(stored["state"], "transfer-state");
    assert_eq!(stored["codeChallenge"], "challenge");
    assert!(stored.get("clientID").is_none());
    assert!(stored.get("callbackURL").is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&URL_SAFE_NO_PAD.decode(redirect_cookie).unwrap()).unwrap(),
        json!({ "identifier": code, "state": "transfer-state" })
    );

    let alias_only = app
        .oneshot(
            Request::post(
                "/api/auth/electron/transfer-user?client_id=electron&state=alias-state&code_challenge=challenge",
            )
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, "myapp:/")
            .header(header::COOKIE, cookie_header(&cookies))
            .body(Body::from(r#"{"callbackUrl":"ignored"}"#))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alias_only.status(), StatusCode::OK);
    let alias_body = body_json(alias_only).await;
    assert_eq!(alias_body["url"], serde_json::Value::Null);
    assert_eq!(alias_body["redirect"], false);
    assert_eq!(
        alias_body["electron_authorization_code"]
            .as_str()
            .unwrap()
            .len(),
        32
    );
}
