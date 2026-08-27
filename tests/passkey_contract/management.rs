use super::*;

#[tokio::test]
async fn requires_the_official_unauthorized_session_error() {
    let (app, _, _) = application().await;
    let response = app
        .oneshot(
            Request::get("/api/auth/passkey/list-user-passkeys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(response).await,
        json!({ "code": "UNAUTHORIZED", "message": "Unauthorized" })
    );
}

#[tokio::test]
async fn matches_official_cross_account_ownership_errors() {
    let (app, service, store) = application().await;
    let luna = store.find_user_by_username("luna").await.unwrap().unwrap();
    let other = service
        .provision_password_user(NewPasswordUser {
            username: "other".into(),
            name: "Other".into(),
            email: None,
            password: "password".into(),
            role: "member".into(),
        })
        .await
        .unwrap();
    let now = Utc::now();
    let passkey = store
        .save_passkey(passkey_create(StoredPasskey {
            id: Uuid::new_v4().to_string(),
            user_id: other.id,
            name: Some("Other key".into()),
            credential_id: "other-credential".into(),
            public_key: "cHVibGljLWtleQ==".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
            created_at: now,
        }))
        .await
        .unwrap();
    let cookie = persisted_session_cookie(&service, &store, &luna.id).await;

    let response = app
        .clone()
        .oneshot(passkey_request(
            "/api/auth/passkey/update-passkey",
            &cookie,
            json!({ "id": passkey.id, "name": "Nope" }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response_json(response).await["code"],
        "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
    );

    let response = app
        .oneshot(passkey_request(
            "/api/auth/passkey/delete-passkey",
            &cookie,
            json!({ "id": passkey.id }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(response_json(response).await["code"], "UNAUTHORIZED");
}
