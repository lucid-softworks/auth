use super::*;

#[tokio::test]
async fn user_updates_refresh_every_active_secondary_session_without_extending_expiry() {
    let primary = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let (_, app) = app_with_store(
        CookieCacheStrategy::Compact,
        SessionStorageMode::Database,
        Some(secondary.clone()),
        false,
        primary,
    );
    let first = sign_up(&app, "secondary-user@example.com").await;
    let second = sign_in(&app, "secondary-user@example.com").await;
    let first_token = first.body["token"].as_str().unwrap();
    let second_token = second.body["token"].as_str().unwrap();
    let mut before_expiries = Vec::new();
    for token in [first_token, second_token] {
        let cached: Value =
            serde_json::from_str(&secondary.get(token).await.unwrap().unwrap()).unwrap();
        before_expiries.push(cached["session"]["expiresAt"].clone());
    }

    let updated = request_with_cookies(
        &app,
        Request::builder()
            .method("POST")
            .uri("/api/auth/update-user")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "name": "Updated User" }).to_string()))
            .unwrap(),
        &first.cookies,
    )
    .await;

    assert_eq!(updated.body["status"], true);
    for (token, before_expiry) in [first_token, second_token].into_iter().zip(before_expiries) {
        let cached: Value =
            serde_json::from_str(&secondary.get(token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["user"]["name"], "Updated User");
        assert_eq!(cached["session"]["expiresAt"], before_expiry);
    }
    let authoritative = get_session(&app, &second.cookies, "?disableCookieCache=true").await;
    assert_eq!(authoritative.body["user"]["name"], "Updated User");
}

#[tokio::test]
async fn session_field_updates_follow_secondary_authority_and_preserve_expiry() {
    for mirror in [false, true] {
        let primary = Arc::new(MemoryStore::default());
        let secondary = Arc::new(MemorySecondaryStorage::default());
        let (_, app) = app_with_store(
            CookieCacheStrategy::Compact,
            SessionStorageMode::Database,
            Some(secondary.clone()),
            mirror,
            primary.clone(),
        );
        let signed_up = sign_up(
            &app,
            if mirror {
                "mirrored-fields@example.com"
            } else {
                "secondary-fields@example.com"
            },
        )
        .await;
        let token = signed_up.body["token"].as_str().unwrap();
        let before: Value =
            serde_json::from_str(&secondary.get(token).await.unwrap().unwrap()).unwrap();

        let updated = request_with_cookies(
            &app,
            Request::builder()
                .method("POST")
                .uri("/api/auth/update-session")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "theme": "dark" }).to_string()))
                .unwrap(),
            &signed_up.cookies,
        )
        .await;

        assert_eq!(updated.body["session"]["theme"], "dark");
        let cached: Value =
            serde_json::from_str(&secondary.get(token).await.unwrap().unwrap()).unwrap();
        assert_eq!(cached["session"]["theme"], "dark");
        assert_eq!(
            cached["session"]["expiresAt"],
            before["session"]["expiresAt"]
        );
        let user_id =
            uuid::Uuid::parse_str(signed_up.body["user"]["id"].as_str().unwrap()).unwrap();
        assert_eq!(
            primary.list_sessions(user_id).await.unwrap().len(),
            usize::from(mirror)
        );
    }
}
