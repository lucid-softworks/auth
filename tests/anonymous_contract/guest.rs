use super::*;
use lucid_auth::{
    AdminPlugin, GuestCapabilityPlugin, NewGuestGrant, NewPasswordUser, OwnerPolicyPlugin,
};

#[tokio::test]
async fn guest_capability_sessions_are_not_anonymous_plugin_upgrade_sources() {
    let store = Arc::new(MemoryStore::default());
    let links = Arc::new(LinkRecorder::default());
    let mut config = AuthConfig::new([41_u8; 32]).unwrap();
    config.email_and_password.enabled = true;
    config.trust_origin("http://localhost").unwrap();
    config
        .add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))
        .unwrap();
    config.add_plugin(OwnerPolicyPlugin).unwrap();
    config
        .add_plugin(AnonymousPlugin::new(AnonymousPluginConfig {
            on_link_account: Some(links.clone()),
            ..AnonymousPluginConfig::default()
        }))
        .unwrap();
    config
        .add_plugin(GuestCapabilityPlugin::new(store.clone()))
        .unwrap();
    let service = Arc::new(AuthService::new(store.clone(), config));
    service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let owner = service
        .sign_in_username("owner", "correct horse battery staple".into(), None, None)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let grant = service
        .issue_guest_grant(
            &owner.session,
            NewGuestGrant {
                label: "Scoped guest".into(),
                permissions: vec!["documents:read".into()],
                resource_scopes: vec!["documents/one".into()],
                valid_from: now,
                expires_at: now + chrono::Duration::hours(1),
                max_uses: Some(1),
            },
        )
        .await
        .unwrap();
    let guest = service
        .redeem_guest_grant(&grant.token, None, None)
        .await
        .unwrap();
    let guest_id = guest.session.user.id;
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&guest.token)
    );
    let response = lucid_auth::axum::router(service.clone())
        .oneshot(email_signup(
            &cookie,
            "guest-upgrade@example.com",
            "Permanent",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(store.find_user_by_id(&guest_id).await.unwrap().is_some());
    assert!(
        service
            .guest_capability_principal(&guest.token)
            .await
            .unwrap()
            .is_some()
    );
    assert!(links.0.lock().unwrap().is_empty());
}
