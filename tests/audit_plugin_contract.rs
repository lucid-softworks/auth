use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use lucid_auth::{
    AdminPlugin, AuditEvent, AuditPlugin, AuditStore, AuthConfig, AuthError, AuthService,
    MemoryAuditStore, MemoryStore, NewPasswordUser, OperatorSecurityConfig, OperatorSecurityPlugin,
    OwnerPolicyPlugin, UsernamePlugin,
};
use serde_json::Value;
use std::sync::Arc;
use tower::ServiceExt;

async fn fixture(
    audit: Option<Arc<dyn AuditStore>>,
    retain: usize,
) -> (
    Router,
    Arc<AuthService>,
    lucid_auth::SignInResult,
    lucid_auth::AuthUser,
) {
    let mut config = AuthConfig::new([61_u8; 32]).unwrap();
    config.trust_origin("http://localhost").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    config
        .add_plugin(AdminPlugin::new(OwnerPolicyPlugin::admin_config()))
        .unwrap();
    config.add_plugin(OwnerPolicyPlugin).unwrap();
    let auth_store = Arc::new(MemoryStore::default());
    config
        .add_plugin(OperatorSecurityPlugin::new(
            auth_store.clone(),
            OperatorSecurityConfig::default(),
        ))
        .unwrap();
    if let Some(audit) = audit {
        config
            .add_plugin(AuditPlugin::new(audit).with_max_events(retain))
            .unwrap();
    }
    let service = Arc::new(AuthService::new(auth_store, config));
    let mut member = None;
    for (username, role) in [("owner", "owner"), ("member", "member")] {
        let user = service
            .provision_password_user(NewPasswordUser {
                username: username.into(),
                name: username.into(),
                email: None,
                password: "password".into(),
                role: role.into(),
            })
            .await
            .unwrap();
        if username == "member" {
            member = Some(user);
        }
    }
    let owner = service
        .sign_in_username("owner", "password".into(), None, None)
        .await
        .unwrap();
    (
        lucid_auth::axum::router(service.clone()),
        service,
        owner,
        member.unwrap(),
    )
}

#[tokio::test]
async fn route_and_store_requirement_are_absent_without_the_plugin() {
    let (app, service, _, _) = fixture(None, 10).await;
    assert!(service.plugin_metadata().iter().all(|descriptor| {
        descriptor
            .endpoints
            .iter()
            .all(|endpoint| endpoint.path != "/access/audit")
    }));
    let response = app
        .oneshot(
            Request::get("/api/auth/access/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn plugin_records_identity_applies_retention_and_owns_the_route() {
    let audit = Arc::new(MemoryAuditStore::default());
    let (app, service, owner, member) = fixture(Some(audit), 2).await;
    assert!(service.plugin_metadata().iter().any(|descriptor| {
        descriptor.id == "lucid-security-audit"
            && descriptor
                .endpoints
                .iter()
                .any(|endpoint| endpoint.path == "/access/audit")
    }));
    for role in ["viewer", "member", "viewer"] {
        service
            .set_user_role(&owner.session, &member.id, role)
            .await
            .unwrap();
    }
    let events = service.list_audit_events(&owner.session, 10).await.unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| {
        event.actor_user_id == Some(owner.session.user.id.clone())
            && event.subject_user_id == Some(member.id.clone())
            && event.outcome == lucid_auth::AuditOutcome::Success
    }));

    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&owner.token)
    );
    let response = app
        .oneshot(
            Request::get("/api/auth/access/audit?limit=1")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["events"].as_array().unwrap().len(), 1);
}

#[derive(Clone)]
struct FailingAuditStore;

#[async_trait]
impl AuditStore for FailingAuditStore {
    async fn record_audit_event(
        &self,
        _event: AuditEvent,
        _retain: usize,
    ) -> Result<(), AuthError> {
        Err(AuthError::Storage("audit sink unavailable".into()))
    }

    async fn list_audit_events(&self, _limit: usize) -> Result<Vec<AuditEvent>, AuthError> {
        Err(AuthError::Storage("audit sink unavailable".into()))
    }

    async fn anonymize_user(&self, _user_id: &str) -> Result<(), AuthError> {
        Err(AuthError::Storage("audit sink unavailable".into()))
    }
}

#[tokio::test]
async fn sink_failure_is_fail_open_for_authoritative_writes() {
    let (_, service, owner, member) = fixture(Some(Arc::new(FailingAuditStore)), 10).await;
    let updated = service
        .set_user_role(&owner.session, &member.id, "viewer")
        .await
        .unwrap();
    assert_eq!(updated.role, "viewer");
    assert!(matches!(
        service.list_audit_events(&owner.session, 10).await,
        Err(AuthError::Storage(message)) if message == "audit sink unavailable"
    ));
}

#[tokio::test]
async fn records_impersonated_and_actorless_identity() {
    let audit = Arc::new(MemoryAuditStore::default());
    let (_, service, owner, member) = fixture(Some(audit.clone()), 100).await;

    service
        .impersonate_user(&owner.session, &member.id, None, None)
        .await
        .unwrap();
    service
        .operator_security()
        .unwrap()
        .local_recover_sole_owner("owner", "replacement-password".into())
        .await
        .unwrap();

    let events = audit.list_audit_events(100).await.unwrap();
    let impersonation = events
        .iter()
        .find(|event| event.action == "impersonation.started")
        .unwrap();
    assert_eq!(
        impersonation.actor_user_id,
        Some(owner.session.user.id.clone())
    );
    assert_eq!(impersonation.subject_user_id, Some(member.id.clone()));

    let recovery = events
        .iter()
        .find(|event| event.action == "operator_security.owner_recovered")
        .unwrap();
    assert_eq!(recovery.actor_user_id, None);
    assert_eq!(
        recovery.subject_user_id,
        Some(owner.session.user.id.clone())
    );
}

#[tokio::test]
async fn deleting_a_user_anonymizes_prior_event_identity() {
    let audit = Arc::new(MemoryAuditStore::default());
    let (_, service, owner, member) = fixture(Some(audit.clone()), 100).await;
    service
        .set_user_role(&owner.session, &member.id, "viewer")
        .await
        .unwrap();
    service
        .remove_user(&owner.session, &member.id)
        .await
        .unwrap();

    let events = audit.list_audit_events(100).await.unwrap();
    let role_change = events
        .iter()
        .find(|event| event.action == "user.role.changed")
        .unwrap();
    assert_eq!(
        role_change.actor_user_id,
        Some(owner.session.user.id.clone())
    );
    assert_eq!(role_change.subject_user_id, None);
}
