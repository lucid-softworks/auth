use super::*;
use crate::{AuditPlugin, AuthConfig, MemoryAuditStore, MemoryStore, NewPasswordUser};
use std::sync::Arc;

async fn owner_and_member() -> (AuthService, SignInResult, AuthUser) {
    let mut config = AuthConfig::new([8_u8; 32]).unwrap();
    config
        .add_plugin(AuditPlugin::new(Arc::new(MemoryAuditStore::default())))
        .unwrap();
    let service = AuthService::new(Arc::new(MemoryStore::default()), config);
    service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Owner".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let member = service
        .provision_password_user(NewPasswordUser {
            username: "member".into(),
            name: "Member".into(),
            email: None,
            password: "password".into(),
            role: "member".into(),
        })
        .await
        .unwrap();
    let owner = service
        .sign_in_username("owner", "password".into(), None, None)
        .await
        .unwrap();
    (service, owner, member)
}

#[tokio::test]
async fn protects_the_final_owner_and_rejects_member_administration() {
    let (service, owner, member) = owner_and_member().await;
    let error = service
        .set_user_role(&owner.session, owner.session.user.id, "viewer")
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::LastOwner));
    let member_session = service
        .sign_in_username("member", "password".into(), None, None)
        .await
        .unwrap();
    let error = service
        .set_user_role(&member_session.session, member.id, "viewer")
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::Forbidden));
}

#[tokio::test]
async fn impersonation_is_bounded_and_returns_to_the_owner() {
    let (service, owner, member) = owner_and_member().await;
    let impersonated = service
        .impersonate_user(&owner.session, member.id, None, None)
        .await
        .unwrap();
    assert_eq!(impersonated.session.user.id, member.id);
    assert_eq!(
        impersonated.session.session.actor_user_id,
        Some(owner.session.user.id)
    );
    assert!(impersonated.session.session.expires_at <= Utc::now() + chrono::Duration::hours(1));
    let restored = service
        .stop_impersonating(&impersonated.session, None, None)
        .await
        .unwrap();
    assert_eq!(restored.session.user.id, owner.session.user.id);
    assert!(restored.session.session.actor_user_id.is_none());
    let forbidden = service
        .list_users(&impersonated.session, 10, 0)
        .await
        .unwrap_err();
    assert!(matches!(forbidden, AuthError::Forbidden));
}

#[tokio::test]
async fn owner_promotion_revokes_sessions_created_under_the_old_role() {
    let (service, owner, member) = owner_and_member().await;
    let member_session = service
        .sign_in_username("member", "password".into(), None, None)
        .await
        .unwrap();
    service
        .set_user_role(&owner.session, member.id, "owner")
        .await
        .unwrap();
    assert!(
        service
            .session(&member_session.token)
            .await
            .unwrap()
            .is_none()
    );
}
