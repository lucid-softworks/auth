use super::*;
use crate::{AuthConfig, MemoryStore, NewPasswordUser, StoredPasskey};
use std::sync::Arc;

async fn owner_and_member() -> (AuthService, SignInResult, AuthUser) {
    let service = AuthService::new(
        Arc::new(MemoryStore::default()),
        AuthConfig::new([8_u8; 32]).unwrap(),
    );
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
async fn required_mfa_roles_need_recent_strong_authentication_for_changes() {
    let (service, mut owner, member) = owner_and_member().await;
    owner.session.session.assurance = Assurance::PasswordAndPasskey;
    owner.session.session.created_at = Utc::now() - chrono::Duration::minutes(16);
    let mut config = AuthConfig::new([8_u8; 32]).unwrap();
    config.required_mfa_roles = vec!["owner".into()];
    let hardened = AuthService::new(service.store.clone(), config);
    let error = hardened
        .set_user_role(&owner.session, member.id, "viewer")
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::StepUpRequired));
    owner.session.session.created_at = Utc::now();
    hardened
        .set_user_role(&owner.session, member.id, "viewer")
        .await
        .unwrap();
}

#[tokio::test]
async fn local_recovery_resets_only_the_sole_owner_and_records_it() {
    let (service, owner, _) = owner_and_member().await;
    let now = Utc::now();
    service
        .store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id: owner.session.user.id,
            name: Some("Lost key".into()),
            credential_id: "lost-credential".into(),
            credential: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await
        .unwrap();
    service
        .store
        .replace_recovery_codes(owner.session.user.id, vec!["lost-code".into()])
        .await
        .unwrap();
    service
        .local_recover_sole_owner("owner", "recovered-password".into())
        .await
        .unwrap();
    assert!(service.session(&owner.token).await.unwrap().is_none());
    assert!(
        service
            .list_passkeys(owner.session.user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        service
            .store
            .recovery_code_count(owner.session.user.id)
            .await
            .unwrap(),
        0
    );
    let recovered = service
        .sign_in_username("owner", "recovered-password".into(), None, None)
        .await
        .unwrap();
    assert!(recovered.session.user.must_change_password);
    let event = service
        .store
        .list_audit_events(1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(event.action, "owner.recovered_locally");
    assert!(event.actor_user_id.is_none());
}

#[tokio::test]
async fn local_recovery_refuses_to_choose_between_multiple_owners() {
    let (service, _, _) = owner_and_member().await;
    service
        .provision_password_user(NewPasswordUser {
            username: "second_owner".into(),
            name: "Second owner".into(),
            email: None,
            password: "password".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let error = service
        .local_recover_sole_owner("owner", "recovered-password".into())
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::SoleOwnerRecoveryUnavailable));
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

#[tokio::test]
async fn temporary_owner_credentials_cannot_use_administration() {
    let (service, mut owner, _) = owner_and_member().await;
    owner.session.user.must_change_password = true;
    let error = service.list_users(&owner.session, 10, 0).await.unwrap_err();
    assert!(matches!(error, AuthError::Forbidden));
}
