use chrono::{Duration, Utc};
use lucid_auth::{
    AccessStore, AuthConfig, AuthError, AuthService, MemorySecondaryStorage, MemoryStore,
    NewPasswordUser, SecondaryStorage, VerificationIdentifierHasher, VerificationIdentifierStorage,
    VerificationStore, VerificationValue,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const SECRET: [u8; 32] = [93; 32];

#[tokio::test]
async fn secondary_only_values_cover_crud_and_ttl() {
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let service = service(store.clone(), secondary.clone(), false, false);
    let now = Utc::now();
    service
        .create_verification_value(value("crud", "token", now + Duration::minutes(2)))
        .await
        .unwrap();

    let key = "verification:crud:token";
    assert!(secondary.get(key).await.unwrap().is_some());
    assert!(
        store
            .find_verification("crud", "crud:token")
            .await
            .unwrap()
            .is_none()
    );
    let found = service
        .find_verification_value("crud", "token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.payload, json!({ "step": 1 }));

    let mut updated = value("crud", "token", now + Duration::minutes(3));
    updated.payload = json!({ "step": 2 });
    service
        .update_verification_value(updated)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        service
            .find_verification_value("crud", "token")
            .await
            .unwrap()
            .unwrap()
            .payload,
        json!({ "step": 2 })
    );

    service
        .create_verification_value(value("crud", "delete", now + Duration::minutes(2)))
        .await
        .unwrap();
    assert!(
        service
            .delete_verification_value("crud", "delete")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        service
            .find_verification_value("crud", "delete")
            .await
            .unwrap()
            .is_none()
    );

    service
        .create_verification_value(value("crud", "expired", now - Duration::seconds(1)))
        .await
        .unwrap();
    assert!(
        service
            .find_verification_value("crud", "expired")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn secondary_consumption_has_one_concurrent_winner_and_no_resurrection() {
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let service = service(store, secondary.clone(), false, false);
    let now = Utc::now();
    service
        .create_verification_value(value("consume", "token", now + Duration::minutes(2)))
        .await
        .unwrap();

    let (left, right) = tokio::join!(
        service.consume_verification_value("consume", "token", now),
        service.consume_verification_value("consume", "token", now),
    );
    assert_eq!(
        usize::from(left.unwrap().is_some()) + usize::from(right.unwrap().is_some()),
        1
    );
    assert!(
        secondary
            .get("verification:consume:token")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        service
            .consume_verification_value("consume", "token", now)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn hashed_identifiers_use_better_auth_sha256_base64url_and_plain_fallback() {
    use base64::Engine;
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let service = service(store, secondary.clone(), false, true);
    let now = Utc::now();
    service
        .create_verification_value(value("hashed", "secret", now + Duration::minutes(2)))
        .await
        .unwrap();
    let digest =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(b"hashed:secret"));
    assert!(
        secondary
            .get(&format!("verification:{digest}"))
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        secondary
            .get("verification:hashed:secret")
            .await
            .unwrap()
            .is_none()
    );

    let legacy = value("hashed", "legacy", now + Duration::minutes(2));
    secondary
        .set(
            "verification:hashed:legacy",
            serde_json::to_string(&legacy).unwrap(),
            Some(120),
        )
        .await
        .unwrap();
    assert!(
        service
            .consume_verification_value("hashed", "legacy", now)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        secondary
            .get("verification:hashed:legacy")
            .await
            .unwrap()
            .is_none()
    );
}

#[derive(Debug)]
struct PrefixHasher;

#[async_trait::async_trait]
impl VerificationIdentifierHasher for PrefixHasher {
    async fn hash(&self, identifier: &str) -> Result<String, AuthError> {
        Ok(format!("custom:{identifier}"))
    }
}

#[tokio::test]
async fn custom_identifier_overrides_follow_declared_prefix_order() {
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.secondary_storage = Some(secondary.clone());
    config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
    config.verification.store_identifier.overrides = vec![
        ("ordered:".into(), VerificationIdentifierStorage::Plain),
        (
            "ordered:special:".into(),
            VerificationIdentifierStorage::Custom(Arc::new(PrefixHasher)),
        ),
        (
            "custom:".into(),
            VerificationIdentifierStorage::Custom(Arc::new(PrefixHasher)),
        ),
    ];
    let service = AuthService::new(store, config);
    let expires_at = Utc::now() + Duration::minutes(2);

    service
        .create_verification_value(value("ordered", "special:value", expires_at))
        .await
        .unwrap();
    assert!(
        secondary
            .get("verification:ordered:special:value")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        secondary
            .get("verification:custom:ordered:special:value")
            .await
            .unwrap()
            .is_none()
    );

    service
        .create_verification_value(value("custom", "value", expires_at))
        .await
        .unwrap();
    assert!(
        secondary
            .get("verification:custom:custom:value")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn database_mirroring_survives_restart_and_enables_atomic_reservations() {
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let first = service(store.clone(), secondary.clone(), true, false);
    let now = Utc::now();
    first
        .create_verification_value(value("mirror", "restart", now + Duration::minutes(2)))
        .await
        .unwrap();
    secondary
        .delete("verification:mirror:restart")
        .await
        .unwrap();
    let restarted = service(store.clone(), secondary.clone(), true, false);
    assert!(
        restarted
            .find_verification_value("mirror", "restart")
            .await
            .unwrap()
            .is_some()
    );

    let reservation = value("reservation", "assertion", now + Duration::minutes(2));
    assert!(
        restarted
            .reserve_verification_value(reservation.clone())
            .await
            .unwrap()
    );
    assert!(
        !restarted
            .reserve_verification_value(reservation)
            .await
            .unwrap()
    );

    let secondary_only = service(store, secondary, false, false);
    let error = secondary_only
        .reserve_verification_value(value("reservation", "blocked", now + Duration::minutes(2)))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("reserveVerificationValue requires database-backed verification storage")
    );
}

#[tokio::test]
async fn mirrored_password_reset_revokes_secondary_and_database_sessions() {
    let store = Arc::new(MemoryStore::default());
    let secondary = Arc::new(MemorySecondaryStorage::default());
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.email_and_password.enabled = true;
    config.email_and_password.revoke_sessions_on_password_reset = true;
    config.secondary_storage = Some(secondary.clone());
    config.session.store_session_in_database = true;
    config.verification.store_in_database = true;
    let service = AuthService::new(store.clone(), config);
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "reset_user".into(),
            name: "Reset User".into(),
            email: Some("reset@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "member".into(),
        })
        .await
        .unwrap();
    let session = service
        .sign_in_email(
            "reset@example.com",
            "correct horse battery staple".into(),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert!(secondary.get(&session.token).await.unwrap().is_some());
    assert_eq!(store.list_sessions(user.id).await.unwrap().len(), 1);

    let token = "mirrored-password-reset";
    service
        .create_verification_value(VerificationValue {
            purpose: "password-reset".into(),
            identifier: hex::encode(Sha256::digest(token.as_bytes())),
            payload: json!({ "user_id": user.id }),
            additional_fields: serde_json::Map::new(),
            expires_at: Utc::now() + Duration::minutes(2),
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    service
        .reset_password(token, "replacement password".into())
        .await
        .unwrap();

    assert!(secondary.get(&session.token).await.unwrap().is_none());
    assert!(store.list_sessions(user.id).await.unwrap().is_empty());
    assert!(service.session(&session.token).await.unwrap().is_none());
    assert!(
        service
            .sign_in_email(
                "reset@example.com",
                "replacement password".into(),
                None,
                None,
                None,
                None,
            )
            .await
            .is_ok()
    );
}

fn service(
    store: Arc<MemoryStore>,
    secondary: Arc<MemorySecondaryStorage>,
    store_in_database: bool,
    hashed: bool,
) -> AuthService {
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.secondary_storage = Some(secondary);
    config.verification.store_in_database = store_in_database;
    if hashed {
        config.verification.store_identifier.default = VerificationIdentifierStorage::Hashed;
    }
    AuthService::new(store, config)
}

fn value(purpose: &str, identifier: &str, expires_at: chrono::DateTime<Utc>) -> VerificationValue {
    VerificationValue {
        purpose: purpose.into(),
        identifier: identifier.into(),
        payload: json!({ "step": 1 }),
        additional_fields: serde_json::Map::new(),
        expires_at,
        created_at: Utc::now(),
    }
}
