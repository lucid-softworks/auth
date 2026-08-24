use chrono::{Duration, Utc};
use lucid_auth::{
    AuthStore, EmailVerificationOutcome, PasswordResetOutcome, VerificationStore,
    VerificationValue, postgres::PostgresStore,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub async fn password_reset_is_atomic(
    store: &PostgresStore,
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let token_hash = hex::encode(Sha256::digest(b"postgres-password-reset"));
    store
        .create_verification(VerificationValue {
            purpose: "password-reset".into(),
            identifier: token_hash.clone(),
            payload: json!({ "user_id": user_id }),
            additional_fields: serde_json::Map::new(),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_password_reset(&token_hash, "first-hash".into(), now, true),
        store.consume_password_reset(&token_hash, "second-hash".into(), now, true)
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PasswordResetOutcome::Reset(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, PasswordResetOutcome::InvalidToken))
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM lucid_auth_sessions WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

pub async fn email_is_atomic(
    store: &PostgresStore,
    user: &lucid_auth::AuthUser,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let token_hash = hex::encode(Sha256::digest(b"postgres-email-verification"));
    store
        .create_verification(VerificationValue {
            purpose: "email-verification".into(),
            identifier: token_hash.clone(),
            payload: json!({ "email": user.email }),
            additional_fields: serde_json::Map::new(),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_email_verification(&token_hash, now),
        store.consume_email_verification(&token_hash, now)
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EmailVerificationOutcome::Verified(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EmailVerificationOutcome::InvalidToken))
            .count(),
        1
    );
    Ok(())
}

pub async fn values_are_atomic(
    store: &PostgresStore,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    store
        .create_verification(VerificationValue {
            purpose: "contract".into(),
            identifier: "single-use".into(),
            payload: json!({ "subject": user_id }),
            additional_fields: serde_json::Map::from_iter([("channel".into(), json!("email"))]),
            expires_at: now + Duration::minutes(1),
            created_at: now,
        })
        .await?;
    let (left, right) = tokio::join!(
        store.consume_verification("contract", "single-use", now),
        store.consume_verification("contract", "single-use", now)
    );
    let values = [left?, right?];
    assert_eq!(values.iter().filter(|value| value.is_some()).count(), 1);
    assert_eq!(
        values
            .iter()
            .flatten()
            .next()
            .expect("one atomic consumer")
            .additional_fields["channel"],
        "email"
    );

    store
        .create_verification(VerificationValue {
            purpose: "contract".into(),
            identifier: "expired".into(),
            payload: json!({}),
            additional_fields: serde_json::Map::new(),
            expires_at: now - Duration::seconds(1),
            created_at: now - Duration::minutes(1),
        })
        .await?;
    assert!(
        store
            .consume_verification("contract", "expired", now)
            .await?
            .is_none()
    );
    reservation_update_and_delete_are_atomic(store, now).await?;
    Ok(())
}

async fn reservation_update_and_delete_are_atomic(
    store: &PostgresStore,
    now: chrono::DateTime<Utc>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reservation = VerificationValue {
        purpose: "contract".into(),
        identifier: "reservation".into(),
        payload: json!({ "winner": true }),
        additional_fields: serde_json::Map::new(),
        expires_at: now + Duration::minutes(1),
        created_at: now,
    };
    let (left, right) = tokio::join!(
        store.reserve_verification(reservation.clone()),
        store.reserve_verification(reservation.clone())
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);

    let mut updated = reservation;
    updated.payload = json!({ "winner": "updated" });
    updated.expires_at = now + Duration::minutes(2);
    assert_eq!(
        store
            .update_verification(updated)
            .await?
            .expect("reserved value can be updated")
            .payload,
        json!({ "winner": "updated" })
    );
    assert!(
        store
            .delete_verification("contract", "reservation")
            .await?
            .is_some()
    );
    assert!(
        store
            .delete_verification("contract", "reservation")
            .await?
            .is_none()
    );
    Ok(())
}
