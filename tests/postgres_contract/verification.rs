use chrono::{Duration, Utc};
use lucid_auth::{VerificationStore, VerificationValue, postgres::PostgresStore};
use serde_json::json;
use uuid::Uuid;

pub async fn values_are_atomic(
    store: &PostgresStore,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    store
        .create_verification(VerificationValue::new(
            "single-use",
            json!({ "subject": user_id }).to_string(),
            now + Duration::minutes(1),
        ))
        .await?;
    let (left, right) = tokio::join!(
        store.consume_verification("single-use"),
        store.consume_verification("single-use")
    );
    let values = [left?, right?];
    assert_eq!(values.iter().filter(|value| value.is_some()).count(), 1);
    assert_eq!(
        values
            .iter()
            .flatten()
            .next()
            .expect("one atomic consumer")
            .value,
        json!({ "subject": user_id }).to_string()
    );

    store
        .create_verification(VerificationValue::new(
            "expired",
            "expired",
            now - Duration::seconds(1),
        ))
        .await?;
    assert!(store.consume_verification("expired").await?.is_some());
    reservation_update_and_delete_are_atomic(store, now).await
}

async fn reservation_update_and_delete_are_atomic(
    store: &PostgresStore,
    now: chrono::DateTime<Utc>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reservation = VerificationValue::new(
        "reservation",
        json!({ "winner": true }).to_string(),
        now + Duration::minutes(1),
    );
    let (left, right) = tokio::join!(
        store.reserve_verification(reservation.clone()),
        store.reserve_verification(reservation.clone())
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);

    let mut updated = reservation;
    updated.value = json!({ "winner": "updated" }).to_string();
    updated.expires_at = now + Duration::minutes(2);
    assert_eq!(
        store
            .update_verification(updated)
            .await?
            .expect("reserved value can be updated")
            .value,
        json!({ "winner": "updated" }).to_string()
    );
    assert!(store.delete_verification("reservation").await?.is_some());
    assert!(store.delete_verification("reservation").await?.is_none());
    Ok(())
}
