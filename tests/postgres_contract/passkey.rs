use super::database_create;
use chrono::Utc;
use lucid_auth::{AuthStore, StoredPasskey, postgres::PostgresStore};
use uuid::Uuid;

pub(super) async fn passkey_counters_are_atomic(
    store: &PostgresStore,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let passkey = store
        .save_passkey(database_create(
            StoredPasskey {
                id: String::new(),
                user_id: user_id.to_owned(),
                name: None,
                public_key: "cHVibGljLWtleQ==".into(),
                credential_id: Uuid::new_v4().to_string(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                aaguid: None,
                created_at: now,
            },
            "passkey",
        ))
        .await?;
    assert_eq!(
        store
            .find_passkey_by_id(&passkey.id)
            .await?
            .expect("passkey lookup by ID")
            .id,
        passkey.id
    );
    let mut left = passkey.clone();
    left.counter = 1;
    let mut right = passkey;
    right.counter = 2;
    let (left, right) = tokio::join!(
        store.update_passkey_after_authentication(left, 0),
        store.update_passkey_after_authentication(right, 0),
    );
    assert_eq!(usize::from(left?) + usize::from(right?), 1);
    Ok(())
}
