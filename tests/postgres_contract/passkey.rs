use chrono::Utc;
use lucid_auth::{AuthStore, StoredPasskey, postgres::PostgresStore};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs_core::proto::{
    AttestationFormat, AuthenticatorTransport, COSEAlgorithm, COSEEC2Key, COSEKey, COSEKeyType,
    Credential, ECDSACurve, ParsedAttestation, RegisteredExtensions, UserVerificationPolicy,
};

pub(super) struct LegacyPasskey {
    credential_id: String,
    credential: serde_json::Value,
}

pub(super) async fn insert_legacy_passkey(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<LegacyPasskey, Box<dyn std::error::Error>> {
    let credential = Credential {
        cred_id: vec![1, 2, 3, 4].into(),
        cred: COSEKey {
            type_: COSEAlgorithm::ES256,
            key: COSEKeyType::EC_EC2(COSEEC2Key {
                curve: ECDSACurve::SECP256R1,
                x: vec![1; 32].into(),
                y: vec![2; 32].into(),
            }),
        },
        counter: 9,
        transports: Some(vec![AuthenticatorTransport::Internal]),
        user_verified: true,
        backup_eligible: true,
        backup_state: true,
        registration_policy: UserVerificationPolicy::Preferred,
        extensions: RegisteredExtensions::none(),
        attestation: ParsedAttestation::default(),
        attestation_format: AttestationFormat::None,
    };
    let credential = json!({ "cred": credential });
    let credential_id = credential["cred"]["cred_id"]
        .as_str()
        .expect("serialized credential ID")
        .to_owned();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO lucid_auth_passkeys \
         (id, user_id, name, credential_id, credential, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind("Legacy key")
    .bind(&credential_id)
    .bind(&credential)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(LegacyPasskey {
        credential_id,
        credential,
    })
}

pub(super) async fn assert_legacy_passkey_migrated(
    store: &PostgresStore,
    legacy: &LegacyPasskey,
) -> Result<(), Box<dyn std::error::Error>> {
    let passkey = store
        .find_passkey_by_credential_id(&legacy.credential_id)
        .await?
        .expect("migrated legacy passkey");
    assert_eq!(passkey.credential, legacy.credential);
    assert!(!passkey.public_key.is_empty());
    assert_eq!(passkey.counter, 9);
    assert_eq!(passkey.device_type, "multiDevice");
    assert!(passkey.backed_up);
    assert_eq!(passkey.transports.as_deref(), Some("internal"));
    Ok(())
}

pub(super) async fn passkey_public_key_column_count(
    pool: &sqlx::PgPool,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.columns \
         WHERE table_schema = current_schema() \
           AND table_name = 'lucid_auth_passkeys' AND column_name = 'public_key'",
    )
    .fetch_one(pool)
    .await
}

pub(super) async fn passkey_counters_are_atomic(
    store: &PostgresStore,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = Utc::now();
    let passkey = store
        .save_passkey(StoredPasskey {
            id: Uuid::new_v4(),
            user_id,
            name: None,
            public_key: "cHVibGljLWtleQ==".into(),
            credential_id: Uuid::new_v4().to_string(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: None,
            aaguid: None,
            credential: json!({}),
            created_at: now,
            updated_at: now,
        })
        .await?;
    assert_eq!(
        store
            .find_passkey_by_id(passkey.id)
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
