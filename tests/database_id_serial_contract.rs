use chrono::{Duration, Utc};
use lucid_auth::{
    ApiKeyConfiguration, ApiKeyPlugin, AuthConfig, AuthService, AuthStore, DatabaseCreate,
    DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan, MemoryStore, NewApiKey, NewPasswordUser,
    OAuthAccountStore, RateLimitRequest, RateLimitStorageMode, StoredPasskey, VerificationValue,
};
use std::{collections::BTreeMap, sync::Arc};

const SECRET: [u8; 32] = [b'S'; 32];

fn api_key_input() -> NewApiKey {
    NewApiKey {
        config_id: "default".into(),
        name: None,
        prefix: None,
        expires_at: None,
        permissions: None,
        metadata: None,
        remaining: None,
        refill_amount: None,
        refill_interval: None,
        rate_limit_enabled: false,
        rate_limit_time_window: None,
        rate_limit_max: None,
    }
}

async fn save_serial_passkey(store: &MemoryStore, user_id: &str) -> String {
    store
        .save_passkey(DatabaseCreate::new(
            StoredPasskey {
                id: String::new(),
                user_id: user_id.to_owned(),
                name: None,
                credential_id: "serial-credential".into(),
                public_key: "public-key".into(),
                counter: 0,
                device_type: "singleDevice".into(),
                backed_up: false,
                transports: None,
                aaguid: None,
                created_at: Utc::now(),
            },
            DatabaseIdPlan::new(
                DatabaseIdGeneration::Serial,
                "passkey",
                DatabaseIdInput::Absent,
                false,
            ),
        ))
        .await
        .unwrap()
        .id
}

#[tokio::test]
async fn memory_serial_ids_are_decimal_strings_for_every_core_create() {
    let api_keys = ApiKeyConfiguration::default();
    let mut config = AuthConfig::new(SECRET).unwrap();
    config.database_id_generation = DatabaseIdGeneration::Serial;
    config.rate_limit.enabled = true;
    config.rate_limit.storage = RateLimitStorageMode::Database;
    config
        .add_plugin(ApiKeyPlugin::new(api_keys.clone()))
        .unwrap();
    let store = Arc::new(MemoryStore::default());
    let service = AuthService::new(store.clone(), config);

    let user = service
        .provision_password_user(NewPasswordUser {
            username: "serial_user".into(),
            name: "Serial User".into(),
            email: Some("serial@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let account = store.list_user_accounts(&user.id).await.unwrap().remove(0);
    let signed_in = service
        .sign_in_username(
            "serial_user",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    service
        .create_verification_value(VerificationValue::new(
            "serial:verification",
            "value",
            Utc::now() + Duration::minutes(5),
        ))
        .await
        .unwrap();
    let verification = service
        .find_verification_value("serial:verification")
        .await
        .unwrap()
        .unwrap();
    let api_key = service
        .issue_api_key(&signed_in.session, &api_keys, api_key_input())
        .await
        .unwrap();
    let passkey_id = save_serial_passkey(&store, &user.id).await;
    service
        .consume_rate_limit_request(
            &RateLimitRequest {
                method: "GET".into(),
                path: "/serial-id-contract".into(),
                query: None,
                headers: BTreeMap::new(),
            },
            Some("192.0.2.101"),
        )
        .await
        .unwrap()
        .unwrap();

    for id in [
        user.id,
        account.id,
        signed_in.session.session.id,
        verification.id,
        api_key.api_key.id,
        passkey_id,
    ] {
        assert_eq!(id, "1");
        assert!(id.bytes().all(|byte| byte.is_ascii_digit()));
    }
}
