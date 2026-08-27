use super::{callback::CallbackLedger, database::StrategyDatabase};
use chrono::Utc;
use lucid_auth::{
    AuthError, AuthStore, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    SiweSchema, SiweStore, StoredPasskey,
};

const WALLET_ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

pub(super) struct PluginIds {
    pub(super) passkey_id: String,
    pub(super) wallet_id: String,
    pub(super) wallet_user_id: String,
}

pub(super) async fn exercise(
    database: &StrategyDatabase,
    label: &str,
    user_id: &str,
) -> Result<PluginIds, Box<dyn std::error::Error>> {
    let passkey = database
        .store
        .save_passkey(passkey_create(
            &database.strategy,
            user_id,
            &format!("strategy-{label}-credential"),
        ))
        .await?;
    let wallet = verify_siwe_wallet(database, 1).await?;
    Ok(PluginIds {
        passkey_id: passkey.id,
        wallet_id: wallet.wallet.id,
        wallet_user_id: wallet.user.id,
    })
}

pub(super) async fn assert_round_trip(
    database: &StrategyDatabase,
    user_id: &str,
    ids: &PluginIds,
    physical_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let passkey = database
        .store
        .find_passkey_by_id(&ids.passkey_id)
        .await?
        .expect("strategy passkey");
    assert_eq!(passkey.id, ids.passkey_id);
    assert_eq!(passkey.user_id, user_id);
    let wallet = database
        .store
        .find_wallet_owner(&SiweSchema::default(), WALLET_ADDRESS, Some(1.0))
        .await?
        .expect("strategy wallet");
    assert_eq!(wallet.wallet.id, ids.wallet_id);
    assert_eq!(wallet.wallet.user_id, ids.wallet_user_id);
    assert_eq!(wallet.user.id, ids.wallet_user_id);
    assert_physical_types(database, user_id, ids, physical_type).await
}

async fn assert_physical_types(
    database: &StrategyDatabase,
    user_id: &str,
    ids: &PluginIds,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let types = sqlx::query_as::<_, (String, String, String, String)>(
        r#"SELECT pg_typeof(p.id)::text, pg_typeof(p."userId")::text,
                  pg_typeof(w.id)::text, pg_typeof(w."userId")::text
             FROM "passkey" p CROSS JOIN "walletAddress" w
            WHERE p."userId"::text = $1 AND p.id::text = $2 AND w.id::text = $3"#,
    )
    .bind(user_id)
    .bind(&ids.passkey_id)
    .bind(&ids.wallet_id)
    .fetch_one(&database.pool)
    .await?;
    let expected = expected.to_owned();
    assert_eq!(
        types,
        (
            expected.clone(),
            expected.clone(),
            expected.clone(),
            expected
        )
    );
    Ok(())
}

pub(super) async fn assert_lazy_conflicts(
    database: &StrategyDatabase,
    ledger: &CallbackLedger,
    user_id: &str,
    ids: &PluginIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let before = ledger.snapshot();
    let error = database
        .store
        .save_passkey(passkey_create(
            &database.strategy,
            user_id,
            "strategy-callback-credential",
        ))
        .await
        .unwrap_err();
    assert!(matches!(error, AuthError::CredentialAlreadyRegistered));
    assert_eq!(ledger.snapshot(), before);

    let model_counts =
        ["user", "walletAddress", "account"].map(|model| (model, ledger.count_model(model)));
    let session_count = ledger.count_model("session");
    let wallet = verify_siwe_wallet(database, 1).await?;
    assert_eq!(wallet.wallet.id, ids.wallet_id);
    for (model, count) in model_counts {
        assert_eq!(ledger.count_model(model), count);
    }
    assert_eq!(ledger.count_model("session"), session_count + 1);
    Ok(())
}

pub(super) async fn assert_database_round_trip(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(r#"ALTER TABLE "passkey" ALTER COLUMN id SET DEFAULT 'database-passkey-id'"#)
        .execute(&database.pool)
        .await?;
    let passkey = database
        .store
        .save_passkey(passkey_create(
            &DatabaseIdGeneration::Database,
            "database-user",
            "database-passkey-credential",
        ))
        .await?;
    assert_eq!(passkey.id, "database-passkey-id");
    assert_eq!(passkey.user_id, "database-user");

    configure_database_siwe_defaults(database).await?;
    let wallet = verify_siwe_wallet(database, 1).await?;
    assert_eq!(wallet.user.id, "database-siwe-user-1");
    assert_eq!(wallet.wallet.id, "database-wallet-1");
    assert_eq!(wallet.wallet.user_id, wallet.user.id);
    assert_database_physical_types(database).await
}

async fn configure_database_siwe_defaults(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::raw_sql(
        r#"CREATE SEQUENCE database_siwe_user_id;
           CREATE SEQUENCE database_siwe_account_id;
           CREATE SEQUENCE database_siwe_session_id;
           CREATE SEQUENCE database_siwe_wallet_id;
           ALTER TABLE "user" ALTER COLUMN id SET DEFAULT
             ('database-siwe-user-' || nextval('database_siwe_user_id')::text);
           ALTER TABLE "account" ALTER COLUMN id SET DEFAULT
             ('database-siwe-account-' || nextval('database_siwe_account_id')::text);
           ALTER TABLE "session" ALTER COLUMN id SET DEFAULT
             ('database-siwe-session-' || nextval('database_siwe_session_id')::text);
           ALTER TABLE "walletAddress" ALTER COLUMN id SET DEFAULT
             ('database-wallet-' || nextval('database_siwe_wallet_id')::text);"#,
    )
    .execute(&database.pool)
    .await?;
    Ok(())
}

async fn assert_database_physical_types(
    database: &StrategyDatabase,
) -> Result<(), Box<dyn std::error::Error>> {
    let physical = sqlx::query_as::<_, (String, String, String, String)>(
        r#"SELECT pg_typeof(p.id)::text, pg_typeof(p."userId")::text,
                  pg_typeof(w.id)::text, pg_typeof(w."userId")::text
             FROM "passkey" p CROSS JOIN "walletAddress" w"#,
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(
        physical,
        ("text".into(), "text".into(), "text".into(), "text".into())
    );
    Ok(())
}

fn passkey_create(
    strategy: &DatabaseIdGeneration,
    user_id: &str,
    credential_id: &str,
) -> DatabaseCreate<StoredPasskey> {
    DatabaseCreate::new(
        StoredPasskey {
            id: String::new(),
            user_id: user_id.into(),
            name: Some("Strategy passkey".into()),
            credential_id: credential_id.into(),
            public_key: "cHVibGljLWtleQ==".into(),
            counter: 0,
            device_type: "singleDevice".into(),
            backed_up: false,
            transports: Some("internal".into()),
            aaguid: None,
            created_at: Utc::now(),
        },
        DatabaseIdPlan::new(strategy.clone(), "passkey", DatabaseIdInput::Absent, false),
    )
}

async fn verify_siwe_wallet(
    database: &StrategyDatabase,
    chain_id: u64,
) -> Result<lucid_auth::WalletAddressOwner, Box<dyn std::error::Error>> {
    let nonce = database.service.create_siwe_nonce().await?;
    database
        .service
        .verify_siwe_message(
            siwe_message(&nonce, chain_id),
            "0xstrategy-signature".into(),
            None,
            None,
            None,
            None,
        )
        .await?;
    Ok(database
        .store
        .find_wallet_owner(
            &SiweSchema::default(),
            WALLET_ADDRESS,
            Some(chain_id as f64),
        )
        .await?
        .expect("verified SIWE wallet"))
}

fn siwe_message(nonce: &str, chain_id: u64) -> String {
    format!(
        "example.com wants you to sign in with your Ethereum account:\n{WALLET_ADDRESS}\n\n\
         URI: https://example.com\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\n\
         Issued At: 2026-08-24T12:00:00Z"
    )
}
