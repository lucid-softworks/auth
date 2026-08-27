use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, SiweConfig, SiweMessageVerifier, SiweNonceGenerator,
    SiwePlugin, SiweSchema, SiweVerificationRequest, postgres::PostgresStore,
};
use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
const TABLE: &str = "postgres_siwe_wallets";

struct Nonce(AtomicU64);

#[async_trait]
impl SiweNonceGenerator for Nonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(format!(
            "postgres{:08}",
            self.0.fetch_add(1, Ordering::Relaxed)
        ))
    }
}

struct Verifier;

#[async_trait]
impl SiweMessageVerifier for Verifier {
    async fn verify(&self, _: SiweVerificationRequest) -> Result<bool, AuthError> {
        Ok(true)
    }
}

pub(super) fn register(
    config: &mut AuthConfig,
    store: &Arc<PostgresStore>,
) -> Result<(), AuthError> {
    let mut siwe = SiweConfig::new(
        "example.com",
        Arc::new(Nonce(AtomicU64::new(1))),
        Arc::new(Verifier),
    );
    siwe.email_domain_name = Some("example.com".into());
    siwe.schema = SiweSchema {
        model_name: Some(TABLE.into()),
        user_id_field_name: Some("owner_id".into()),
        address_field_name: Some("wallet".into()),
        chain_id_field_name: Some("network".into()),
        is_primary_field_name: Some("primary_wallet".into()),
        created_at_field_name: Some("added_at".into()),
    };
    config.add_plugin(SiwePlugin::new(store.clone(), siwe))
}

pub(super) async fn assert_atomic_and_persistent(
    service: &Arc<AuthService>,
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_plugin_migration_applied(pool).await?;
    let first_nonce = service.create_siwe_nonce().await?;
    let competing_nonce = service.create_siwe_nonce().await?;
    let (first, competing) = tokio::join!(
        service.verify_siwe_message(
            message(&first_nonce, 1),
            "0xpostgres-signature".into(),
            None,
            None,
            None,
            None,
        ),
        service.verify_siwe_message(
            message(&competing_nonce, 1),
            "0xpostgres-signature".into(),
            None,
            None,
            None,
            None,
        )
    );
    let first = first?;
    let competing = competing?;
    assert_eq!(competing.user_id, first.user_id);
    assert_eq!(first.wallet_address, ADDRESS);
    assert_eq!(first.chain_id, 1.0);

    let second_nonce = service.create_siwe_nonce().await?;
    let third_nonce = service.create_siwe_nonce().await?;
    let (second, third) = tokio::join!(
        service.verify_siwe_message(
            message(&second_nonce, 137),
            "0xpostgres-signature".into(),
            None,
            None,
            None,
            None,
        ),
        service.verify_siwe_message(
            message(&third_nonce, 10),
            "0xpostgres-signature".into(),
            None,
            None,
            None,
            None,
        )
    );
    let second = second?;
    let third = third?;
    assert_eq!(second.user_id, first.user_id);
    assert_eq!(third.user_id, first.user_id);

    assert_persisted_identity(pool, &first.user_id).await
}

async fn assert_persisted_identity(
    pool: &sqlx::PgPool,
    user_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM postgres_siwe_wallets \
             WHERE owner_id = $1 AND lower(wallet) = lower($2)",
        )
        .bind(user_id)
        .bind(ADDRESS)
        .fetch_one(pool)
        .await?,
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM postgres_siwe_wallets \
             WHERE owner_id = $1 AND primary_wallet = TRUE",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM \"account\" \
             WHERE \"userId\" = $1 AND \"issuer\" = 'local:siwe' \
               AND \"providerId\" = 'siwe'",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?,
        3
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM \"session\" WHERE \"userId\" = $1",)
            .bind(user_id)
            .fetch_one(pool)
            .await?,
        4
    );
    let wallet_ids = sqlx::query_scalar::<_, String>(
        "SELECT id FROM postgres_siwe_wallets WHERE owner_id = $1 ORDER BY network",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    assert_eq!(wallet_ids.len(), 3);
    assert!(
        wallet_ids
            .iter()
            .all(|id| { id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_alphanumeric()) })
    );
    assert_eq!(wallet_ids.iter().collect::<HashSet<_>>().len(), 3);
    Ok(())
}

async fn assert_plugin_migration_applied(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT to_regclass('postgres_siwe_wallets') IS NOT NULL")
            .fetch_one(pool)
            .await?
    );
    let id_types = sqlx::query_scalar::<_, String>(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema = current_schema() \
           AND table_name = 'postgres_siwe_wallets' \
           AND column_name IN ('id', 'owner_id') ORDER BY column_name",
    )
    .fetch_all(pool)
    .await?;
    assert_eq!(id_types, ["text", "text"]);
    Ok(())
}

fn message(nonce: &str, chain_id: u64) -> String {
    format!(
        "example.com wants you to sign in with your Ethereum account:\n{ADDRESS}\n\n\
         URI: https://example.com\nVersion: 1\nChain ID: {chain_id}\nNonce: {nonce}\n\
         Issued At: 2026-08-24T12:00:00Z"
    )
}
