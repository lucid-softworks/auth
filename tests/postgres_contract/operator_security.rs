use lucid_auth::{AuthService, AuthStore, OperatorSecurityStore, postgres::PostgresStore};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

pub async fn assert_table_absent(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    for table in [
        "lucid_auth_operator_temporary_passwords",
        "lucid_auth_legacy_temporary_passwords",
    ] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
                .bind(table)
                .fetch_one(pool)
                .await?
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'lucid_auth_users' \
               AND column_name = 'must_change_password'",
        )
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}

pub async fn insert_legacy_shape(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        "CREATE TABLE lucid_auth_legacy_temporary_passwords (\
           user_id UUID PRIMARY KEY REFERENCES lucid_auth_users(id) ON DELETE CASCADE,\
           created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
         )",
    )
    .execute(pool)
    .await?;
    sqlx::query("INSERT INTO lucid_auth_legacy_temporary_passwords (user_id) VALUES ($1)")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn assert_legacy_migrated(
    service: &AuthService,
    pool: &PgPool,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        service
            .operator_security()
            .unwrap()
            .status(user_id)
            .await?
            .temporary_password
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT to_regclass('lucid_auth_legacy_temporary_passwords') IS NOT NULL",
        )
        .fetch_one(pool)
        .await?
    );
    Ok(())
}

pub async fn assert_atomic(
    service: &AuthService,
    store: &PostgresStore,
    signed_in: &lucid_auth::SignInResult,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    service
        .operator_security()
        .unwrap()
        .local_recover_sole_owner("owner", "operator recovered password".into())
        .await?;
    assert!(service.session(&signed_in.token).await?.is_none());
    assert!(store.list_passkeys(user_id).await?.is_empty());
    assert!(store.is_temporary_password(user_id).await?);
    assert!(
        service
            .sign_in_username("owner", "operator recovered password".into(), None, None)
            .await
            .is_ok()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn legacy_temporary_password_column_is_extracted() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let schema = format!("lucid_auth_upgrade_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await?;
    let search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(move |connection, _metadata| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await?;
    seed_legacy_column(&pool).await?;
    sqlx::raw_sql(include_str!(
        "../../migrations/0012_extract_operator_security.sql"
    ))
    .execute(&pool)
    .await?;
    assert_legacy_column_extracted(&pool).await?;
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}

async fn seed_legacy_column(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE lucid_auth_users (\
           id UUID PRIMARY KEY,\
           must_change_password BOOLEAN NOT NULL DEFAULT FALSE\
         )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO lucid_auth_users (id, must_change_password) VALUES ($1, TRUE), ($2, FALSE)",
    )
    .bind(Uuid::nil())
    .bind(Uuid::max())
    .execute(pool)
    .await?;
    Ok(())
}

async fn assert_legacy_column_extracted(pool: &PgPool) -> Result<(), sqlx::Error> {
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM lucid_auth_legacy_temporary_passwords")
            .fetch_one(pool)
            .await?,
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, Uuid>("SELECT user_id FROM lucid_auth_legacy_temporary_passwords")
            .fetch_one(pool)
            .await?,
        Uuid::nil()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'lucid_auth_users' \
               AND column_name = 'must_change_password'",
        )
        .fetch_one(pool)
        .await?,
        0
    );
    Ok(())
}
