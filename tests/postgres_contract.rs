use lucid_auth::{AuthConfig, AuthService, NewPasswordUser, postgres::PostgresStore};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a PostgreSQL server in DATABASE_URL"]
async fn migrations_and_authentication_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")?;
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await?;
    let schema = format!("lucid_auth_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await?;

    let search_path = format!("SET search_path TO {schema}");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |connection, _metadata| {
            let search_path = search_path.clone();
            Box::pin(async move {
                sqlx::query(&search_path).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&database_url)
        .await?;

    let store = PostgresStore::new(pool.clone());
    store.migrate().await?;
    store.migrate().await?;

    let service = AuthService::new(Arc::new(store), AuthConfig::new([42_u8; 32])?);
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "owner".into(),
            name: "Example Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await?;
    let signed_in = service
        .sign_in_username(
            "owner",
            "correct horse battery staple".into(),
            Some("127.0.0.1".into()),
            Some("lucid-auth integration test".into()),
        )
        .await?;

    assert_eq!(signed_in.session.user, user);
    assert_eq!(signed_in.session.principal().subject_id, user.id);
    assert!(service.session(&signed_in.token).await?.is_some());

    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await?;
    admin.close().await;
    Ok(())
}
