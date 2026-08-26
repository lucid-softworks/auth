use super::database::StrategyDatabase;
use chrono::{Duration, Utc};
use lucid_auth::{AuthError, DatabaseIdGeneration, VerificationValue};

pub(super) async fn database_ids_are_hydrated_and_missing_ids_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = StrategyDatabase::start(DatabaseIdGeneration::Database, "database").await?;
    sqlx::raw_sql(
        r#"CREATE SEQUENCE "verification_id_sequence";
           ALTER TABLE "verification" ALTER COLUMN "id" SET DEFAULT
             ('database-verification-' || nextval('verification_id_sequence')::text);"#,
    )
    .execute(&database.pool)
    .await?;

    database
        .service
        .create_verification_value(VerificationValue::new(
            "database-returned",
            "value",
            Utc::now() + Duration::minutes(5),
        ))
        .await?;
    let hydrated = database
        .service
        .find_verification_value("database-returned")
        .await?
        .expect("database-returned verification");
    assert_eq!(hydrated.id, "database-verification-1");
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            r#"SELECT pg_typeof(id)::text FROM "verification" WHERE identifier = $1"#,
        )
        .bind("database-returned")
        .fetch_one(&database.pool)
        .await?,
        "text"
    );

    sqlx::raw_sql(
        r#"ALTER TABLE "verification" DROP CONSTRAINT "verification_pkey";
           ALTER TABLE "verification" ALTER COLUMN "id" DROP DEFAULT;
           ALTER TABLE "verification" ALTER COLUMN "id" DROP NOT NULL;"#,
    )
    .execute(&database.pool)
    .await?;
    let error = database
        .service
        .create_verification_value(VerificationValue::new(
            "database-missing",
            "value",
            Utc::now() + Duration::minutes(5),
        ))
        .await
        .unwrap_err();
    let AuthError::Storage(message) = error else {
        panic!("unexpected missing database ID error: {error}");
    };
    assert_eq!(
        message,
        "invalid verification row: invalid type: null, expected a string"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            r#"SELECT COUNT(*) FROM "verification" WHERE identifier = $1 AND id IS NULL"#,
        )
        .bind("database-missing")
        .fetch_one(&database.pool)
        .await?,
        1
    );
    database.close().await
}
