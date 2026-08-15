use super::{PostgresStore, storage_error};
use crate::AuthError;

const MIGRATIONS: [(i64, &str, &str); 6] = [
    (
        1,
        "initial authentication schema",
        include_str!("../../migrations/0001_auth.sql"),
    ),
    (
        2,
        "WebAuthn passkeys",
        include_str!("../../migrations/0002_passkeys.sql"),
    ),
    (
        3,
        "access administration and audit",
        include_str!("../../migrations/0003_access_audit.sql"),
    ),
    (
        4,
        "user deletion cascades",
        include_str!("../../migrations/0004_user_deletion.sql"),
    ),
    (
        5,
        "durable authentication throttling",
        include_str!("../../migrations/0005_security_hardening.sql"),
    ),
    (
        6,
        "passkey recovery codes",
        include_str!("../../migrations/0006_recovery_codes.sql"),
    ),
];

impl PostgresStore {
    pub async fn migrate(&self) -> Result<(), AuthError> {
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('lucid-auth-migrations'))")
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS lucid_auth_migrations (\
               version BIGINT PRIMARY KEY, \
               description TEXT NOT NULL, \
               applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
             )",
        )
        .execute(&mut *transaction)
        .await
        .map_err(storage_error)?;

        for (version, description, sql) in MIGRATIONS {
            let applied = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM lucid_auth_migrations WHERE version = $1)",
            )
            .bind(version)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
            if applied {
                continue;
            }
            sqlx::raw_sql(sql)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
            sqlx::query("INSERT INTO lucid_auth_migrations (version, description) VALUES ($1, $2)")
                .bind(version)
                .bind(description)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        transaction.commit().await.map_err(storage_error)
    }
}
