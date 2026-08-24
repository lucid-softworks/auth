use super::{PostgresStore, schema::migration_checksum, storage_error};
use crate::AuthError;
use std::collections::BTreeSet;

/// One checked-in core PostgreSQL migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreMigration {
    pub version: i64,
    pub description: &'static str,
    pub sql: &'static str,
}

const MIGRATIONS: &[CoreMigration] = &[
    CoreMigration {
        version: 1,
        description: "initial authentication schema",
        sql: include_str!("../../migrations/0001_auth.sql"),
    },
    CoreMigration {
        version: 2,
        description: "legacy WebAuthn passkey storage",
        sql: include_str!("../../migrations/0002_passkeys.sql"),
    },
    CoreMigration {
        version: 4,
        description: "user deletion cascades",
        sql: include_str!("../../migrations/0004_user_deletion.sql"),
    },
    CoreMigration {
        version: 5,
        description: "durable authentication throttling",
        sql: include_str!("../../migrations/0005_security_hardening.sql"),
    },
    CoreMigration {
        version: 9,
        description: "durable one-time verification values",
        sql: include_str!("../../migrations/0009_verification_values.sql"),
    },
    CoreMigration {
        version: 10,
        description: "core email and password accounts",
        sql: include_str!("../../migrations/0010_email_password.sql"),
    },
    CoreMigration {
        version: 11,
        description: "extract custom step-up assurance",
        sql: include_str!("../../migrations/0011_extract_step_up_policy.sql"),
    },
    CoreMigration {
        version: 12,
        description: "extract custom operator security policy",
        sql: include_str!("../../migrations/0012_extract_operator_security.sql"),
    },
    CoreMigration {
        version: 13,
        description: "Better Auth additional user fields",
        sql: include_str!("../../migrations/0013_admin_additional_fields.sql"),
    },
    CoreMigration {
        version: 14,
        description: "Better Auth additional session fields",
        sql: include_str!("../../migrations/0014_session_additional_fields.sql"),
    },
    CoreMigration {
        version: 15,
        description: "Better Auth issuer-qualified OAuth accounts",
        sql: include_str!("../../migrations/0015_oauth_accounts.sql"),
    },
    CoreMigration {
        version: 16,
        description: "Better Auth request rate limits",
        sql: include_str!("../../migrations/0016_better_auth_rate_limits.sql"),
    },
    CoreMigration {
        version: 17,
        description: "Better Auth account and verification additional fields",
        sql: include_str!("../../migrations/0017_database_additional_fields.sql"),
    },
    CoreMigration {
        version: 18,
        description: "migration schema diagnostics",
        sql: include_str!("../../migrations/0018_migration_diagnostics.sql"),
    },
];

pub fn core_migrations() -> &'static [CoreMigration] {
    MIGRATIONS
}

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

        for migration in MIGRATIONS {
            let applied = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM lucid_auth_migrations WHERE version = $1)",
            )
            .bind(migration.version)
            .fetch_one(&mut *transaction)
            .await
            .map_err(storage_error)?;
            if applied {
                continue;
            }
            sqlx::raw_sql(migration.sql)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
            sqlx::query("INSERT INTO lucid_auth_migrations (version, description) VALUES ($1, $2)")
                .bind(migration.version)
                .bind(migration.description)
                .execute(&mut *transaction)
                .await
                .map_err(storage_error)?;
        }
        validate_and_backfill(&mut transaction).await?;
        transaction.commit().await.map_err(storage_error)
    }
}

async fn validate_and_backfill(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), AuthError> {
    let known = MIGRATIONS
        .iter()
        .map(|migration| migration.version)
        .collect::<BTreeSet<_>>();
    let applied = sqlx::query_as::<_, (i64, String, Option<String>)>(
        "SELECT version, description, checksum FROM lucid_auth_migrations ORDER BY version",
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage_error)?;
    for (version, description, checksum) in applied {
        let Some(migration) = MIGRATIONS
            .iter()
            .find(|migration| migration.version == version)
        else {
            return Err(invalid_migration(format!(
                "database contains unknown core migration version {version}"
            )));
        };
        if description != migration.description {
            return Err(invalid_migration(format!(
                "core migration {version} description does not match this binary"
            )));
        }
        let expected = migration_checksum(migration.sql);
        match checksum {
            Some(actual) if actual != expected => {
                return Err(invalid_migration(format!(
                    "core migration {version} checksum does not match this binary"
                )));
            }
            None => {
                sqlx::query("UPDATE lucid_auth_migrations SET checksum = $2 WHERE version = $1")
                    .bind(version)
                    .bind(expected)
                    .execute(&mut **transaction)
                    .await
                    .map_err(storage_error)?;
            }
            Some(_) => {}
        }
    }
    debug_assert_eq!(known.len(), MIGRATIONS.len());
    Ok(())
}

fn invalid_migration(message: String) -> AuthError {
    AuthError::InvalidConfiguration(message)
}
