use sqlx::Row;

pub(super) async fn assert_exact_schema(
    pool: &sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(tables(pool).await?, expected_tables());
    assert_eq!(columns(pool).await?, expected_columns());
    assert_eq!(indexes(pool).await?, expected_indexes());
    assert_eq!(references(pool).await?, expected_references());
    assert_legacy_aliases_absent(pool).await?;
    Ok(())
}

async fn tables(pool: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_type = 'BASE TABLE' \
         ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
}

async fn columns(pool: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema = current_schema() ORDER BY table_name, ordinal_position",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| format!("{}|{}", row.get::<String, _>(0), row.get::<String, _>(1)))
        .collect())
}

async fn indexes(pool: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT table_class.relname, index_class.relname, index_meta.indisunique, \
                ARRAY_AGG(attribute.attname::text ORDER BY keys.ordinality) \
         FROM pg_class index_class \
         JOIN pg_namespace namespace ON namespace.oid = index_class.relnamespace \
         JOIN pg_index index_meta ON index_meta.indexrelid = index_class.oid \
         JOIN pg_class table_class ON table_class.oid = index_meta.indrelid \
         CROSS JOIN LATERAL UNNEST(index_meta.indkey) WITH ORDINALITY keys(attnum, ordinality) \
         JOIN pg_attribute attribute ON attribute.attrelid = table_class.oid \
              AND attribute.attnum = keys.attnum \
         WHERE namespace.nspname = current_schema() \
         GROUP BY table_class.relname, index_class.relname, index_meta.indisunique \
         ORDER BY table_class.relname, index_class.relname",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let columns = row.get::<Vec<String>, _>(3).join(",");
            format!(
                "{}|{}|{}|{columns}",
                row.get::<String, _>(0),
                row.get::<String, _>(1),
                row.get::<bool, _>(2)
            )
        })
        .collect())
}

async fn references(pool: &sqlx::PgPool) -> Result<Vec<String>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT source.relname, source_column.attname, target.relname, target_column.attname, \
                fk_constraint.confdeltype::text \
         FROM pg_constraint fk_constraint \
         JOIN pg_class source ON source.oid = fk_constraint.conrelid \
         JOIN pg_class target ON target.oid = fk_constraint.confrelid \
         JOIN pg_namespace namespace ON namespace.oid = source.relnamespace \
         JOIN pg_attribute source_column ON source_column.attrelid = source.oid \
              AND source_column.attnum = fk_constraint.conkey[1] \
         JOIN pg_attribute target_column ON target_column.attrelid = target.oid \
              AND target_column.attnum = fk_constraint.confkey[1] \
         WHERE namespace.nspname = current_schema() AND fk_constraint.contype = 'f' \
         ORDER BY source.relname, source_column.attname",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .iter()
        .map(|row| {
            format!(
                "{}|{}|{}|{}|{}",
                row.get::<String, _>(0),
                row.get::<String, _>(1),
                row.get::<String, _>(2),
                row.get::<String, _>(3),
                row.get::<String, _>(4)
            )
        })
        .collect())
}

async fn assert_legacy_aliases_absent(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    for alias in [
        "lucid_auth_users",
        "lucid_auth_sessions",
        "lucid_auth_accounts",
        "lucid_auth_verification_values",
        "lucid_auth_rate_limits",
    ] {
        let found = sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass($1)::text")
            .bind(alias)
            .fetch_one(pool)
            .await?;
        assert_eq!(found, None, "legacy table alias {alias} must not exist");
    }
    Ok(())
}

fn expected_tables() -> Vec<String> {
    [
        "auth accounts",
        "auth sessions",
        "auth users",
        "auth verifications",
        "request buckets",
    ]
    .map(str::to_owned)
    .into()
}

fn expected_columns() -> Vec<String> {
    [
        (
            "auth accounts",
            [
                "id",
                "issuer url",
                "remote id",
                "provider name",
                "owner id",
                "access secret",
                "refresh secret",
                "identity token",
                "access expires",
                "refresh expires",
                "granted scopes",
                "password digest",
                "created at",
                "updated at",
            ]
            .as_slice(),
        ),
        (
            "auth sessions",
            [
                "id",
                "expires at",
                "session token",
                "created at",
                "updated at",
                "client ip",
                "select",
                "owner id",
            ]
            .as_slice(),
        ),
        (
            "auth users",
            [
                "id",
                "display name",
                "login email",
                "verified flag",
                "avatar url",
                "created at",
                "updated at",
            ]
            .as_slice(),
        ),
        (
            "auth verifications",
            [
                "id",
                "lookup key",
                "secret value",
                "expires at",
                "created at",
                "updated at",
            ]
            .as_slice(),
        ),
        (
            "request buckets",
            ["id", "limit key", "hit count", "last request ms"].as_slice(),
        ),
    ]
    .into_iter()
    .flat_map(|(table, columns)| {
        columns
            .iter()
            .map(move |column| format!("{table}|{column}"))
    })
    .collect()
}

fn expected_indexes() -> Vec<String> {
    [
        "auth accounts|auth accounts_issuer url_remote id_uidx|true|issuer url,remote id",
        "auth accounts|auth accounts_owner id_idx|false|owner id",
        "auth accounts|auth accounts_pkey|true|id",
        "auth sessions|auth sessions_owner id_idx|false|owner id",
        "auth sessions|auth sessions_pkey|true|id",
        "auth sessions|auth sessions_session token_key|true|session token",
        "auth users|auth users_login email_key|true|login email",
        "auth users|auth users_pkey|true|id",
        "auth verifications|auth verifications_lookup key_idx|false|lookup key",
        "auth verifications|auth verifications_pkey|true|id",
        "request buckets|request buckets_limit key_key|true|limit key",
        "request buckets|request buckets_pkey|true|id",
    ]
    .map(str::to_owned)
    .into()
}

fn expected_references() -> Vec<String> {
    [
        "auth accounts|owner id|auth users|id|c",
        "auth sessions|owner id|auth users|id|c",
    ]
    .map(str::to_owned)
    .into()
}
