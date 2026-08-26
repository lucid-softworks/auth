use super::{PhysicalModel, ddl};
use crate::{AuthError, ResolvedAdapterSchema};
use indexmap::IndexMap;
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashSet;

pub(super) async fn migrate(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAdapterSchema,
    models: &IndexMap<String, PhysicalModel>,
) -> Result<(), AuthError> {
    for model in models.values().filter(|model| !model.disable_migrations) {
        let created = ensure_table(transaction, schema, model).await?;
        let added_columns = if created {
            HashSet::new()
        } else {
            ensure_columns(transaction, schema, model).await?
        };
        ensure_indexes(transaction, schema, model, created, &added_columns).await?;
    }
    Ok(())
}

async fn ensure_table(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
) -> Result<bool, AuthError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = $1 \
         AND table_type = 'BASE TABLE')",
    )
    .bind(&model.table)
    .fetch_one(&mut **transaction)
    .await
    .map_err(storage)?;
    if exists {
        return Ok(false);
    }
    sqlx::raw_sql(&ddl::create_table(schema, model)?)
        .execute(&mut **transaction)
        .await
        .map_err(storage)?;
    Ok(true)
}

async fn ensure_columns(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
) -> Result<HashSet<String>, AuthError> {
    let existing = sqlx::query(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1",
    )
    .bind(&model.table)
    .fetch_all(&mut **transaction)
    .await
    .map_err(storage)?
    .into_iter()
    .map(|row| row.get::<String, _>("column_name"))
    .collect::<HashSet<_>>();
    let mut added = HashSet::new();
    for (column, physical) in &model.columns {
        if existing.contains(column) {
            continue;
        }
        let field = &physical.field;
        if field.required && ddl::add_column_default(field).is_none() {
            let has_rows: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS (SELECT 1 FROM {} LIMIT 1)",
                model.quoted_table
            ))
            .fetch_one(&mut **transaction)
            .await
            .map_err(storage)?;
            if has_rows {
                return Err(AuthError::InvalidConfiguration(format!(
                    "cannot add required Better Auth field '{}.{}' to a non-empty PostgreSQL table without a database default",
                    model.table, column
                )));
            }
        }
        let definition = ddl::add_column_definition(schema, column, field)?;
        sqlx::raw_sql(&format!(
            "ALTER TABLE {} ADD COLUMN {}",
            model.quoted_table, definition
        ))
        .execute(&mut **transaction)
        .await
        .map_err(storage)?;
        added.insert(column.clone());
    }
    Ok(added)
}

async fn ensure_indexes(
    transaction: &mut Transaction<'_, Postgres>,
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
    created: bool,
    added_columns: &HashSet<String>,
) -> Result<(), AuthError> {
    if let Some(indexes) = schema.field_indexes_by_table().get(&model.table) {
        for index in indexes
            .iter()
            .filter(|index| should_create_field_index(created, added_columns, index))
        {
            execute_index(transaction, model, index).await?;
        }
    }
    if let Some(indexes) = schema.indexes_by_table().get(&model.table) {
        for index in indexes {
            execute_index(transaction, model, index).await?;
        }
    }
    Ok(())
}

fn should_create_field_index(
    created: bool,
    added_columns: &HashSet<String>,
    index: &crate::ResolvedDatabaseIndex,
) -> bool {
    if created {
        return !index.unique;
    }
    index
        .columns
        .iter()
        .all(|column| added_columns.contains(column))
}

async fn execute_index(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PhysicalModel,
    index: &crate::ResolvedDatabaseIndex,
) -> Result<(), AuthError> {
    let existing = sqlx::query(
        "SELECT table_class.relname::text AS table_name, \
                index_meta.indisunique AS is_unique, \
                index_meta.indisvalid AS is_valid, \
                index_meta.indpred IS NOT NULL AS is_partial, \
                COALESCE(ARRAY_AGG(attribute.attname::text ORDER BY keys.ordinality) \
                    FILTER (WHERE keys.ordinality <= index_meta.indnkeyatts), \
                    ARRAY[]::text[]) AS columns \
         FROM pg_class index_class \
         JOIN pg_namespace namespace ON namespace.oid = index_class.relnamespace \
         JOIN pg_index index_meta ON index_meta.indexrelid = index_class.oid \
         JOIN pg_class table_class ON table_class.oid = index_meta.indrelid \
         CROSS JOIN LATERAL UNNEST(index_meta.indkey) WITH ORDINALITY \
             AS keys(attnum, ordinality) \
         LEFT JOIN pg_attribute attribute ON attribute.attrelid = table_class.oid \
             AND attribute.attnum = keys.attnum \
         WHERE namespace.nspname = current_schema() AND index_class.relname = $1 \
         GROUP BY table_class.relname, index_meta.indisunique, index_meta.indisvalid, \
                  index_meta.indpred, index_meta.indnkeyatts",
    )
    .bind(&index.name)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(storage)?;
    if let Some(existing) = existing {
        let existing_table = existing.get::<String, _>("table_name");
        let existing_unique = existing.get::<bool, _>("is_unique");
        let existing_valid = existing.get::<bool, _>("is_valid");
        let existing_partial = existing.get::<bool, _>("is_partial");
        let existing_columns = existing.get::<Vec<Option<String>>, _>("columns");
        if !index_matches(
            &existing_table,
            existing_unique,
            existing_valid,
            existing_partial,
            &existing_columns,
            &model.table,
            index,
        ) {
            return Err(AuthError::InvalidConfiguration(format!(
                "PostgreSQL index '{}' does not match the Better Auth schema (expected {} on {} ({}) with valid={}, partial={})",
                index.name,
                if index.unique {
                    "unique index"
                } else {
                    "index"
                },
                model.table,
                index.columns.join(", "),
                true,
                false,
            )));
        }
        return Ok(());
    }
    sqlx::raw_sql(&ddl::create_index(
        &model.table,
        &index.name,
        &index.columns,
        index.unique,
    ))
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(storage)
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

fn index_matches(
    existing_table: &str,
    existing_unique: bool,
    existing_valid: bool,
    existing_partial: bool,
    existing_columns: &[Option<String>],
    expected_table: &str,
    expected: &crate::ResolvedDatabaseIndex,
) -> bool {
    existing_table == expected_table
        && existing_unique == expected.unique
        && existing_valid
        && !existing_partial
        && existing_columns.len() == expected.columns.len()
        && existing_columns
            .iter()
            .zip(&expected.columns)
            .all(|(actual, expected)| actual.as_deref() == Some(expected))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected() -> crate::ResolvedDatabaseIndex {
        crate::ResolvedDatabaseIndex {
            name: "widget_owner_created_idx".into(),
            columns: vec!["owner_id".into(), "created_at".into()],
            unique: true,
        }
    }

    #[test]
    fn existing_indexes_must_match_table_columns_order_and_shape() {
        let index = expected();
        let columns = [Some("owner_id".into()), Some("created_at".into())];
        assert!(index_matches(
            "widget", true, true, false, &columns, "widget", &index
        ));
        assert!(!index_matches(
            "other", true, true, false, &columns, "widget", &index
        ));
        assert!(!index_matches(
            "widget", false, true, false, &columns, "widget", &index
        ));
        assert!(!index_matches(
            "widget", true, false, false, &columns, "widget", &index
        ));
        assert!(!index_matches(
            "widget", true, true, true, &columns, "widget", &index
        ));
        let reversed = [Some("created_at".into()), Some("owner_id".into())];
        assert!(!index_matches(
            "widget", true, true, false, &reversed, "widget", &index
        ));
        let expression = [None, Some("created_at".into())];
        assert!(!index_matches(
            "widget",
            true,
            true,
            false,
            &expression,
            "widget",
            &index
        ));
    }

    #[test]
    fn field_indexes_follow_better_auth_create_versus_alter_rules() {
        let mut index = expected();
        index.columns = vec!["owner_id".into()];
        assert!(!should_create_field_index(true, &HashSet::new(), &index));
        index.unique = false;
        assert!(should_create_field_index(true, &HashSet::new(), &index));
        assert!(!should_create_field_index(false, &HashSet::new(), &index));
        assert!(should_create_field_index(
            false,
            &HashSet::from(["owner_id".into()]),
            &index,
        ));
    }
}
