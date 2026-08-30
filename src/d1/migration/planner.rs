use super::{
    D1MigrationError, D1MigrationMode, D1MigrationPlan, D1MigrationStep, PlannedStatement, catalog,
    ddl,
};
use crate::{
    AdditionalField, AdditionalFieldType, ResolvedAdapterSchema,
    d1::{D1Database, schema::D1Schema},
};

pub async fn plan(
    database: &dyn D1Database,
    resolved: &ResolvedAdapterSchema,
    physical: &D1Schema,
    mode: D1MigrationMode,
) -> Result<D1MigrationPlan, D1MigrationError> {
    let live = catalog::Catalog::load(database).await?;
    let mut plan = D1MigrationPlan::default();
    let mut deferred = Vec::new();
    add_columns(
        database,
        resolved,
        physical,
        &live,
        mode,
        &mut plan,
        &mut deferred,
    )
    .await?;
    add_tables(resolved, physical, &live, &mut plan, &mut deferred)?;
    add_indexes(resolved, physical, &live, &mut deferred)?;
    plan.statements.extend(deferred);
    Ok(plan)
}

async fn add_columns(
    database: &dyn D1Database,
    resolved: &ResolvedAdapterSchema,
    physical: &D1Schema,
    live: &catalog::Catalog,
    mode: D1MigrationMode,
    plan: &mut D1MigrationPlan,
    deferred: &mut Vec<PlannedStatement>,
) -> Result<(), D1MigrationError> {
    for model in physical.models().filter(|model| !model.disable_migrations) {
        let Some(table) = live.table(&model.table) else {
            continue;
        };
        for (column, definition) in &model.columns {
            if let Some(existing) = table.column(column) {
                let _auto_incrementing = existing.auto_incrementing;
                if definition.field.required && existing.nullable {
                    plan.warnings.push(format!("Column \"{column}\" on table \"{}\" stays nullable while the schema declares the field required, so existing rows can still hold null. Backfill every row for this column and enforce NOT NULL to remove the drift.", model.table));
                }
                if !ddl::type_matches(&existing.data_type, definition.field.field_type) {
                    plan.warnings.push(format!("Field {column} in table {} has a different type in the database. Expected {} but got {}.", model.table, ddl::field_type_name(definition.field.field_type), existing.data_type));
                }
                continue;
            }
            if definition.field.required
                && !ddl::has_usable_static_default(&definition.field)
                && catalog::table_has_rows(database, &model.table).await?
            {
                let message = unsafe_required_column(&model.table, column, &definition.field);
                if mode == D1MigrationMode::Execute {
                    return Err(D1MigrationError::Unsafe(message));
                }
                plan.unsafe_changes.push(message);
            }
            plan.statements.push(PlannedStatement {
                step: D1MigrationStep::AddColumn {
                    table: model.table.clone(),
                    column: column.clone(),
                },
                sql: format!(
                    "alter table {} add column {}",
                    model.quoted_table,
                    ddl::column_definition(resolved, column, &definition.field, false, true)?
                ),
            });
            if definition.field.index || definition.field.unique {
                let index = resolved
                    .field_indexes_by_table()
                    .get(&model.table)
                    .and_then(|items| {
                        items
                            .iter()
                            .find(|item| item.columns.len() == 1 && item.columns[0] == *column)
                    })
                    .expect("resolved field index exists");
                deferred.push(index_statement(&model.table, index));
            }
        }
    }
    Ok(())
}

fn add_tables(
    resolved: &ResolvedAdapterSchema,
    physical: &D1Schema,
    live: &catalog::Catalog,
    plan: &mut D1MigrationPlan,
    deferred: &mut Vec<PlannedStatement>,
) -> Result<(), D1MigrationError> {
    for model in physical.models().filter(|model| !model.disable_migrations) {
        if live.table(&model.table).is_some() {
            continue;
        }
        plan.statements.push(PlannedStatement {
            step: D1MigrationStep::CreateTable {
                table: model.table.clone(),
            },
            sql: ddl::create_table(resolved, model)?,
        });
        if let Some(indexes) = resolved.field_indexes_by_table().get(&model.table) {
            deferred.extend(
                indexes
                    .iter()
                    .filter(|index| !index.unique)
                    .map(|index| index_statement(&model.table, index)),
            );
        }
    }
    Ok(())
}

fn add_indexes(
    resolved: &ResolvedAdapterSchema,
    physical: &D1Schema,
    live: &catalog::Catalog,
    deferred: &mut Vec<PlannedStatement>,
) -> Result<(), D1MigrationError> {
    for model in physical.models().filter(|model| !model.disable_migrations) {
        for index in resolved
            .indexes_by_table()
            .get(&model.table)
            .into_iter()
            .flatten()
        {
            match live.index(&index.name) {
                Some(existing)
                    if existing.table == model.table
                        && existing.unique == index.unique
                        && existing.valid_full_columns
                        && existing.columns == index.columns => {}
                Some(existing) if existing.table == model.table => {
                    return Err(D1MigrationError::Conflict(format!(
                        "Database index \"{}\" on table \"{}\" does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again.",
                        index.name, model.table
                    )));
                }
                Some(existing) => {
                    return Err(D1MigrationError::Conflict(format!(
                        "Database index name \"{}\" is already used by table \"{}\". Index names must be unique across the schema.",
                        index.name, existing.table
                    )));
                }
                None => deferred.push(index_statement(&model.table, index)),
            }
        }
    }
    Ok(())
}

fn index_statement(table: &str, index: &crate::ResolvedDatabaseIndex) -> PlannedStatement {
    PlannedStatement {
        step: D1MigrationStep::CreateIndex {
            table: table.into(),
            name: index.name.clone(),
        },
        sql: ddl::create_index(table, &index.name, &index.columns, index.unique),
    }
}

fn unsafe_required_column(table: &str, column: &str, field: &AdditionalField) -> String {
    let detail = if field.field_type == AdditionalFieldType::String {
        " For a text column, every existing row ends up with the same empty string."
    } else {
        ""
    };
    format!(
        "Cannot add required column \"{column}\" to populated D1 table \"{table}\": the schema declares no default value, so existing rows have no value to backfill.{detail} Add the column as nullable, backfill a correct value for every row, then make it NOT NULL."
    )
}
