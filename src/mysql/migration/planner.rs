use super::{
    PlannedStatement, MySqlMigrationError, MySqlMigrationMode, MySqlMigrationPlan,
    MySqlMigrationStep, catalog, ddl,
};
use crate::{ResolvedAdapterSchema, ResolvedDatabaseIndex, mysql::schema::MySqlSchema};
use sqlx::MySqlPool;

pub(in crate::mysql) async fn plan(
    pool: &MySqlPool,
    resolved: &ResolvedAdapterSchema,
    physical: &MySqlSchema,
    mode: MySqlMigrationMode,
) -> Result<MySqlMigrationPlan, MySqlMigrationError> {
    let live = catalog::Catalog::load(pool).await?;
    let mut planner = Planner {
        resolved,
        physical,
        live,
        mode,
        plan: MySqlMigrationPlan::default(),
        deferred: Vec::new(),
    };
    planner.add_missing_columns(pool).await?;
    planner.add_missing_tables()?;
    planner.add_table_indexes()?;
    planner.plan.statements.extend(planner.deferred);
    Ok(planner.plan)
}

struct Planner<'a> {
    resolved: &'a ResolvedAdapterSchema,
    physical: &'a MySqlSchema,
    live: catalog::Catalog,
    mode: MySqlMigrationMode,
    plan: MySqlMigrationPlan,
    deferred: Vec<PlannedStatement>,
}

impl Planner<'_> {
    async fn add_missing_columns(&mut self, pool: &MySqlPool) -> Result<(), MySqlMigrationError> {
        let Planner {
            resolved,
            physical,
            live,
            mode,
            plan,
            deferred,
        } = self;
        for model in physical.models().filter(|model| !model.disable_migrations) {
            let Some(table) = live.table(&model.table) else {
                continue;
            };
            for (column, definition) in &model.columns {
                if let Some(existing) = table.column(column) {
                    record_drift(plan, model, column, definition, existing);
                    continue;
                }
                check_required_column(pool, *mode, plan, model, column, definition).await?;
                plan.statements.push(PlannedStatement {
                    step: MySqlMigrationStep::AddColumn {
                        table: model.table.clone(),
                        column: column.clone(),
                    },
                    sql: format!(
                        "alter table {} add column {}",
                        model.quoted_table,
                        ddl::column_definition(
                            resolved,
                            model,
                            column,
                            &definition.field,
                            false,
                            true,
                        )?
                    ),
                });
                defer_field_index(resolved, deferred, model, column, definition);
            }
        }
        Ok(())
    }

    fn add_missing_tables(&mut self) -> Result<(), MySqlMigrationError> {
        let Planner {
            resolved,
            physical,
            live,
            plan,
            deferred,
            ..
        } = self;
        for model in physical.models().filter(|model| !model.disable_migrations) {
            if live.table(&model.table).is_some() {
                continue;
            }
            plan.statements.push(PlannedStatement {
                step: MySqlMigrationStep::CreateTable {
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

    fn add_table_indexes(&mut self) -> Result<(), MySqlMigrationError> {
        let Planner {
            resolved,
            physical,
            live,
            deferred,
            ..
        } = self;
        for model in physical.models().filter(|model| !model.disable_migrations) {
            for index in resolved
                .indexes_by_table()
                .get(&model.table)
                .into_iter()
                .flatten()
            {
                match live.index(&model.table, &index.name) {
                    Some(existing) if index_matches(existing, &model.table, index) => {}
                    Some(_) => {
                        return Err(MySqlMigrationError::Conflict(index_conflict(
                            &index.name,
                            &model.table,
                        )));
                    }
                    None => {
                        if let Some(table) = live.table(&model.table) {
                            check_existing_index_size(resolved, model, table, index)?;
                        }
                        deferred.push(index_statement(&model.table, index));
                    }
                }
            }
        }
        Ok(())
    }
}

async fn check_required_column(
    pool: &MySqlPool,
    mode: MySqlMigrationMode,
    plan: &mut MySqlMigrationPlan,
    model: &crate::mysql::schema::PhysicalModel,
    column: &str,
    definition: &crate::mysql::schema::PhysicalColumn,
) -> Result<(), MySqlMigrationError> {
    if !definition.field.required
        || ddl::has_usable_static_default(&definition.field)
        || ddl::has_usable_timestamp_default(&definition.field)
        || !catalog::table_has_rows(pool, &model.table).await?
    {
        return Ok(());
    }
    let message = unsafe_required_column(&model.table, column, &definition.field);
    if mode == MySqlMigrationMode::Execute {
        return Err(MySqlMigrationError::Unsafe(message));
    }
    plan.unsafe_changes.push(message);
    Ok(())
}

fn defer_field_index(
    resolved: &ResolvedAdapterSchema,
    deferred: &mut Vec<PlannedStatement>,
    model: &crate::mysql::schema::PhysicalModel,
    column: &str,
    definition: &crate::mysql::schema::PhysicalColumn,
) {
    if !definition.field.index && !definition.field.unique {
        return;
    }
    let index = resolved
        .field_indexes_by_table()
        .get(&model.table)
        .and_then(|indexes| {
            indexes
                .iter()
                .find(|index| index.columns.len() == 1 && index.columns[0] == column)
        })
        .expect("resolved field index exists");
    deferred.push(index_statement(&model.table, index));
}

fn record_drift(
    plan: &mut MySqlMigrationPlan,
    model: &crate::mysql::schema::PhysicalModel,
    column: &str,
    definition: &crate::mysql::schema::PhysicalColumn,
    existing: &catalog::Column,
) {
    if definition.field.required && existing.nullable {
        plan.warnings.push(format!(
            "Column \"{column}\" on table \"{}\" stays nullable while the schema declares the field required, so existing rows can still hold null. Backfill every row for this column and enforce NOT NULL to remove the drift.",
            model.table
        ));
    }
    if !ddl::type_matches(&existing.data_type, definition.field.field_type) {
        plan.warnings.push(format!(
            "Field {column} in table {} has a different type in the database. Expected {} but got {}.",
            model.table,
            ddl::field_type_name(definition.field.field_type),
            existing.data_type
        ));
    }
}

fn index_matches(existing: &catalog::Index, table: &str, expected: &ResolvedDatabaseIndex) -> bool {
    existing.table == table
        && existing.unique == expected.unique
        && existing.valid_full_columns
        && existing.columns == expected.columns
}

fn index_statement(table: &str, index: &ResolvedDatabaseIndex) -> PlannedStatement {
    PlannedStatement {
        step: MySqlMigrationStep::CreateIndex {
            table: table.into(),
            name: index.name.clone(),
        },
        sql: ddl::create_index(table, &index.name, &index.columns, index.unique),
    }
}

fn index_conflict(name: &str, table: &str) -> String {
    format!(
        "Database index \"{name}\" on table \"{table}\" does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again."
    )
}

fn check_existing_index_size(
    resolved: &ResolvedAdapterSchema,
    model: &crate::mysql::schema::PhysicalModel,
    table: &catalog::Table,
    index: &ResolvedDatabaseIndex,
) -> Result<(), MySqlMigrationError> {
    let mut bytes = 0_usize;
    for column in &index.columns {
        if is_string_column(resolved, model, column) {
            let characters = match table.column(column) {
                Some(existing) => existing.character_maximum_length.ok_or_else(|| {
                    MySqlMigrationError::Conflict(index_size_error(
                        &index.name,
                        &model.table,
                        column,
                        "has no finite discovered character bound",
                    ))
                })? as usize,
                None if column == "id" => 36,
                None => ddl::generated_string_length(resolved, model, column).ok_or_else(|| {
                    MySqlMigrationError::Conflict(index_size_error(
                        &index.name,
                        &model.table,
                        column,
                        "has no safe generated character bound",
                    ))
                })?,
            };
            bytes = bytes.saturating_add(characters.saturating_mul(4));
        } else {
            bytes = bytes.saturating_add(16);
        }
    }
    if bytes > 3_072 {
        return Err(MySqlMigrationError::Conflict(format!(
            "Cannot create MySQL index \"{}\" on table \"{}\": its calculated key size is {bytes} bytes, above the 3072-byte limit.",
            index.name, model.table
        )));
    }
    Ok(())
}

fn is_string_column(
    resolved: &ResolvedAdapterSchema,
    model: &crate::mysql::schema::PhysicalModel,
    column: &str,
) -> bool {
    if column == "id" {
        return model.id_type != crate::DatabaseIdType::Serial;
    }
    let Some(field) = model.columns.get(column).map(|column| &column.field) else {
        return false;
    };
    if let Some(reference) = &field.references
        && reference.field == "id"
    {
        return resolved
            .catalog()
            .table(&reference.model)
            .is_some_and(|table| table.id_type != crate::DatabaseIdType::Serial);
    }
    matches!(
        field.field_type,
        crate::AdditionalFieldType::String | crate::AdditionalFieldType::StringLiteral(_)
    )
}

fn index_size_error(name: &str, table: &str, column: &str, reason: &str) -> String {
    format!(
        "Cannot create MySQL index \"{name}\" on table \"{table}\": string column \"{column}\" {reason}, so the 3072-byte key limit cannot be verified."
    )
}

fn unsafe_required_column(table: &str, column: &str, field: &crate::AdditionalField) -> String {
    let text_detail = if field.field_type == crate::AdditionalFieldType::String {
        " For a text column, every existing row ends up with the same empty string."
    } else {
        ""
    };
    format!(
        "Cannot add required column \"{column}\" to populated table \"{table}\": the schema declares no default value, so existing rows have no value to backfill. MySQL accepts this statement instead of rejecting it and fills every existing row with an implicit default for the column type, reporting a successful migration over corrupted data.{text_detail} Add the column as nullable, backfill a correct value for every row, then make it NOT NULL."
    )
}
