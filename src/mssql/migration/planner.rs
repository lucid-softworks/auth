use super::{
    PlannedStatement, MssqlMigrationError, MssqlMigrationMode, MssqlMigrationPlan,
    MssqlMigrationStep, catalog, ddl,
};
use crate::{
    ResolvedAdapterSchema, ResolvedDatabaseIndex,
    mssql::{MssqlPool, schema::MssqlSchema},
};

pub(in crate::mssql) async fn plan(
    pool: &MssqlPool,
    resolved: &ResolvedAdapterSchema,
    physical: &MssqlSchema,
    mode: MssqlMigrationMode,
) -> Result<MssqlMigrationPlan, MssqlMigrationError> {
    let live = catalog::Catalog::load(pool).await?;
    let mut planner = Planner {
        resolved,
        physical,
        live,
        mode,
        plan: MssqlMigrationPlan::default(),
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
    physical: &'a MssqlSchema,
    live: catalog::Catalog,
    mode: MssqlMigrationMode,
    plan: MssqlMigrationPlan,
    deferred: Vec<PlannedStatement>,
}

impl Planner<'_> {
    async fn add_missing_columns(&mut self, pool: &MssqlPool) -> Result<(), MssqlMigrationError> {
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
                    step: MssqlMigrationStep::AddColumn {
                        table: model.table.clone(),
                        column: column.clone(),
                    },
                    sql: format!(
                        "alter table {} add {}",
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

    fn add_missing_tables(&mut self) -> Result<(), MssqlMigrationError> {
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
                step: MssqlMigrationStep::CreateTable {
                    table: model.table.clone(),
                },
                sql: ddl::create_table(resolved, model)?,
            });
            if let Some(indexes) = resolved.field_indexes_by_table().get(&model.table) {
                deferred.extend(
                    indexes
                        .iter()
                        .filter(|index| !index.unique)
                        .map(|index| index_statement(model, index)),
                );
            }
        }
        Ok(())
    }

    fn add_table_indexes(&mut self) -> Result<(), MssqlMigrationError> {
        let Planner {
            resolved,
            physical,
            live,
            deferred,
            ..
        } = self;
        for model in physical.models().filter(|model| !model.disable_migrations) {
            let table_exists = live.table(&model.table).is_some();
            let table_indexes = resolved
                .indexes_by_table()
                .get(&model.table)
                .into_iter()
                .flatten();
            let field_indexes = table_exists
                .then(|| resolved.field_indexes_by_table().get(&model.table))
                .flatten()
                .into_iter()
                .flatten();
            for index in table_indexes.chain(field_indexes) {
                let filtered = nullable_unique_column(model, index).is_some();
                match live.index(&model.table, &index.name) {
                    Some(existing)
                        if index_matches(existing, &model.table, index, filtered) => {}
                    Some(_) => {
                        return Err(MssqlMigrationError::Conflict(index_conflict(
                            &index.name,
                            &model.table,
                        )));
                    }
                    None
                        if index.unique
                            && resolved
                                .field_indexes_by_table()
                                .get(&model.table)
                                .is_some_and(|indexes| {
                                    indexes.iter().any(|field| field.name == index.name)
                                })
                            && live.has_equivalent_inline_unique(
                                &model.table,
                                &index.columns,
                            ) => {}
                    None => {
                        if let Some(table) = live.table(&model.table) {
                            check_existing_index_size(resolved, model, table, index)?;
                        }
                        deferred.push(index_statement(model, index));
                    }
                }
            }
        }
        Ok(())
    }
}

async fn check_required_column(
    pool: &MssqlPool,
    mode: MssqlMigrationMode,
    plan: &mut MssqlMigrationPlan,
    model: &crate::mssql::schema::PhysicalModel,
    column: &str,
    definition: &crate::mssql::schema::PhysicalColumn,
) -> Result<(), MssqlMigrationError> {
    if !definition.field.required
        || ddl::has_usable_static_default(&definition.field)
        || ddl::has_usable_timestamp_default(&definition.field)
        || !catalog::table_has_rows(pool, &model.table).await?
    {
        return Ok(());
    }
    let message = unsafe_required_column(&model.table, column, &definition.field);
    if mode == MssqlMigrationMode::Execute {
        return Err(MssqlMigrationError::Unsafe(message));
    }
    plan.unsafe_changes.push(message);
    Ok(())
}

fn defer_field_index(
    resolved: &ResolvedAdapterSchema,
    deferred: &mut Vec<PlannedStatement>,
    model: &crate::mssql::schema::PhysicalModel,
    column: &str,
    definition: &crate::mssql::schema::PhysicalColumn,
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
    deferred.push(index_statement(model, index));
}

fn record_drift(
    plan: &mut MssqlMigrationPlan,
    model: &crate::mssql::schema::PhysicalModel,
    column: &str,
    definition: &crate::mssql::schema::PhysicalColumn,
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

fn index_matches(
    existing: &catalog::Index,
    table: &str,
    expected: &ResolvedDatabaseIndex,
    filtered: bool,
) -> bool {
    existing.table.eq_ignore_ascii_case(table)
        && existing.unique == expected.unique
        && !existing.disabled
        && !existing.hypothetical
        && existing.filtered == filtered
        && existing.columns.len() == expected.columns.len()
        && existing
            .columns
            .iter()
            .zip(&expected.columns)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn index_statement(
    model: &crate::mssql::schema::PhysicalModel,
    index: &ResolvedDatabaseIndex,
) -> PlannedStatement {
    PlannedStatement {
        step: MssqlMigrationStep::CreateIndex {
            table: model.table.clone(),
            name: index.name.clone(),
        },
        sql: ddl::create_index(
            &model.table,
            &index.name,
            &index.columns,
            index.unique,
            nullable_unique_column(model, index),
        ),
    }
}

fn nullable_unique_column<'a>(
    model: &'a crate::mssql::schema::PhysicalModel,
    index: &'a ResolvedDatabaseIndex,
) -> Option<&'a str> {
    let column = (index.unique && index.columns.len() == 1).then(|| index.columns[0].as_str())?;
    model
        .columns
        .get(column)
        .filter(|definition| !definition.field.required)
        .map(|_| column)
}

fn index_conflict(name: &str, table: &str) -> String {
    format!(
        "Database index \"{name}\" on table \"{table}\" does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again."
    )
}

fn check_existing_index_size(
    resolved: &ResolvedAdapterSchema,
    model: &crate::mssql::schema::PhysicalModel,
    table: &catalog::Table,
    index: &ResolvedDatabaseIndex,
) -> Result<(), MssqlMigrationError> {
    let mut bytes = 0_usize;
    for column in &index.columns {
        if is_string_column(resolved, model, column) {
            let characters = match table.column(column) {
                Some(existing) => existing.character_maximum_length.ok_or_else(|| {
                    MssqlMigrationError::Conflict(index_size_error(
                        &index.name,
                        &model.table,
                        column,
                        "has no finite discovered character bound",
                    ))
                })? as usize,
                None if column == "id" => 36,
                None => ddl::generated_string_length(resolved, model, column).ok_or_else(|| {
                    MssqlMigrationError::Conflict(index_size_error(
                        &index.name,
                        &model.table,
                        column,
                        "has no safe generated character bound",
                    ))
                })?,
            };
            let multiplier = if table
                .column(column)
                .is_some_and(|existing| existing.data_type.starts_with('n'))
            {
                2
            } else {
                1
            };
            bytes = bytes.saturating_add(characters.saturating_mul(multiplier));
        } else {
            bytes = bytes.saturating_add(8);
        }
    }
    if bytes > 1_700 {
        return Err(MssqlMigrationError::Conflict(format!(
            "Cannot create MSSQL index \"{}\" on table \"{}\": its calculated key size is {bytes} bytes, above Better Auth's 1700-byte limit.",
            index.name, model.table
        )));
    }
    Ok(())
}

fn is_string_column(
    resolved: &ResolvedAdapterSchema,
    model: &crate::mssql::schema::PhysicalModel,
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
        "Cannot create MSSQL index \"{name}\" on table \"{table}\": string column \"{column}\" {reason}, so Better Auth's 1700-byte key limit cannot be verified."
    )
}

fn unsafe_required_column(table: &str, column: &str, _field: &crate::AdditionalField) -> String {
    format!(
        "Cannot add required column \"{column}\" to populated table \"{table}\": the schema declares no usable default value. Add it as nullable, backfill every row, then enforce NOT NULL."
    )
}
