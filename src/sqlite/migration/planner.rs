use super::{
    PlannedStatement, SqliteMigrationError, SqliteMigrationMode, SqliteMigrationPlan,
    SqliteMigrationStep, catalog, ddl,
};
use crate::{ResolvedAdapterSchema, ResolvedDatabaseIndex, sqlite::schema::SqliteSchema};
use sqlx::SqlitePool;

pub(in crate::sqlite) async fn plan(
    pool: &SqlitePool,
    resolved: &ResolvedAdapterSchema,
    physical: &SqliteSchema,
    mode: SqliteMigrationMode,
) -> Result<SqliteMigrationPlan, SqliteMigrationError> {
    let live = catalog::Catalog::load(pool).await?;
    let mut planner = Planner {
        resolved,
        physical,
        live,
        mode,
        plan: SqliteMigrationPlan::default(),
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
    physical: &'a SqliteSchema,
    live: catalog::Catalog,
    mode: SqliteMigrationMode,
    plan: SqliteMigrationPlan,
    deferred: Vec<PlannedStatement>,
}

impl Planner<'_> {
    async fn add_missing_columns(&mut self, pool: &SqlitePool) -> Result<(), SqliteMigrationError> {
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
                    step: SqliteMigrationStep::AddColumn {
                        table: model.table.clone(),
                        column: column.clone(),
                    },
                    sql: format!(
                        "alter table {} add column {}",
                        model.quoted_table,
                        ddl::column_definition(resolved, column, &definition.field, false, true,)?
                    ),
                });
                defer_field_index(resolved, deferred, model, column, definition);
            }
        }
        Ok(())
    }

    fn add_missing_tables(&mut self) -> Result<(), SqliteMigrationError> {
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
                step: SqliteMigrationStep::CreateTable {
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

    fn add_table_indexes(&mut self) -> Result<(), SqliteMigrationError> {
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
                match live.index(&index.name) {
                    Some(existing) if index_matches(existing, &model.table, index) => {}
                    Some(existing) if existing.table == model.table => {
                        return Err(SqliteMigrationError::Conflict(index_conflict(
                            &index.name,
                            &model.table,
                        )));
                    }
                    Some(existing) => {
                        return Err(SqliteMigrationError::Conflict(index_owner_conflict(
                            &index.name,
                            &existing.table,
                        )));
                    }
                    None => deferred.push(index_statement(&model.table, index)),
                }
            }
        }
        Ok(())
    }
}

async fn check_required_column(
    pool: &SqlitePool,
    mode: SqliteMigrationMode,
    plan: &mut SqliteMigrationPlan,
    model: &crate::sqlite::schema::PhysicalModel,
    column: &str,
    definition: &crate::sqlite::schema::PhysicalColumn,
) -> Result<(), SqliteMigrationError> {
    if !definition.field.required
        || ddl::has_usable_static_default(&definition.field)
        || !catalog::table_has_rows(pool, &model.table).await?
    {
        return Ok(());
    }
    let message = unsafe_required_column(&model.table, column, &definition.field);
    if mode == SqliteMigrationMode::Execute {
        return Err(SqliteMigrationError::Unsafe(message));
    }
    plan.unsafe_changes.push(message);
    Ok(())
}

fn defer_field_index(
    resolved: &ResolvedAdapterSchema,
    deferred: &mut Vec<PlannedStatement>,
    model: &crate::sqlite::schema::PhysicalModel,
    column: &str,
    definition: &crate::sqlite::schema::PhysicalColumn,
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
    plan: &mut SqliteMigrationPlan,
    model: &crate::sqlite::schema::PhysicalModel,
    column: &str,
    definition: &crate::sqlite::schema::PhysicalColumn,
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
        step: SqliteMigrationStep::CreateIndex {
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

fn index_owner_conflict(name: &str, table: &str) -> String {
    format!(
        "Database index name \"{name}\" is already used by table \"{table}\". Index names must be unique across the schema."
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
