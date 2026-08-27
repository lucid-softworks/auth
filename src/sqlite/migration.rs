use super::schema::SqliteSchema;
use crate::ResolvedAdapterSchema;
use sqlx::SqlitePool;

mod catalog;
mod ddl;
#[cfg(test)]
mod tests;

/// Whether unsafe required-column additions abort planning or are compiled
/// and reported for an explicit manual workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteMigrationMode {
    Execute,
    Compile,
}

#[derive(Debug, thiserror::Error)]
pub enum SqliteMigrationError {
    #[error("{0}")]
    Unsafe(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Configuration(String),
    #[error("SQLite migration failed: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqliteMigrationStep {
    AddColumn { table: String, column: String },
    CreateTable { table: String },
    CreateIndex { table: String, name: String },
}

#[derive(Debug, Clone)]
struct PlannedStatement {
    step: SqliteMigrationStep,
    sql: String,
}

/// Immutable additive migration plan derived from the resolved catalog and
/// current ordinary-table metadata.
#[derive(Debug, Clone, Default)]
pub struct SqliteMigrationPlan {
    statements: Vec<PlannedStatement>,
    warnings: Vec<String>,
    unsafe_changes: Vec<String>,
}

impl SqliteMigrationPlan {
    pub fn steps(&self) -> impl Iterator<Item = &SqliteMigrationStep> {
        self.statements.iter().map(|statement| &statement.step)
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn unsafe_changes(&self) -> &[String] {
        &self.unsafe_changes
    }

    /// Matches the pinned compiler, including `;` for an empty plan.
    pub fn compiled_sql(&self) -> String {
        format!(
            "{};",
            self.statements
                .iter()
                .map(|statement| statement.sql.as_str())
                .collect::<Vec<_>>()
                .join(";\n\n")
        )
    }

    /// Executes statements sequentially without a ledger, outer transaction,
    /// retry, or `IF NOT EXISTS` race recovery.
    pub async fn run(&self, pool: &SqlitePool) -> Result<(), SqliteMigrationError> {
        for statement in &self.statements {
            sqlx::query(&statement.sql).execute(pool).await?;
        }
        Ok(())
    }
}

pub(super) async fn plan(
    pool: &SqlitePool,
    resolved: &ResolvedAdapterSchema,
    physical: &SqliteSchema,
    mode: SqliteMigrationMode,
) -> Result<SqliteMigrationPlan, SqliteMigrationError> {
    let live = catalog::Catalog::load(pool).await?;
    let mut plan = SqliteMigrationPlan::default();
    let mut deferred = Vec::<PlannedStatement>::new();

    for model in physical.models().filter(|model| !model.disable_migrations) {
        let Some(table) = live.table(&model.table) else {
            continue;
        };
        for (column, definition) in &model.columns {
            if let Some(existing) = table.column(column) {
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
                continue;
            }
            if definition.field.required
                && !ddl::has_usable_static_default(&definition.field)
                && catalog::table_has_rows(pool, &model.table).await?
            {
                let message = unsafe_required_column(&model.table, column, &definition.field);
                if mode == SqliteMigrationMode::Execute {
                    return Err(SqliteMigrationError::Unsafe(message));
                }
                plan.unsafe_changes.push(message);
            }
            plan.statements.push(PlannedStatement {
                step: SqliteMigrationStep::AddColumn {
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
                    .and_then(|indexes| {
                        indexes
                            .iter()
                            .find(|index| index.columns.len() == 1 && index.columns[0] == *column)
                    })
                    .expect("resolved field index exists");
                deferred.push(index_statement(&model.table, index));
            }
        }
    }

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
                    return Err(SqliteMigrationError::Conflict(format!(
                        "Database index \"{}\" on table \"{}\" does not match the configured fields and uniqueness. Rename or replace the existing index, then run the migration again.",
                        index.name, model.table
                    )));
                }
                Some(existing) => {
                    return Err(SqliteMigrationError::Conflict(format!(
                        "Database index name \"{}\" is already used by table \"{}\". Index names must be unique across the schema.",
                        index.name, existing.table
                    )));
                }
                None => deferred.push(index_statement(&model.table, index)),
            }
        }
    }

    plan.statements.extend(deferred);
    Ok(plan)
}

fn index_statement(table: &str, index: &crate::ResolvedDatabaseIndex) -> PlannedStatement {
    PlannedStatement {
        step: SqliteMigrationStep::CreateIndex {
            table: table.into(),
            name: index.name.clone(),
        },
        sql: ddl::create_index(table, &index.name, &index.columns, index.unique),
    }
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
