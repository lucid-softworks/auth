use super::MssqlPool;

mod catalog;
mod ddl;
mod planner;
pub(super) use planner::plan;

#[cfg(test)]
mod contract;

/// Whether unsafe required-column additions abort planning or are compiled
/// and reported for an explicit manual workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MssqlMigrationMode {
    Execute,
    Compile,
}

#[derive(Debug, thiserror::Error)]
pub enum MssqlMigrationError {
    #[error("{0}")]
    Unsafe(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Configuration(String),
    #[error("MSSQL migration failed: {0}")]
    Database(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MssqlMigrationStep {
    AddColumn { table: String, column: String },
    CreateTable { table: String },
    CreateIndex { table: String, name: String },
}

#[derive(Debug, Clone)]
pub(super) struct PlannedStatement {
    pub(super) step: MssqlMigrationStep,
    pub(super) sql: String,
}

/// Immutable additive migration plan derived from the resolved catalog and
/// current ordinary-table metadata.
#[derive(Debug, Clone, Default)]
pub struct MssqlMigrationPlan {
    pub(super) statements: Vec<PlannedStatement>,
    pub(super) warnings: Vec<String>,
    pub(super) unsafe_changes: Vec<String>,
}

impl MssqlMigrationPlan {
    pub fn steps(&self) -> impl Iterator<Item = &MssqlMigrationStep> {
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
    pub async fn run(&self, pool: &MssqlPool) -> Result<(), MssqlMigrationError> {
        let mut connection = pool
            .get()
            .await
            .map_err(|error| MssqlMigrationError::Database(error.to_string()))?;
        for statement in &self.statements {
            connection
                .simple_query(&statement.sql)
                .await
                .map_err(database)?
                .into_results()
                .await
                .map_err(database)?;
        }
        Ok(())
    }
}

pub(super) fn database(error: tiberius::error::Error) -> MssqlMigrationError {
    MssqlMigrationError::Database(error.to_string())
}
