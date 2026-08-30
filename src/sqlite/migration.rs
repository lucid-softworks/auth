use sqlx::SqlitePool;

mod catalog;
mod ddl;
mod planner;
pub(super) use planner::plan;

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
pub(super) struct PlannedStatement {
    pub(super) step: SqliteMigrationStep,
    pub(super) sql: String,
}

/// Immutable additive migration plan derived from the resolved catalog and
/// current ordinary-table metadata.
#[derive(Debug, Clone, Default)]
pub struct SqliteMigrationPlan {
    pub(super) statements: Vec<PlannedStatement>,
    pub(super) warnings: Vec<String>,
    pub(super) unsafe_changes: Vec<String>,
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
