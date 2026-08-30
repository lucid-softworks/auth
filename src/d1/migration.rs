mod catalog;
mod ddl;
mod planner;

use super::{D1Database, D1Statement, D1TransportError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum D1MigrationMode {
    Execute,
    Compile,
}

#[derive(Debug, thiserror::Error)]
pub enum D1MigrationError {
    #[error("{0}")]
    Unsafe(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Configuration(String),
    #[error("D1 migration failed: {0}")]
    Transport(#[from] D1TransportError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum D1MigrationStep {
    AddColumn { table: String, column: String },
    CreateTable { table: String },
    CreateIndex { table: String, name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PlannedStatement {
    pub step: D1MigrationStep,
    pub sql: String,
}

#[derive(Debug, Clone, Default)]
pub struct D1MigrationPlan {
    pub(super) statements: Vec<PlannedStatement>,
    pub(super) warnings: Vec<String>,
    pub(super) unsafe_changes: Vec<String>,
}

impl D1MigrationPlan {
    pub fn steps(&self) -> impl Iterator<Item = &D1MigrationStep> {
        self.statements.iter().map(|statement| &statement.step)
    }
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }
    pub fn unsafe_changes(&self) -> &[String] {
        &self.unsafe_changes
    }
    pub fn compiled_sql(&self) -> String {
        format!(
            "{};",
            self.statements
                .iter()
                .map(|item| item.sql.as_str())
                .collect::<Vec<_>>()
                .join(";\n\n")
        )
    }

    /// Executes one prepared statement at a time. D1 has no plan-wide transaction.
    pub async fn run(&self, database: &dyn D1Database) -> Result<(), D1MigrationError> {
        for statement in &self.statements {
            database
                .all(D1Statement::new(&statement.sql, vec![]))
                .await?;
        }
        Ok(())
    }
}

pub(super) use planner::plan;
