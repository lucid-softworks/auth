use super::{MssqlMigrationError, database};
use crate::mssql::{MssqlPool, schema::quote, statement::MssqlStatement, value::MssqlValue};
use std::collections::HashMap;
use tiberius::Row;

pub(super) struct Catalog {
    tables: HashMap<String, Table>,
    indexes: HashMap<(String, String), Index>,
}

pub(super) struct Table {
    columns: HashMap<String, Column>,
}

pub(super) struct Column {
    pub(super) data_type: String,
    pub(super) nullable: bool,
    pub(super) character_maximum_length: Option<u64>,
}

pub(super) struct Index {
    pub(super) table: String,
    pub(super) columns: Vec<String>,
    pub(super) unique: bool,
    pub(super) disabled: bool,
    pub(super) hypothetical: bool,
    pub(super) filtered: bool,
}

impl Catalog {
    pub(super) async fn load(pool: &MssqlPool) -> Result<Self, MssqlMigrationError> {
        let mut connection = pool
            .get()
            .await
            .map_err(|error| MssqlMigrationError::Database(error.to_string()))?;
        let schema = connection
            .simple_query("select schema_name() as [schema]")
            .await
            .map_err(database)?
            .into_row()
            .await
            .map_err(database)?
            .and_then(|row| row.get::<&str, _>("schema").map(str::to_owned))
            .filter(|schema| !schema.is_empty())
            .unwrap_or_else(|| "dbo".into());

        let mut table_query = MssqlStatement::new(
            "select t.name as [table_name], c.name as [column_name], ty.name as [data_type], c.is_nullable as [is_nullable], c.max_length as [max_length] from sys.tables t join sys.schemas s on s.schema_id = t.schema_id join sys.columns c on c.object_id = t.object_id join sys.types ty on ty.user_type_id = c.user_type_id where s.name = ",
        );
        table_query
            .bind(MssqlValue::Text(Some(schema.clone())))
            .push(" order by t.name, c.column_id");
        let rows = table_query
            .query(&mut connection, false)
            .await
            .map_err(auth_error)?;
        let mut tables = HashMap::<String, Table>::new();
        for row in rows {
            let table = text(&row, "table_name")?;
            let data_type = text(&row, "data_type")?;
            let max_length = row
                .try_get::<i16, _>("max_length")
                .map_err(database)?
                .and_then(|length| {
                    (length >= 0).then_some(if data_type.starts_with('n') {
                        u64::try_from(length).ok().map(|length| length / 2)
                    } else {
                        u64::try_from(length).ok()
                    })
                })
                .flatten();
            tables
                .entry(table)
                .or_insert_with(|| Table {
                    columns: HashMap::new(),
                })
                .columns
                .insert(
                    portable(&text(&row, "column_name")?),
                    Column {
                        data_type,
                        nullable: row
                            .try_get::<bool, _>("is_nullable")
                            .map_err(database)?
                            .unwrap_or(false),
                        character_maximum_length: max_length,
                    },
                );
        }

        let mut index_query = MssqlStatement::new(
            "select t.name as [table_name], i.name as [index_name], i.is_unique as [is_unique], i.is_disabled as [is_disabled], i.is_hypothetical as [is_hypothetical], i.has_filter as [has_filter], c.name as [column_name] from sys.indexes i join sys.tables t on t.object_id = i.object_id join sys.schemas s on s.schema_id = t.schema_id join sys.index_columns ic on ic.object_id = i.object_id and ic.index_id = i.index_id join sys.columns c on c.object_id = ic.object_id and c.column_id = ic.column_id where s.name = ",
        );
        index_query
            .bind(MssqlValue::Text(Some(schema.clone())))
            .push(" and i.name is not null and ic.key_ordinal > 0 order by t.name, i.name, ic.key_ordinal");
        let mut indexes = HashMap::<(String, String), Index>::new();
        for row in index_query
            .query(&mut connection, false)
            .await
            .map_err(auth_error)?
        {
            let table = text(&row, "table_name")?;
            let name = text(&row, "index_name")?;
            let unique = bit(&row, "is_unique")?;
            let disabled = bit(&row, "is_disabled")?;
            let hypothetical = bit(&row, "is_hypothetical")?;
            let filtered = bit(&row, "has_filter")?;
            indexes
                .entry((portable(&table), portable(&name)))
                .or_insert_with(|| Index {
                    table: table.clone(),
                    columns: Vec::new(),
                    unique,
                    disabled,
                    hypothetical,
                    filtered,
                })
                .columns
                .push(text(&row, "column_name")?);
        }
        Ok(Self {
            tables: tables
                .into_iter()
                .map(|(name, table)| (portable(&name), table))
                .collect(),
            indexes,
        })
    }

    pub(super) fn table(&self, name: &str) -> Option<&Table> {
        self.tables.get(&portable(name))
    }

    pub(super) fn index(&self, table: &str, name: &str) -> Option<&Index> {
        self.indexes.get(&(portable(table), portable(name)))
    }

    pub(super) fn has_equivalent_inline_unique(
        &self,
        table: &str,
        columns: &[String],
    ) -> bool {
        self.indexes.values().any(|index| {
            index.table.eq_ignore_ascii_case(table)
                && index.unique
                && !index.disabled
                && !index.hypothetical
                && !index.filtered
                && index.columns.len() == columns.len()
                && index
                    .columns
                    .iter()
                    .zip(columns)
                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
    }
}

impl Table {
    pub(super) fn column(&self, name: &str) -> Option<&Column> {
        self.columns.get(&portable(name))
    }
}

pub(super) async fn table_has_rows(
    pool: &MssqlPool,
    table: &str,
) -> Result<bool, MssqlMigrationError> {
    let mut connection = pool
        .get()
        .await
        .map_err(|error| MssqlMigrationError::Database(error.to_string()))?;
    let sql = format!("select top (1) 1 as [present] from {}", quote(table));
    Ok(connection
        .simple_query(sql)
        .await
        .map_err(database)?
        .into_row()
        .await
        .map_err(database)?
        .is_some())
}

fn text(row: &Row, field: &str) -> Result<String, MssqlMigrationError> {
    row.try_get::<&str, _>(field)
        .map_err(database)?
        .map(str::to_owned)
        .ok_or_else(|| MssqlMigrationError::Database(format!("catalog field '{field}' is null")))
}

fn bit(row: &Row, field: &str) -> Result<bool, MssqlMigrationError> {
    row.try_get::<bool, _>(field)
        .map_err(database)
        .map(Option::unwrap_or_default)
}

fn auth_error(error: crate::AuthError) -> MssqlMigrationError {
    MssqlMigrationError::Database(error.to_string())
}

fn portable(value: &str) -> String {
    value.to_lowercase()
}
