use super::D1MigrationError;
use crate::d1::{D1Database, D1Statement, D1Value};
use serde_json::{Map, Value};
use std::collections::HashMap;

pub struct Catalog {
    tables: HashMap<String, Table>,
    indexes: HashMap<String, Index>,
}
pub struct Table {
    columns: HashMap<String, Column>,
}
pub struct Column {
    pub data_type: String,
    pub nullable: bool,
    pub auto_incrementing: bool,
}
pub struct Index {
    pub table: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub valid_full_columns: bool,
}

impl Catalog {
    pub async fn load(database: &dyn D1Database) -> Result<Self, D1MigrationError> {
        let table_rows = database.all(D1Statement::new(
            "select \"name\", \"type\", \"sql\" from \"sqlite_master\" where \"type\" in (?, ?) and \"name\" not like ? and \"name\" not like ? and \"name\" <> ? and \"name\" <> ?",
            vec![D1Value::Text("table".into()), D1Value::Text("view".into()), D1Value::Text("sqlite_%".into()), D1Value::Text("_cf_%".into()), D1Value::Text("kysely_migration".into()), D1Value::Text("kysely_migration_lock".into())],
        )).await?.results;
        if table_rows.is_empty() {
            return Ok(Self {
                tables: HashMap::new(),
                indexes: HashMap::new(),
            });
        }
        let pragma = table_rows
            .iter()
            .map(|row| {
                Ok(D1Statement::new(
                    "SELECT * FROM pragma_table_info(?)",
                    vec![D1Value::Text(text(row, "name")?.into())],
                ))
            })
            .collect::<Result<Vec<_>, D1MigrationError>>()?;
        let column_results = database.batch_all(pragma).await?;
        if column_results.len() != table_rows.len() {
            return Err(D1MigrationError::Configuration(
                "D1 pragma batch returned the wrong result count".into(),
            ));
        }
        let mut tables = HashMap::new();
        let mut indexes = HashMap::new();
        for (position, table_row) in table_rows.iter().enumerate() {
            let table = text(table_row, "name")?.to_owned();
            let sql = optional_text(table_row, "sql")?;
            let rows = &column_results[position].results;
            let auto_increment = auto_increment_column(sql.as_deref(), rows)?;
            let columns = rows
                .iter()
                .map(|row| {
                    let name = text(row, "name")?.to_owned();
                    Ok((
                        name.clone(),
                        Column {
                            data_type: text(row, "type")?.to_owned(),
                            nullable: integer(row, "notnull")? == 0,
                            auto_incrementing: auto_increment.as_deref() == Some(name.as_str()),
                        },
                    ))
                })
                .collect::<Result<HashMap<_, _>, D1MigrationError>>()?;
            load_indexes(database, &table, &mut indexes).await?;
            tables.insert(table, Table { columns });
        }
        Ok(Self { tables, indexes })
    }

    pub fn table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }
    pub fn index(&self, name: &str) -> Option<&Index> {
        self.indexes.get(&name.to_lowercase())
    }
}

impl Table {
    pub fn column(&self, name: &str) -> Option<&Column> {
        self.columns.get(name)
    }
}

async fn load_indexes(
    database: &dyn D1Database,
    table: &str,
    indexes: &mut HashMap<String, Index>,
) -> Result<(), D1MigrationError> {
    let rows = database
        .all(D1Statement::new(
            "select \"name\", \"unique\", \"partial\" from pragma_index_list(?) order by \"seq\"",
            vec![D1Value::Text(table.into())],
        ))
        .await?
        .results;
    for row in rows {
        let name = text(&row, "name")?.to_owned();
        let mut valid = integer(&row, "partial")? == 0;
        let mut positioned = Vec::new();
        for column in database.all(D1Statement::new(
            "select \"seqno\", \"cid\", \"name\" from pragma_index_xinfo(?) where \"key\" = 1 order by \"seqno\"",
            vec![D1Value::Text(name.clone())],
        )).await?.results {
            let cid = integer(&column, "cid")?;
            let column_name = optional_text(&column, "name")?;
            valid &= cid >= 0 && column_name.is_some();
            if let Some(column_name) = column_name { positioned.push((integer(&column, "seqno")?, column_name)); }
        }
        positioned.sort_by_key(|(position, _)| *position);
        indexes.insert(
            name.to_lowercase(),
            Index {
                table: table.into(),
                columns: positioned.into_iter().map(|(_, name)| name).collect(),
                unique: integer(&row, "unique")? != 0,
                valid_full_columns: valid,
            },
        );
    }
    Ok(())
}

fn auto_increment_column(
    sql: Option<&str>,
    rows: &[Map<String, Value>],
) -> Result<Option<String>, D1MigrationError> {
    if let Some(sql) = sql
        && let Some(fragment) = sql
            .split(['(', ')', ','])
            .find(|item| item.to_lowercase().contains("autoincrement"))
        && let Some(name) = fragment.split_whitespace().next()
    {
        return Ok(Some(name.replace(['"', '`'], "")));
    }
    let primary = rows
        .iter()
        .filter(|row| integer(row, "pk").is_ok_and(|value| value > 0))
        .collect::<Vec<_>>();
    if primary.len() == 1 && text(primary[0], "type")?.eq_ignore_ascii_case("integer") {
        return Ok(Some(text(primary[0], "name")?.to_owned()));
    }
    Ok(None)
}

pub async fn table_has_rows(
    database: &dyn D1Database,
    table: &str,
) -> Result<bool, D1MigrationError> {
    Ok(!database
        .all(D1Statement::new(
            format!("select 1 from {} limit 1", super::ddl::quote(table)),
            vec![],
        ))
        .await?
        .results
        .is_empty())
}

fn text<'a>(row: &'a Map<String, Value>, field: &str) -> Result<&'a str, D1MigrationError> {
    row.get(field).and_then(Value::as_str).ok_or_else(|| {
        D1MigrationError::Configuration(format!("D1 introspection field '{field}' is not text"))
    })
}
fn optional_text(
    row: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, D1MigrationError> {
    match row.get(field) {
        Some(Value::Null) | None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(D1MigrationError::Configuration(format!(
            "D1 introspection field '{field}' is not nullable text"
        ))),
    }
}
fn integer(row: &Map<String, Value>, field: &str) -> Result<i64, D1MigrationError> {
    row.get(field).and_then(Value::as_i64).ok_or_else(|| {
        D1MigrationError::Configuration(format!(
            "D1 introspection field '{field}' is not an integer"
        ))
    })
}
