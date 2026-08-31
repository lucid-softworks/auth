use super::MySqlMigrationError;
use sqlx::{MySqlPool, Row};
use std::collections::HashMap;

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
    pub(super) valid_full_columns: bool,
}

impl Catalog {
    pub(super) async fn load(pool: &MySqlPool) -> Result<Self, MySqlMigrationError> {
        let table_rows = sqlx::query(
            "select cast(table_name as char) from information_schema.tables where table_schema = database() and table_type = 'BASE TABLE' order by table_name",
        )
        .fetch_all(pool)
        .await?;
        let mut tables = HashMap::new();
        for row in table_rows {
            let table: String = row.try_get(0)?;
            let columns = sqlx::query(
                "select cast(column_name as char), cast(column_type as char), cast(is_nullable as char), character_maximum_length from information_schema.columns where table_schema = database() and table_name = ? order by ordinal_position",
            )
            .bind(&table)
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>(0)?,
                    Column {
                        data_type: row.try_get(1)?,
                        nullable: row.try_get::<String, _>(2)? == "YES",
                        character_maximum_length: row
                            .try_get::<Option<i64>, _>(3)?
                            .and_then(|value| u64::try_from(value).ok()),
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
            tables.insert(table, Table { columns });
        }

        let mut indexes = HashMap::<(String, String), Index>::new();
        for row in sqlx::query(
            "select cast(table_name as char), cast(index_name as char), non_unique, seq_in_index, cast(column_name as char), sub_part, cast(expression as char) from information_schema.statistics where table_schema = database() order by table_name, index_name, seq_in_index",
        )
        .fetch_all(pool)
        .await?
        {
            let table: String = row.try_get(0)?;
            let name: String = row.try_get(1)?;
            let unique = row.try_get::<i64, _>(2)? == 0;
            let column = row.try_get::<Option<String>, _>(4)?;
            let sub_part = row.try_get::<Option<i64>, _>(5)?;
            let expression = row.try_get::<Option<String>, _>(6)?;
            let index = indexes
                .entry((table.clone(), portable(&name)))
                .or_insert_with(|| Index {
                    table,
                    columns: Vec::new(),
                    unique,
                    valid_full_columns: true,
                });
            index.valid_full_columns &=
                column.is_some() && sub_part.is_none() && expression.is_none();
            if let Some(column) = column {
                index.columns.push(column);
            }
        }
        Ok(Self { tables, indexes })
    }

    pub(super) fn table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }

    pub(super) fn index(&self, table: &str, name: &str) -> Option<&Index> {
        self.indexes.get(&(table.to_owned(), portable(name)))
    }
}

impl Table {
    pub(super) fn column(&self, name: &str) -> Option<&Column> {
        self.columns.get(name)
    }
}

pub(super) async fn table_has_rows(
    pool: &MySqlPool,
    table: &str,
) -> Result<bool, MySqlMigrationError> {
    let sql = format!("select 1 from {} limit 1", crate::mysql::schema::quote(table));
    Ok(sqlx::query(&sql).fetch_optional(pool).await?.is_some())
}

fn portable(value: &str) -> String {
    value.to_lowercase()
}
