use super::SqliteMigrationError;
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;

pub(super) struct Catalog {
    tables: HashMap<String, Table>,
    indexes: HashMap<String, Index>,
}

pub(super) struct Table {
    columns: HashMap<String, Column>,
}

pub(super) struct Column {
    pub(super) data_type: String,
    pub(super) nullable: bool,
}

pub(super) struct Index {
    pub(super) table: String,
    pub(super) columns: Vec<String>,
    pub(super) unique: bool,
    pub(super) valid_full_columns: bool,
}

impl Catalog {
    pub(super) async fn load(pool: &SqlitePool) -> Result<Self, SqliteMigrationError> {
        let table_rows = sqlx::query(
            "select name from sqlite_schema where type = 'table' and name not like 'sqlite_%' order by rowid",
        )
        .fetch_all(pool)
        .await?;
        let mut tables = HashMap::new();
        let mut indexes = HashMap::new();
        for row in table_rows {
            let table: String = row.try_get("name")?;
            let columns = sqlx::query(
                "select name, type, \"notnull\" from pragma_table_info(?) order by cid",
            )
            .bind(&table)
            .fetch_all(pool)
            .await?
            .into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String, _>("name")?,
                    Column {
                        data_type: row.try_get("type")?,
                        nullable: row.try_get::<i64, _>("notnull")? == 0,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>, sqlx::Error>>()?;
            for index_row in sqlx::query(
                "select name, \"unique\", partial from pragma_index_list(?) order by seq",
            )
            .bind(&table)
            .fetch_all(pool)
            .await?
            {
                let name: String = index_row.try_get("name")?;
                let mut valid = index_row.try_get::<i64, _>("partial")? == 0;
                let mut positioned = Vec::new();
                for column in sqlx::query(
                    "select seqno, cid, name from pragma_index_xinfo(?) where key = 1 order by seqno",
                )
                .bind(&name)
                .fetch_all(pool)
                .await?
                {
                    let position: i64 = column.try_get("seqno")?;
                    let cid: i64 = column.try_get("cid")?;
                    let name = column.try_get::<Option<String>, _>("name")?;
                    valid &= cid >= 0 && name.is_some();
                    if let Some(name) = name {
                        positioned.push((position, name));
                    }
                }
                positioned.sort_by_key(|(position, _)| *position);
                indexes.insert(
                    portable(&name),
                    Index {
                        table: table.clone(),
                        columns: positioned.into_iter().map(|(_, name)| name).collect(),
                        unique: index_row.try_get::<i64, _>("unique")? != 0,
                        valid_full_columns: valid,
                    },
                );
            }
            tables.insert(table, Table { columns });
        }
        Ok(Self { tables, indexes })
    }

    pub(super) fn table(&self, name: &str) -> Option<&Table> {
        self.tables.get(name)
    }

    pub(super) fn index(&self, name: &str) -> Option<&Index> {
        self.indexes.get(&portable(name))
    }
}

impl Table {
    pub(super) fn column(&self, name: &str) -> Option<&Column> {
        self.columns.get(name)
    }
}

pub(super) async fn table_has_rows(
    pool: &SqlitePool,
    table: &str,
) -> Result<bool, SqliteMigrationError> {
    let sql = format!("select 1 from {} limit 1", super::ddl::quote(table));
    Ok(sqlx::query(&sql).fetch_optional(pool).await?.is_some())
}

fn portable(value: &str) -> String {
    value.to_lowercase()
}
