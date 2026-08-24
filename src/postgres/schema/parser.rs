use super::PostgresSchemaObject;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(super) struct SchemaManifest {
    tables: BTreeMap<String, BTreeMap<String, String>>,
    indexes: BTreeMap<String, (String, bool)>,
}

impl SchemaManifest {
    pub(super) fn apply(&mut self, sql: &str) {
        let sql = without_do_blocks(sql);
        for statement in sql.split(';').map(str::trim).filter(|sql| !sql.is_empty()) {
            self.apply_statement(statement);
        }
    }

    pub(super) fn add_bookkeeping(&mut self, include_plugins: bool) {
        self.tables.insert(
            "lucid_auth_migrations".into(),
            BTreeMap::from([
                ("applied_at".into(), "timestamp with time zone".into()),
                ("checksum".into(), "text".into()),
                ("description".into(), "text".into()),
                ("version".into(), "bigint".into()),
            ]),
        );
        if include_plugins {
            self.tables.insert(
                "lucid_auth_plugin_migrations".into(),
                BTreeMap::from([
                    ("applied_at".into(), "timestamp with time zone".into()),
                    ("checksum".into(), "text".into()),
                    ("description".into(), "text".into()),
                    ("migration_id".into(), "text".into()),
                    ("plugin_id".into(), "text".into()),
                ]),
            );
        }
    }

    pub(super) fn objects(self) -> Vec<PostgresSchemaObject> {
        let mut objects = BTreeSet::new();
        for (table, columns) in self.tables {
            objects.insert(PostgresSchemaObject::Table {
                name: table.clone(),
            });
            for (name, data_type) in columns {
                objects.insert(PostgresSchemaObject::Column {
                    table: table.clone(),
                    name,
                    data_type,
                });
            }
        }
        for (name, (table, unique)) in self.indexes {
            objects.insert(PostgresSchemaObject::Index {
                table,
                name,
                unique,
            });
        }
        objects.into_iter().collect()
    }

    fn apply_statement(&mut self, statement: &str) {
        let normalized = statement.split_whitespace().collect::<Vec<_>>().join(" ");
        if starts_with(&normalized, "CREATE TABLE ") {
            self.create_table(&normalized);
        } else if starts_with(&normalized, "ALTER TABLE ") {
            self.alter_table(&normalized);
        } else if starts_with(&normalized, "CREATE INDEX ")
            || starts_with(&normalized, "CREATE UNIQUE INDEX ")
        {
            self.create_index(&normalized);
        } else if starts_with(&normalized, "DROP INDEX ") {
            self.drop_index(&normalized);
        } else if starts_with(&normalized, "DROP TABLE ") {
            self.drop_table(&normalized);
        }
    }

    fn create_table(&mut self, statement: &str) {
        let Some(mut rest) = strip_prefix(statement, "CREATE TABLE ") else {
            return;
        };
        rest = strip_prefix(rest, "IF NOT EXISTS ").unwrap_or(rest);
        let Some(open) = rest.find('(') else { return };
        let Some(close) = rest.rfind(')') else { return };
        let table = identifier(rest[..open].trim());
        let columns = self.tables.entry(table).or_default();
        for declaration in split_top_level(&rest[open + 1..close]) {
            let mut words = declaration.split_whitespace();
            let Some(name) = words.next() else { continue };
            if ["CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"]
                .iter()
                .any(|keyword| name.eq_ignore_ascii_case(keyword))
            {
                continue;
            }
            let Some(data_type) = words.next() else {
                continue;
            };
            columns.insert(identifier(name), normalize_type(data_type));
        }
    }

    fn alter_table(&mut self, statement: &str) {
        let Some(rest) = strip_prefix(statement, "ALTER TABLE ") else {
            return;
        };
        let Some((table, operations)) = rest.split_once(' ') else {
            return;
        };
        let table = identifier(table);
        for operation in split_top_level(operations) {
            let words = operation.split_whitespace().collect::<Vec<_>>();
            if words.len() >= 3
                && words[0].eq_ignore_ascii_case("ADD")
                && words[1].eq_ignore_ascii_case("COLUMN")
            {
                let index = if words
                    .get(2)
                    .is_some_and(|word| word.eq_ignore_ascii_case("IF"))
                {
                    5
                } else {
                    2
                };
                if let (Some(name), Some(data_type)) = (words.get(index), words.get(index + 1)) {
                    self.tables
                        .entry(table.clone())
                        .or_default()
                        .insert(identifier(name), normalize_type(data_type));
                }
            } else if words.len() >= 3
                && words[0].eq_ignore_ascii_case("DROP")
                && words[1].eq_ignore_ascii_case("COLUMN")
            {
                let index = if words
                    .get(2)
                    .is_some_and(|word| word.eq_ignore_ascii_case("IF"))
                {
                    4
                } else {
                    2
                };
                if let Some(name) = words.get(index)
                    && let Some(columns) = self.tables.get_mut(&table)
                {
                    columns.remove(&identifier(name));
                }
            } else if words.len() >= 5
                && words[0].eq_ignore_ascii_case("RENAME")
                && words[1].eq_ignore_ascii_case("COLUMN")
                && words[3].eq_ignore_ascii_case("TO")
            {
                if let Some(columns) = self.tables.get_mut(&table)
                    && let Some(data_type) = columns.remove(&identifier(words[2]))
                {
                    columns.insert(identifier(words[4]), data_type);
                }
            } else if words.len() >= 4
                && words[0].eq_ignore_ascii_case("ALTER")
                && words[1].eq_ignore_ascii_case("COLUMN")
                && words[3].eq_ignore_ascii_case("TYPE")
                && let Some(data_type) = words.get(4)
            {
                self.tables
                    .entry(table.clone())
                    .or_default()
                    .insert(identifier(words[2]), normalize_type(data_type));
            }
        }
    }

    fn create_index(&mut self, statement: &str) {
        let unique = starts_with(statement, "CREATE UNIQUE INDEX ");
        let prefix = if unique {
            "CREATE UNIQUE INDEX "
        } else {
            "CREATE INDEX "
        };
        let Some(mut rest) = strip_prefix(statement, prefix) else {
            return;
        };
        rest = strip_prefix(rest, "IF NOT EXISTS ").unwrap_or(rest);
        let words = rest.split_whitespace().collect::<Vec<_>>();
        let Some(on) = words
            .iter()
            .position(|word| word.eq_ignore_ascii_case("ON"))
        else {
            return;
        };
        if on == 0 || on + 1 >= words.len() {
            return;
        }
        self.indexes.insert(
            identifier(words[0]),
            (
                identifier(words[on + 1].split('(').next().unwrap_or(words[on + 1])),
                unique,
            ),
        );
    }

    fn drop_index(&mut self, statement: &str) {
        let Some(mut rest) = strip_prefix(statement, "DROP INDEX ") else {
            return;
        };
        rest = strip_prefix(rest, "IF EXISTS ").unwrap_or(rest);
        if let Some(name) = rest.split_whitespace().next() {
            self.indexes.remove(&identifier(name));
        }
    }

    fn drop_table(&mut self, statement: &str) {
        let Some(mut rest) = strip_prefix(statement, "DROP TABLE ") else {
            return;
        };
        rest = strip_prefix(rest, "IF EXISTS ").unwrap_or(rest);
        if let Some(name) = rest.split_whitespace().next() {
            let table = identifier(name);
            self.tables.remove(&table);
            self.indexes.retain(|_, (owner, _)| owner != &table);
        }
    }
}

fn without_do_blocks(sql: &str) -> String {
    let mut output = String::new();
    let mut in_do = false;
    for line in sql.lines() {
        if !in_do && line.trim_start().to_ascii_uppercase().starts_with("DO $$") {
            in_do = true;
            continue;
        }
        if in_do {
            if line.contains("$$;") {
                in_do = false;
            }
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn split_top_level(value: &str) -> Vec<&str> {
    let mut depth = 0_u32;
    let mut start = 0;
    let mut parts = Vec::new();
    for (index, byte) in value.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                parts.push(value[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(value[start..].trim());
    parts
}

fn starts_with(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(prefix))
}

fn strip_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    starts_with(value, prefix).then(|| &value[prefix.len()..])
}

fn identifier(value: &str) -> String {
    value
        .trim_matches(|character: char| matches!(character, '"' | ',' | ';'))
        .to_ascii_lowercase()
}

fn normalize_type(value: &str) -> String {
    match value
        .trim_matches(|character: char| matches!(character, ',' | ';'))
        .to_ascii_uppercase()
        .as_str()
    {
        "BIGINT" | "INT8" => "bigint".into(),
        "BOOLEAN" | "BOOL" => "boolean".into(),
        "DOUBLE" => "double precision".into(),
        "INTEGER" | "INT" | "INT4" => "integer".into(),
        "JSONB" => "jsonb".into(),
        "TEXT" => "text".into(),
        "TIMESTAMPTZ" => "timestamp with time zone".into(),
        "UUID" => "uuid".into(),
        other => other.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_final_columns_and_indexes_from_ordered_sql() {
        let mut manifest = SchemaManifest::default();
        manifest.apply(
            "CREATE TABLE IF NOT EXISTS example (id UUID PRIMARY KEY, attempts INTEGER);\n\
             CREATE INDEX IF NOT EXISTS example_attempts_idx ON example(attempts);",
        );
        manifest.apply(
            "ALTER TABLE example RENAME COLUMN attempts TO count;\n\
             ALTER TABLE example ALTER COLUMN count TYPE BIGINT, ADD COLUMN IF NOT EXISTS data JSONB;\n\
             DROP INDEX IF EXISTS example_attempts_idx;\n\
             CREATE UNIQUE INDEX example_count_idx ON example(count);",
        );
        assert_eq!(
            manifest.objects(),
            vec![
                PostgresSchemaObject::Column {
                    table: "example".into(),
                    name: "count".into(),
                    data_type: "bigint".into(),
                },
                PostgresSchemaObject::Column {
                    table: "example".into(),
                    name: "data".into(),
                    data_type: "jsonb".into(),
                },
                PostgresSchemaObject::Column {
                    table: "example".into(),
                    name: "id".into(),
                    data_type: "uuid".into(),
                },
                PostgresSchemaObject::Index {
                    table: "example".into(),
                    name: "example_count_idx".into(),
                    unique: true,
                },
                PostgresSchemaObject::Table {
                    name: "example".into(),
                },
            ]
        );
    }

    #[test]
    fn ignores_conditional_legacy_ddl_inside_do_blocks() {
        let mut manifest = SchemaManifest::default();
        manifest.apply(
            "CREATE TABLE current_table (id UUID);\n\
             DO $$\nBEGIN\nCREATE TABLE legacy_table (id UUID);\nEND $$;",
        );
        assert!(manifest.tables.contains_key("current_table"));
        assert!(!manifest.tables.contains_key("legacy_table"));
    }

    #[test]
    fn normalizes_double_precision_to_the_catalog_type() {
        let mut manifest = SchemaManifest::default();
        manifest.apply("CREATE TABLE example (network DOUBLE PRECISION);");
        assert_eq!(manifest.tables["example"]["network"], "double precision");
    }
}
