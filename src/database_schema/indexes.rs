use super::{AuthSchemaCatalog, DatabaseSchemaIndex, SchemaTable};
use crate::AdditionalFieldType;
use indexmap::IndexMap;
use std::collections::HashMap;

const MAX_NAME_BYTES: usize = 63;
const MAX_FIELDS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDatabaseIndex {
    pub columns: Vec<String>,
    pub name: String,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SchemaIndexError(pub String);

pub(super) fn resolve(
    catalog: &AuthSchemaCatalog,
) -> Result<IndexMap<String, Vec<ResolvedDatabaseIndex>>, SchemaIndexError> {
    resolve_with_plural(catalog, false)
}

pub(super) fn resolve_for_adapter(
    catalog: &AuthSchemaCatalog,
    use_plural: bool,
) -> Result<IndexMap<String, Vec<ResolvedDatabaseIndex>>, SchemaIndexError> {
    resolve_with_plural(catalog, use_plural)
}

pub(super) fn resolve_field_indexes_for_adapter(
    catalog: &AuthSchemaCatalog,
    use_plural: bool,
) -> Result<IndexMap<String, Vec<ResolvedDatabaseIndex>>, SchemaIndexError> {
    let sources = merge_physical_tables(catalog, use_plural)?;
    validate_field_indexes(&sources)?;
    let mut resolved = IndexMap::<String, Vec<ResolvedDatabaseIndex>>::new();
    for (table_name, table) in sources {
        let indexes = resolved.entry(table_name.clone()).or_default();
        for (logical, field) in table.fields {
            if !field.index && !field.unique {
                continue;
            }
            let column = physical_field(&logical, field.field_name.as_deref()).to_owned();
            indexes.push(ResolvedDatabaseIndex {
                name: field_index_name(&table_name, &column, field.unique),
                columns: vec![column],
                unique: field.unique,
            });
        }
    }
    Ok(resolved)
}

fn resolve_with_plural(
    catalog: &AuthSchemaCatalog,
    use_plural: bool,
) -> Result<IndexMap<String, Vec<ResolvedDatabaseIndex>>, SchemaIndexError> {
    let sources = merge_physical_tables(catalog, use_plural)?;
    validate_field_indexes(&sources)?;
    let table_names = sources
        .keys()
        .map(|name| (portable(name), name.as_str()))
        .collect::<HashMap<_, _>>();
    let field_owners = field_index_owners(&sources)?;
    let mut owners = HashMap::<String, String>::new();
    let mut result = IndexMap::new();
    for (table_name, table) in &sources {
        let indexes = resolve_table(table_name, table)?;
        for index in &indexes {
            let key = portable(&index.name);
            if table_names.contains_key(&key) {
                return error(format!(
                    "Database index name \"{}\" conflicts with a table name. Index and table names must be unique across the schema.",
                    index.name
                ));
            }
            if let Some(owner) = field_owners.get(&key) {
                return error(format!(
                    "Database index name \"{}\" is already reserved by field-level index metadata on table \"{owner}\". Remove the duplicate table-level index or give it a distinct name.",
                    index.name
                ));
            }
            if let Some(owner) = owners.get(&key)
                && owner != table_name
            {
                return error(format!(
                    "Database index name \"{}\" is used by both table \"{owner}\" and table \"{table_name}\". Index names must be unique across the schema.",
                    index.name
                ));
            }
            owners.insert(key, table_name.clone());
        }
        result.insert(table_name.clone(), indexes);
    }
    Ok(result)
}

fn merge_physical_tables(
    catalog: &AuthSchemaCatalog,
    use_plural: bool,
) -> Result<IndexMap<String, SchemaTable>, SchemaIndexError> {
    let mut sources = IndexMap::<String, SchemaTable>::new();
    for table in catalog
        .tables()
        .values()
        .filter(|table| !table.disable_migrations)
    {
        let physical_name = if use_plural {
            format!("{}s", table.model_name)
        } else {
            table.model_name.clone()
        };
        if let Some(existing) = sources.get_mut(&physical_name) {
            if !existing.indexes.is_empty() || !table.indexes.is_empty() {
                return error(format!(
                    "Database schema resolves more than one indexed logical table to \"{}\". Define table-level indexes through one logical schema key instead of aliasing multiple keys to the same database table.",
                    physical_name
                ));
            }
            existing.fields.extend(table.fields.clone());
        } else {
            let mut table = table.clone();
            table.model_name.clone_from(&physical_name);
            sources.insert(physical_name, table);
        }
    }
    Ok(sources)
}

fn validate_field_indexes(sources: &IndexMap<String, SchemaTable>) -> Result<(), SchemaIndexError> {
    let table_names = sources
        .keys()
        .map(|name| portable(name))
        .collect::<Vec<_>>();
    for (name, owner) in field_index_owners(sources)? {
        if table_names.contains(&name) {
            let original = field_index_name_for_key(sources, &name).unwrap();
            return error(format!(
                "Database index name \"{original}\" conflicts with a table name. Index and table names must be unique across the schema."
            ));
        }
        let _ = owner;
    }
    Ok(())
}

fn field_index_owners(
    sources: &IndexMap<String, SchemaTable>,
) -> Result<HashMap<String, String>, SchemaIndexError> {
    let mut owners = HashMap::new();
    for (table_name, table) in sources {
        for (logical, field) in &table.fields {
            if !field.index && !field.unique {
                continue;
            }
            let column = physical_field(logical, field.field_name.as_deref());
            let name = index_name(
                table_name,
                &DatabaseSchemaIndex::new([column]).unique(field.unique),
            )?;
            let key = portable(&name);
            if let Some(existing) = owners.insert(key, table_name.clone()) {
                return error(format!(
                    "Database field-level index name \"{name}\" is used by both table \"{existing}\" and table \"{table_name}\"."
                ));
            }
        }
    }
    Ok(owners)
}

fn field_index_name_for_key(sources: &IndexMap<String, SchemaTable>, key: &str) -> Option<String> {
    sources.iter().find_map(|(table_name, table)| {
        table.fields.iter().find_map(|(logical, field)| {
            (field.index || field.unique)
                .then(|| {
                    index_name(
                        table_name,
                        &DatabaseSchemaIndex::new([physical_field(
                            logical,
                            field.field_name.as_deref(),
                        )])
                        .unique(field.unique),
                    )
                    .ok()
                })
                .flatten()
                .filter(|name| portable(name) == key)
        })
    })
}

fn resolve_table(
    table_name: &str,
    table: &SchemaTable,
) -> Result<Vec<ResolvedDatabaseIndex>, SchemaIndexError> {
    let mut resolved = Vec::new();
    let mut definitions = HashMap::<String, (Vec<String>, bool)>::new();
    for index in &table.indexes {
        validate_index(table_name, table, index)?;
        let columns = index
            .fields
            .iter()
            .map(|logical| {
                let field = &table.fields[logical];
                physical_field(logical, field.field_name.as_deref()).to_owned()
            })
            .collect::<Vec<_>>();
        if has_portable_duplicates(&columns) {
            return error(format!(
                "Index on table \"{table_name}\" resolves more than one field to the same database column."
            ));
        }
        let mut physical_index = index.clone();
        physical_index.fields.clone_from(&columns);
        let name = index_name(table_name, &physical_index)?;
        let key = portable(&name);
        let definition = (columns.clone(), index.unique);
        if let Some(existing) = definitions.get(&key) {
            if existing != &definition {
                return error(format!(
                    "Database index name \"{name}\" identifies more than one index on table \"{table_name}\"."
                ));
            }
            continue;
        }
        definitions.insert(key, definition);
        resolved.push(ResolvedDatabaseIndex {
            columns,
            name,
            unique: index.unique,
        });
    }
    Ok(resolved)
}

fn validate_index(
    table_name: &str,
    table: &SchemaTable,
    index: &DatabaseSchemaIndex,
) -> Result<(), SchemaIndexError> {
    if index.fields.is_empty() {
        return error(format!(
            "Index on table \"{table_name}\" must include at least one field."
        ));
    }
    if index.fields.len() > MAX_FIELDS {
        return error(format!(
            "Index on table \"{table_name}\" can include at most {MAX_FIELDS} fields so it works across supported databases."
        ));
    }
    if has_duplicates(&index.fields) {
        return error(format!(
            "Index on table \"{table_name}\" contains the same field more than once."
        ));
    }
    for logical in &index.fields {
        let Some(field) = table.fields.get(logical) else {
            return error(format!(
                "Index on table \"{table_name}\" references unknown field \"{logical}\"."
            ));
        };
        if index.unique && !field.required {
            return error(format!(
                "Unique index on table \"{table_name}\" can only include required fields so its behavior is consistent across databases."
            ));
        }
        if matches!(
            field.field_type,
            AdditionalFieldType::Json
                | AdditionalFieldType::StringArray
                | AdditionalFieldType::NumberArray
        ) {
            return error(format!(
                "Index on table \"{table_name}\" references field \"{logical}\", whose type is not portably indexable."
            ));
        }
    }
    Ok(())
}

fn index_name(table_name: &str, index: &DatabaseSchemaIndex) -> Result<String, SchemaIndexError> {
    if let Some(name) = &index.name {
        if name.trim().is_empty() {
            return error("Database index names must contain at least one visible character.");
        }
        let mut characters = name.chars();
        let valid_first = characters
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_alphabetic());
        if !valid_first
            || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            return error(
                "Database index names must start with a letter or underscore and contain only letters, numbers, and underscores.",
            );
        }
        if name.len() > MAX_NAME_BYTES {
            return error(format!(
                "Database index names must be at most {MAX_NAME_BYTES} UTF-8 bytes."
            ));
        }
        return Ok(name.clone());
    }
    let kind = if index.unique { "uidx" } else { "idx" };
    let generated = format!("{table_name}_{}_{kind}", index.fields.join("_"));
    if generated.len() <= MAX_NAME_BYTES {
        return Ok(generated);
    }
    let suffix = format!("_{:08x}_{kind}", fnv1a_utf16(&generated));
    let stem = &generated[..generated.len() - kind.len() - 1];
    Ok(format!(
        "{}{}",
        truncate_utf8(stem, MAX_NAME_BYTES - suffix.len()),
        suffix
    ))
}

pub(crate) fn field_index_name(table_name: &str, column: &str, unique: bool) -> String {
    index_name(
        table_name,
        &DatabaseSchemaIndex::new([column]).unique(unique),
    )
    .expect("generated Better Auth field index names are always valid")
}

fn physical_field<'a>(logical: &'a str, configured: Option<&'a str>) -> &'a str {
    configured
        .filter(|name| !name.is_empty())
        .unwrap_or(logical)
}

fn fnv1a_utf16(value: &str) -> u32 {
    value.encode_utf16().fold(2_166_136_261_u32, |hash, unit| {
        (hash ^ u32::from(unit)).wrapping_mul(16_777_619)
    })
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    let mut end = 0;
    for (offset, character) in value.char_indices() {
        let next = offset + character.len_utf8();
        if next > max_bytes {
            break;
        }
        end = next;
    }
    &value[..end]
}

fn portable(value: &str) -> String {
    value.to_lowercase()
}

fn has_duplicates(values: &[String]) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().any(|value| !seen.insert(value))
}

fn has_portable_duplicates(values: &[String]) -> bool {
    let mut seen = std::collections::HashSet::new();
    values.iter().any(|value| !seen.insert(portable(value)))
}

fn error<T>(message: impl Into<String>) -> Result<T, SchemaIndexError> {
    Err(SchemaIndexError(message.into()))
}
