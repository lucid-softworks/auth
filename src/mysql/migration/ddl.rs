use super::MySqlMigrationError;
use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldType, DatabaseIdType,
    ResolvedAdapterSchema, ResolvedDatabaseIndex,
    mysql::schema::{PhysicalModel, quote},
};

const MYSQL_INDEX_BYTES: usize = 3_072;
const MYSQL_BYTES_PER_CHARACTER: usize = 4;
const MYSQL_NON_STRING_INDEX_BYTES: usize = 16;
const MYSQL_GENERATED_INDEX_STRING_LENGTH: usize = 191;

pub(super) fn create_table(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
) -> Result<String, MySqlMigrationError> {
    let mut definitions = vec![match model.id_type {
        DatabaseIdType::Serial => "`id` integer not null auto_increment primary key".into(),
        DatabaseIdType::String | DatabaseIdType::Uuid => {
            "`id` varchar(36) not null primary key".into()
        }
    }];
    for (column, physical) in &model.columns {
        definitions.push(column_definition(
            schema,
            model,
            column,
            &physical.field,
            true,
            false,
        )?);
    }
    Ok(format!(
        "create table {} ({})",
        model.quoted_table,
        definitions.join(", ")
    ))
}

pub(super) fn column_definition(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
    column: &str,
    field: &AdditionalField,
    inline_unique: bool,
    add_column: bool,
) -> Result<String, MySqlMigrationError> {
    let mut definition = format!(
        "{} {}",
        quote(column),
        sql_type(schema, model, column, field)
    );
    if field.required {
        definition.push_str(" not null");
    }
    if inline_unique && field.unique {
        definition.push_str(" unique");
    }
    if field.field_type == AdditionalFieldType::Date && field.has_default_factory() {
        definition.push_str(" default CURRENT_TIMESTAMP(3)");
    } else if add_column && let Some(default) = static_default(field) {
        definition.push_str(" default ");
        definition.push_str(&default);
    }
    if let Some(reference) = &field.references {
        let (table, target) = schema
            .adapter_reference_names(&reference.model, &reference.field)
            .map_err(|error| MySqlMigrationError::Configuration(error.to_string()))?;
        definition.push_str(&format!(
            " references {} ({}){}",
            quote(&table),
            quote(&target),
            on_delete(reference.on_delete)
        ));
    }
    Ok(definition)
}

pub(super) fn create_index(table: &str, name: &str, columns: &[String], unique: bool) -> String {
    format!(
        "create {}index {} on {} ({})",
        if unique { "unique " } else { "" },
        quote(name),
        quote(table),
        columns
            .iter()
            .map(|column| quote(column))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub(super) fn has_usable_static_default(field: &AdditionalField) -> bool {
    if !field.required && field.unique {
        return false;
    }
    matches!(
        (field.field_type, field.static_default_value()),
        (
            AdditionalFieldType::String,
            Some(serde_json::Value::String(_))
        ) | (
            AdditionalFieldType::Number,
            Some(serde_json::Value::Number(_))
        ) | (
            AdditionalFieldType::Boolean,
            Some(serde_json::Value::Bool(_))
        )
    )
}

pub(super) fn has_usable_timestamp_default(field: &AdditionalField) -> bool {
    field.field_type == AdditionalFieldType::Date && field.has_default_factory()
}

pub(super) fn type_matches(discovered: &str, expected: AdditionalFieldType) -> bool {
    let normalized = discovered
        .to_lowercase()
        .split('(')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    match expected {
        AdditionalFieldType::String => matches!(normalized.as_str(), "varchar" | "text"),
        AdditionalFieldType::StringLiteral(_) => normalized == "text",
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => normalized == "json",
        AdditionalFieldType::Number => matches!(
            normalized.as_str(),
            "integer" | "int" | "bigint" | "smallint" | "mediumint" | "tinyint"
        ),
        AdditionalFieldType::Boolean => matches!(normalized.as_str(), "boolean" | "bool" | "tinyint"),
        AdditionalFieldType::Date => matches!(normalized.as_str(), "timestamp" | "datetime"),
    }
}

pub(super) const fn field_type_name(field_type: AdditionalFieldType) -> &'static str {
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => "string",
        AdditionalFieldType::Number => "number",
        AdditionalFieldType::Boolean => "boolean",
        AdditionalFieldType::Date => "date",
        AdditionalFieldType::Json => "json",
        AdditionalFieldType::StringArray => "string[]",
        AdditionalFieldType::NumberArray => "number[]",
    }
}

pub(super) fn generated_string_length(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
    column: &str,
) -> Option<usize> {
    let field = &model.columns.get(column)?.field;
    if field.field_type != AdditionalFieldType::String || field.references.is_some() {
        return None;
    }
    let indexes = containing_indexes(schema, model, column);
    if indexes.is_empty() {
        return (field.unique || field.index)
            .then_some(MYSQL_GENERATED_INDEX_STRING_LENGTH)
            .or_else(|| field.sortable.then_some(255));
    }
    indexes
        .into_iter()
        .filter_map(|index| safe_string_length(model, index))
        .min()
}

fn sql_type(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
    column: &str,
    field: &AdditionalField,
) -> String {
    if let Some(id_type) = field.references.as_ref().and_then(|reference| {
        (reference.field == "id")
            .then(|| {
                schema
                    .catalog()
                    .table(&reference.model)
                    .map(|table| table.id_type)
            })
            .flatten()
    }) {
        return id_type_sql(id_type).into();
    }
    match field.field_type {
        AdditionalFieldType::String => generated_string_length(schema, model, column)
            .map(|length| format!("varchar({length})"))
            .unwrap_or_else(|| "text".into()),
        AdditionalFieldType::StringLiteral(_) => "text".into(),
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => "json".into(),
        AdditionalFieldType::Boolean => "boolean".into(),
        AdditionalFieldType::Number if field.bigint => "bigint".into(),
        AdditionalFieldType::Number => "integer".into(),
        AdditionalFieldType::Date => "timestamp(3)".into(),
    }
}

fn id_type_sql(id_type: DatabaseIdType) -> &'static str {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => "varchar(36)",
        DatabaseIdType::Serial => "integer",
    }
}

fn containing_indexes<'a>(
    schema: &'a ResolvedAdapterSchema,
    model: &PhysicalModel,
    column: &str,
) -> Vec<&'a ResolvedDatabaseIndex> {
    schema
        .indexes_by_table()
        .get(&model.table)
        .into_iter()
        .flatten()
        .chain(
            schema
                .field_indexes_by_table()
                .get(&model.table)
                .into_iter()
                .flatten(),
        )
        .filter(|index| index.columns.iter().any(|candidate| candidate == column))
        .collect()
}

fn safe_string_length(model: &PhysicalModel, index: &ResolvedDatabaseIndex) -> Option<usize> {
    let mut strings = 0;
    let mut fixed = 0;
    for column in &index.columns {
        let field = &model.columns.get(column)?.field;
        if field.field_type == AdditionalFieldType::String && field.references.is_none() {
            strings += 1;
        } else {
            fixed += MYSQL_NON_STRING_INDEX_BYTES;
        }
    }
    (strings > 0 && fixed < MYSQL_INDEX_BYTES).then(|| {
        ((MYSQL_INDEX_BYTES - fixed) / MYSQL_BYTES_PER_CHARACTER / strings)
            .clamp(1, MYSQL_GENERATED_INDEX_STRING_LENGTH)
    })
}

fn static_default(field: &AdditionalField) -> Option<String> {
    if !has_usable_static_default(field) {
        return None;
    }
    match field.static_default_value()? {
        serde_json::Value::String(value) => Some(format!("'{}'", value.replace('\'', "''"))),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(i64::from(*value).to_string()),
        _ => None,
    }
}

fn on_delete(action: Option<AdditionalFieldOnDelete>) -> &'static str {
    match action {
        None | Some(AdditionalFieldOnDelete::Cascade) => " on delete cascade",
        Some(AdditionalFieldOnDelete::NoAction) => "",
        Some(AdditionalFieldOnDelete::Restrict) => " on delete restrict",
        Some(AdditionalFieldOnDelete::SetNull) => " on delete set null",
        Some(AdditionalFieldOnDelete::SetDefault) => " on delete set default",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdapterSchemaOptions, AuthConfig, AuthSchemaCatalog, PluginSchemaTable};
    use std::sync::Arc;

    fn resolved(table: PluginSchemaTable, serial: bool) -> (ResolvedAdapterSchema, PhysicalModel) {
        let mut config = AuthConfig::new([62; 32]).unwrap();
        if serial {
            config.database_id_generation = crate::DatabaseIdGeneration::Serial;
        }
        let schema = ResolvedAdapterSchema::new(
            Arc::new(AuthSchemaCatalog::build(&config, [table]).unwrap()),
            AdapterSchemaOptions::default(),
        )
        .unwrap();
        let physical = crate::mysql::schema::MySqlSchema::new(&schema)
            .unwrap()
            .models()
            .find(|model| model.table == "widget")
            .unwrap()
            .clone();
        (schema, physical)
    }

    #[test]
    fn generates_mysql_types_and_serial_primary_keys() {
        let table = PluginSchemaTable::new("widget")
            .field("name", AdditionalField::new(AdditionalFieldType::String).unique(true))
            .field("data", AdditionalField::new(AdditionalFieldType::Json))
            .field("when", AdditionalField::new(AdditionalFieldType::Date));
        let (schema, model) = resolved(table, true);
        let sql = create_table(&schema, &model).unwrap();
        assert!(sql.contains("`id` integer not null auto_increment primary key"));
        assert!(sql.contains("`name` varchar(191) not null unique"));
        assert!(sql.contains("`data` json not null"));
        assert!(sql.contains("`when` timestamp(3) not null"));
    }
}
