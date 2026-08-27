use super::SqliteMigrationError;
use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldType, DatabaseIdType,
    ResolvedAdapterSchema,
};

pub(super) use crate::sqlite::schema::quote;

pub(super) fn create_table(
    schema: &ResolvedAdapterSchema,
    model: &crate::sqlite::schema::PhysicalModel,
) -> Result<String, SqliteMigrationError> {
    let mut definitions = vec![format!(
        "\"id\" {} not null primary key",
        id_type(model.id_type)
    )];
    for (column, physical) in &model.columns {
        definitions.push(column_definition(
            schema,
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
    column: &str,
    field: &AdditionalField,
    inline_unique: bool,
    add_column: bool,
) -> Result<String, SqliteMigrationError> {
    let mut definition = format!("{} {}", quote(column), sql_type(schema, field));
    if field.required {
        definition.push_str(" not null");
    }
    if inline_unique && field.unique {
        definition.push_str(" unique");
    }
    if add_column && let Some(default) = static_default(field) {
        definition.push_str(" default ");
        definition.push_str(&default);
    }
    if let Some(reference) = &field.references {
        let (table, target) = schema
            .adapter_reference_names(&reference.model, &reference.field)
            .map_err(|error| SqliteMigrationError::Configuration(error.to_string()))?;
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

pub(super) fn type_matches(discovered: &str, expected: AdditionalFieldType) -> bool {
    if matches!(
        expected,
        AdditionalFieldType::StringArray | AdditionalFieldType::NumberArray
    ) {
        return discovered.to_lowercase().contains("json");
    }
    let normalized = discovered
        .to_lowercase()
        .split('(')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    match expected {
        AdditionalFieldType::String
        | AdditionalFieldType::StringLiteral(_)
        | AdditionalFieldType::Json => normalized == "text",
        AdditionalFieldType::Number => matches!(normalized.as_str(), "integer" | "real" | "bigint"),
        AdditionalFieldType::Boolean => matches!(normalized.as_str(), "integer" | "boolean"),
        AdditionalFieldType::Date => matches!(normalized.as_str(), "date" | "integer"),
        AdditionalFieldType::StringArray | AdditionalFieldType::NumberArray => unreachable!(),
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

fn sql_type(schema: &ResolvedAdapterSchema, field: &AdditionalField) -> &'static str {
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
        return id_type_sql(id_type);
    }
    match field.field_type {
        AdditionalFieldType::String
        | AdditionalFieldType::StringLiteral(_)
        | AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => "text",
        AdditionalFieldType::Boolean => "integer",
        AdditionalFieldType::Number if field.bigint => "bigint",
        AdditionalFieldType::Number => "integer",
        AdditionalFieldType::Date => "date",
    }
}

fn id_type(id_type: DatabaseIdType) -> &'static str {
    id_type_sql(id_type)
}

fn id_type_sql(id_type: DatabaseIdType) -> &'static str {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => "text",
        DatabaseIdType::Serial => "integer",
    }
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
