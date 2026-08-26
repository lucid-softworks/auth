use super::{PhysicalModel, quote, schema_error};
use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldType, AuthError, DatabaseIdType,
    ResolvedAdapterSchema,
};
#[cfg(test)]
use indexmap::IndexMap;

#[cfg(test)]
pub(super) fn render_migration(
    schema: &ResolvedAdapterSchema,
    models: &IndexMap<String, PhysicalModel>,
) -> Result<String, AuthError> {
    let mut statements = Vec::new();
    for model in models.values().filter(|model| !model.disable_migrations) {
        statements.push(create_table(schema, model)?);
    }
    for model in models.values().filter(|model| !model.disable_migrations) {
        if let Some(indexes) = schema.field_indexes_by_table().get(&model.table) {
            statements.extend(indexes.iter().filter(|index| !index.unique).map(|index| {
                create_index(&model.table, &index.name, &index.columns, index.unique)
            }));
        }
        if let Some(indexes) = schema.indexes_by_table().get(&model.table) {
            statements.extend(indexes.iter().map(|index| {
                create_index(&model.table, &index.name, &index.columns, index.unique)
            }));
        }
    }
    Ok(format!("{};\n", statements.join(";\n")))
}

pub(super) fn create_table(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
) -> Result<String, AuthError> {
    let mut definitions = vec![format!(
        "\"id\" {} PRIMARY KEY",
        id_column_sql(model.id_type)
    )];
    for (column, physical) in &model.columns {
        let field = &physical.field;
        let definition = create_column_definition(schema, column, field)?;
        definitions.push(definition);
    }
    Ok(format!(
        "CREATE TABLE {} (\n  {}\n)",
        quote(&model.table),
        definitions.join(",\n  ")
    ))
}

pub(super) fn create_column_definition(
    schema: &ResolvedAdapterSchema,
    column: &str,
    field: &AdditionalField,
) -> Result<String, AuthError> {
    column_definition(schema, column, field, true, create_table_default(field))
}

pub(super) fn add_column_definition(
    schema: &ResolvedAdapterSchema,
    column: &str,
    field: &AdditionalField,
) -> Result<String, AuthError> {
    column_definition(schema, column, field, false, add_column_default(field))
}

fn column_definition(
    schema: &ResolvedAdapterSchema,
    column: &str,
    field: &AdditionalField,
    inline_unique: bool,
    default: Option<String>,
) -> Result<String, AuthError> {
    let mut definition = format!("{} {}", quote(column), sql_type(schema, field));
    if field.required {
        definition.push_str(" NOT NULL");
    }
    if inline_unique && field.unique {
        definition.push_str(" UNIQUE");
    }
    if let Some(default) = default {
        definition.push_str(" DEFAULT ");
        definition.push_str(&default);
    }
    if let Some(reference) = &field.references {
        let (target_table, target_field) =
            schema_error(schema.adapter_reference_names(&reference.model, &reference.field))?;
        definition.push_str(&format!(
            " REFERENCES {}({}){}",
            quote(&target_table),
            quote(&target_field),
            on_delete(reference.on_delete)
        ));
    }
    Ok(definition)
}

pub(super) fn create_index(table: &str, name: &str, columns: &[String], unique: bool) -> String {
    format!(
        "CREATE {}INDEX {} ON {} ({})",
        if unique { "UNIQUE " } else { "" },
        quote(name),
        quote(table),
        columns
            .iter()
            .map(|column| quote(column))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn sql_type(schema: &ResolvedAdapterSchema, field: &AdditionalField) -> &'static str {
    if let Some(id_type) = reference_id_type(schema, field) {
        return id_sql_type(id_type);
    }
    match field.field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => "TEXT",
        AdditionalFieldType::Number if field.bigint => "BIGINT",
        AdditionalFieldType::Number => "INTEGER",
        AdditionalFieldType::Boolean => "BOOLEAN",
        AdditionalFieldType::Date => "TIMESTAMPTZ",
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => "JSONB",
    }
}

pub(super) fn catalog_type(
    schema: &ResolvedAdapterSchema,
    field: &AdditionalField,
) -> &'static str {
    if let Some(id_type) = reference_id_type(schema, field) {
        return id_catalog_type(id_type);
    }
    match field.field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => "text",
        AdditionalFieldType::Number if field.bigint => "bigint",
        AdditionalFieldType::Number => "integer",
        AdditionalFieldType::Boolean => "boolean",
        AdditionalFieldType::Date => "timestamp with time zone",
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => "jsonb",
    }
}

fn reference_id_type(
    schema: &ResolvedAdapterSchema,
    field: &AdditionalField,
) -> Option<DatabaseIdType> {
    let reference = field
        .references
        .as_ref()
        .filter(|value| value.field == "id")?;
    schema
        .catalog()
        .table(&reference.model)
        .map(|table| table.id_type)
}

fn id_sql_type(id_type: DatabaseIdType) -> &'static str {
    match id_type {
        DatabaseIdType::String => "TEXT",
        DatabaseIdType::Serial => "INTEGER",
        DatabaseIdType::Uuid => "UUID",
    }
}

fn id_catalog_type(id_type: DatabaseIdType) -> &'static str {
    match id_type {
        DatabaseIdType::String => "text",
        DatabaseIdType::Serial => "integer",
        DatabaseIdType::Uuid => "uuid",
    }
}

fn id_column_sql(id_type: DatabaseIdType) -> &'static str {
    match id_type {
        DatabaseIdType::String => "TEXT",
        DatabaseIdType::Serial => "INTEGER GENERATED BY DEFAULT AS IDENTITY",
        DatabaseIdType::Uuid => "UUID DEFAULT pg_catalog.gen_random_uuid()",
    }
}

fn create_table_default(field: &AdditionalField) -> Option<String> {
    (field.field_type == AdditionalFieldType::Date && field.has_default_factory())
        .then(|| "CURRENT_TIMESTAMP".into())
}

pub(super) fn add_column_default(field: &AdditionalField) -> Option<String> {
    if let Some(default) = create_table_default(field) {
        return Some(default);
    }
    if !field.required && field.unique {
        return None;
    }
    let value = field.static_default_value()?;
    match (&field.field_type, value) {
        (AdditionalFieldType::String, serde_json::Value::String(value)) => {
            Some(format!("'{}'", value.replace('\'', "''")))
        }
        (AdditionalFieldType::Number, serde_json::Value::Number(value)) => Some(value.to_string()),
        (AdditionalFieldType::Boolean, serde_json::Value::Bool(value)) => Some(if *value {
            "TRUE".into()
        } else {
            "FALSE".into()
        }),
        _ => None,
    }
}

fn on_delete(action: Option<AdditionalFieldOnDelete>) -> &'static str {
    match action {
        None | Some(AdditionalFieldOnDelete::Cascade) => " ON DELETE CASCADE",
        Some(AdditionalFieldOnDelete::NoAction) => "",
        Some(AdditionalFieldOnDelete::Restrict) => " ON DELETE RESTRICT",
        Some(AdditionalFieldOnDelete::SetNull) => " ON DELETE SET NULL",
        Some(AdditionalFieldOnDelete::SetDefault) => " ON DELETE SET DEFAULT",
    }
}
