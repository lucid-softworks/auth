use super::MssqlMigrationError;
use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldType, DatabaseIdType,
    ResolvedAdapterSchema,
    mssql::schema::{PhysicalModel, quote},
};

const MSSQL_INDEX_STRING_LENGTH: usize = 255;
const MSSQL_ORDINARY_STRING_LENGTH: usize = 8_000;

pub(super) fn create_table(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
) -> Result<String, MssqlMigrationError> {
    let mut definitions = vec![match model.id_type {
        DatabaseIdType::Serial => "[id] integer identity primary key not null".into(),
        DatabaseIdType::String | DatabaseIdType::Uuid => {
            "[id] varchar(36) primary key not null".into()
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
    for (column, physical) in &model.columns {
        if physical.field.references.is_some() {
            definitions.push(reference_definition(schema, column, &physical.field)?);
        }
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
) -> Result<String, MssqlMigrationError> {
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
        definition.push_str(" default CURRENT_TIMESTAMP");
    } else if add_column && let Some(default) = static_default(field) {
        definition.push_str(" default ");
        definition.push_str(&default);
    }
    if add_column && field.references.is_some() {
        definition.push_str(", add ");
        definition.push_str(&reference_definition(schema, column, field)?);
    }
    Ok(definition)
}

pub(super) fn create_index(
    table: &str,
    name: &str,
    columns: &[String],
    unique: bool,
    nullable_unique_column: Option<&str>,
) -> String {
    let mut sql = format!(
        "create {}index {} on {} ({})",
        if unique { "unique " } else { "" },
        quote(name),
        quote(table),
        columns
            .iter()
            .map(|column| quote(column))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if let Some(column) = nullable_unique_column {
        sql.push_str(" where ");
        sql.push_str(&quote(column));
        sql.push_str(" is not null");
    }
    sql
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
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            normalized == "varchar"
        }
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => normalized == "varchar",
        AdditionalFieldType::Number => matches!(
            normalized.as_str(),
            "integer" | "int" | "bigint"
        ),
        AdditionalFieldType::Boolean => normalized == "smallint",
        AdditionalFieldType::Date => normalized == "datetime2",
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
    let indexed = field.unique
        || field.index
        || field.sortable
        || schema
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
            .any(|index| index.columns.iter().any(|candidate| candidate == column));
    Some(if indexed {
        MSSQL_INDEX_STRING_LENGTH
    } else {
        MSSQL_ORDINARY_STRING_LENGTH
    })
}

fn sql_type(
    schema: &ResolvedAdapterSchema,
    model: &PhysicalModel,
    column: &str,
    field: &AdditionalField,
) -> String {
    if let Some(reference) = &field.references
        && let Some(table) = schema.catalog().table(&reference.model)
    {
        if reference.field == "id" {
            return id_type_sql(table.id_type).into();
        }
        if let Some(target) = table.fields.get(&reference.field)
            && target.field_type == AdditionalFieldType::String
        {
            return if target.unique || target.index || target.sortable {
                format!("varchar({MSSQL_INDEX_STRING_LENGTH})")
            } else {
                format!("varchar({MSSQL_ORDINARY_STRING_LENGTH})")
            };
        }
    }
    match field.field_type {
        AdditionalFieldType::String => generated_string_length(schema, model, column)
            .map(|length| format!("varchar({length})"))
            .unwrap_or_else(|| format!("varchar({MSSQL_ORDINARY_STRING_LENGTH})")),
        AdditionalFieldType::StringLiteral(_) => {
            format!("varchar({MSSQL_ORDINARY_STRING_LENGTH})")
        }
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => format!("varchar({MSSQL_ORDINARY_STRING_LENGTH})"),
        AdditionalFieldType::Boolean => "smallint".into(),
        AdditionalFieldType::Number if field.bigint => "bigint".into(),
        AdditionalFieldType::Number => "integer".into(),
        AdditionalFieldType::Date => "datetime2(3)".into(),
    }
}

fn reference_definition(
    schema: &ResolvedAdapterSchema,
    column: &str,
    field: &AdditionalField,
) -> Result<String, MssqlMigrationError> {
    let reference = field.references.as_ref().expect("reference is present");
    let (table, target) = schema
        .adapter_reference_names(&reference.model, &reference.field)
        .map_err(|error| MssqlMigrationError::Configuration(error.to_string()))?;
    Ok(format!(
        "foreign key ({}) references {} ({}){}",
        quote(column),
        quote(&table),
        quote(&target),
        on_delete(reference.on_delete)
    ))
}

fn id_type_sql(id_type: DatabaseIdType) -> &'static str {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => "varchar(36)",
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
        Some(AdditionalFieldOnDelete::Restrict) => "",
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
        let physical = crate::mssql::schema::MssqlSchema::new(&schema)
            .unwrap()
            .models()
            .find(|model| model.table == "widget")
            .unwrap()
            .clone();
        (schema, physical)
    }

    #[test]
    fn generates_mssql_types_and_serial_primary_keys() {
        let table = PluginSchemaTable::new("widget")
            .field("name", AdditionalField::new(AdditionalFieldType::String).unique(true))
            .field("data", AdditionalField::new(AdditionalFieldType::Json))
            .field("when", AdditionalField::new(AdditionalFieldType::Date));
        let (schema, model) = resolved(table, true);
        let sql = create_table(&schema, &model).unwrap();
        assert!(sql.contains("[id] integer identity primary key not null"));
        assert!(sql.contains("[name] varchar(255) not null unique"));
        assert!(sql.contains("[data] varchar(8000) not null"));
        assert!(sql.contains("[when] datetime2(3) not null"));
    }
}
