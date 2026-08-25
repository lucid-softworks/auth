use crate::{AdditionalField, AdditionalFieldType};
use serde_json::{Value, json};

pub(super) fn request_field_schema(field: &AdditionalField) -> Value {
    let mut schema = match field.field_type {
        AdditionalFieldType::Date => json!({ "type": "string", "format": "date-time" }),
        AdditionalFieldType::Json => json!({}),
        AdditionalFieldType::StringArray => {
            json!({ "type": "array", "items": { "type": "string" } })
        }
        AdditionalFieldType::NumberArray => {
            json!({ "type": "array", "items": { "type": "number" } })
        }
        AdditionalFieldType::StringLiteral(values) => {
            json!({ "type": "string", "enum": values })
        }
        primitive => json!({ "type": primitive_name(primitive) }),
    };
    if let Some(default) = field.static_default_value() {
        schema
            .as_object_mut()
            .expect("field schema is object")
            .insert("default".into(), default.clone());
    }
    schema
}

pub(super) fn model_field_schema(field: &AdditionalField) -> Value {
    let mut schema = match field.field_type {
        AdditionalFieldType::Date => json!({ "type": "string", "format": "date-time" }),
        AdditionalFieldType::StringArray => {
            json!({ "type": "array", "items": { "type": "string" } })
        }
        AdditionalFieldType::NumberArray => {
            json!({ "type": "array", "items": { "type": "number" } })
        }
        AdditionalFieldType::StringLiteral(values) => json!({ "type": values }),
        primitive => json!({ "type": primitive_name(primitive) }),
    };
    let object = schema.as_object_mut().expect("field schema is object");
    if let Some(default) = field.static_default_value() {
        object.insert("default".into(), default.clone());
    }
    if !field.input {
        object.insert("readOnly".into(), true.into());
    }
    schema
}

const fn primitive_name(field_type: AdditionalFieldType) -> &'static str {
    match field_type {
        AdditionalFieldType::String => "string",
        AdditionalFieldType::Number => "number",
        AdditionalFieldType::Boolean => "boolean",
        AdditionalFieldType::Json => "json",
        AdditionalFieldType::Date
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray
        | AdditionalFieldType::StringLiteral(_) => unreachable!(),
    }
}
