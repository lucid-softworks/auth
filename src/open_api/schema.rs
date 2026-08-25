use super::{FieldSchema, FieldSchemaKind, types::json_object};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn convert(schema: &FieldSchema) -> Value {
    let mut value = convert_kind(&schema.kind);
    let object = value.as_object_mut().expect("OpenAPI schemas are objects");
    for (key, value) in &schema.metadata {
        object.insert(key.clone(), value.clone());
    }
    if let Some(description) = &schema.description {
        object.insert("description".into(), Value::String(description.clone()));
    }
    value
}

fn convert_kind(kind: &FieldSchemaKind) -> Value {
    match kind {
        FieldSchemaKind::String {
            min_length,
            max_length,
        } => {
            let mut value = json!({ "type": "string" });
            let object = value.as_object_mut().expect("object");
            if let Some(length) = min_length {
                object.insert("minLength".into(), (*length).into());
            }
            if let Some(length) = max_length {
                object.insert("maxLength".into(), (*length).into());
            }
            value
        }
        FieldSchemaKind::Number => json!({ "type": "number" }),
        FieldSchemaKind::Boolean => json!({ "type": "boolean" }),
        FieldSchemaKind::Array(items) => json!({
            "type": "array",
            "items": convert(items),
        }),
        FieldSchemaKind::Object(fields) => object_schema(fields),
        FieldSchemaKind::Record { key, value } => json!({
            "type": "object",
            "propertyNames": convert(key),
            "additionalProperties": convert(value),
        }),
        FieldSchemaKind::Intersection(left, right) => intersection(left, right),
        FieldSchemaKind::Union { options, exclusive } => union(options, *exclusive),
        FieldSchemaKind::Literal(values) => json!({ "enum": values }),
        FieldSchemaKind::Enum(values) => json!({ "type": "string", "enum": values }),
        FieldSchemaKind::Optional(inner)
        | FieldSchemaKind::Default(inner)
        | FieldSchemaKind::Prefault(inner)
        | FieldSchemaKind::NonOptional(inner) => convert(inner),
        FieldSchemaKind::Nullable(inner) => nullable(convert(inner)),
        FieldSchemaKind::Catch(inner) | FieldSchemaKind::Readonly(inner) => convert(inner),
        FieldSchemaKind::Pipe {
            input,
            output,
            transform_input,
        } => convert(if *transform_input { output } else { input }),
        FieldSchemaKind::Any
        | FieldSchemaKind::Unknown
        | FieldSchemaKind::Undefined
        | FieldSchemaKind::Void => json!({}),
        FieldSchemaKind::Null => json!({ "type": "null" }),
        FieldSchemaKind::Raw(value) => value.clone(),
    }
}

fn object_schema(fields: &BTreeMap<String, FieldSchema>) -> Value {
    let properties = fields
        .iter()
        .map(|(name, field)| (name.clone(), convert(field)))
        .collect::<Map<_, _>>();
    let required = fields
        .iter()
        .filter(|(_, field)| !field.accepts_undefined())
        .map(|(name, _)| Value::String(name.clone()))
        .collect::<Vec<_>>();
    let mut value = json!({ "type": "object", "properties": properties });
    if !required.is_empty() {
        value
            .as_object_mut()
            .expect("object")
            .insert("required".into(), Value::Array(required));
    }
    value
}

fn nullable(mut schema: Value) -> Value {
    let Some(object) = schema.as_object_mut() else {
        return json!({ "anyOf": [schema, { "type": "null" }] });
    };
    match object.get_mut("type") {
        Some(Value::String(schema_type)) => {
            *object.get_mut("type").expect("present") = json!([schema_type.clone(), "null"]);
        }
        Some(Value::Array(types)) => {
            if !types.iter().any(|value| value == "null") {
                types.push(Value::String("null".into()));
            }
        }
        _ => return json!({ "anyOf": [schema, { "type": "null" }] }),
    }
    schema
}

fn union(options: &[FieldSchema], exclusive: bool) -> Value {
    let converted = options
        .iter()
        .filter(|schema| {
            !matches!(
                schema.kind,
                FieldSchemaKind::Undefined | FieldSchemaKind::Void
            )
        })
        .map(convert)
        .collect::<Vec<_>>();
    match converted.as_slice() {
        [] => json!({}),
        [only] => only.clone(),
        _ if exclusive => json!({ "oneOf": converted }),
        _ => json!({ "anyOf": converted }),
    }
}

fn intersection(left: &FieldSchema, right: &FieldSchema) -> Value {
    let left = convert(left);
    let right = convert(right);
    merge_object_schemas(&left, &right).unwrap_or_else(|| json!({ "allOf": [left, right] }))
}

fn merge_object_schemas(left: &Value, right: &Value) -> Option<Value> {
    let left = left.as_object()?;
    let right = right.as_object()?;
    if !object_type(left.get("type"))
        || !object_type(right.get("type"))
        || ["$ref", "allOf", "anyOf"]
            .iter()
            .any(|key| left.contains_key(*key) || right.contains_key(*key))
    {
        return None;
    }
    let mut properties = left
        .get("properties")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, value) in right
        .get("properties")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        if properties
            .get(name)
            .is_some_and(|existing| existing != value)
        {
            return None;
        }
        properties.insert(name.clone(), value.clone());
    }
    for key in ["additionalProperties", "propertyNames"] {
        if let (Some(left), Some(right)) = (left.get(key), right.get(key))
            && left != right
        {
            return None;
        }
    }
    let required = left
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .chain(right.get("required").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    let nullable = allows_null(left.get("type")) && allows_null(right.get("type"));
    let mut entries = vec![
        (
            "type".into(),
            if nullable {
                json!(["object", "null"])
            } else {
                json!("object")
            },
        ),
        ("properties".into(), Value::Object(properties)),
    ];
    if !required.is_empty() {
        entries.push(("required".into(), json!(required)));
    }
    for key in ["additionalProperties", "propertyNames"] {
        if let Some(value) = left.get(key).or_else(|| right.get(key)) {
            entries.push((key.into(), value.clone()));
        }
    }
    Some(json_object(entries))
}

fn object_type(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(value)) => value == "object",
        Some(Value::Array(values)) => values.iter().any(|value| value == "object"),
        _ => false,
    }
}

fn allows_null(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value == "null"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_api::{FieldSchema, FieldSchemaKind};

    fn schema(kind: FieldSchemaKind) -> FieldSchema {
        FieldSchema::new(kind)
    }

    fn string() -> FieldSchema {
        schema(FieldSchemaKind::String {
            min_length: None,
            max_length: None,
        })
    }

    #[test]
    fn optional_and_nullable_are_distinct() {
        let optional = schema(FieldSchemaKind::Optional(Box::new(string())));
        let nullable = schema(FieldSchemaKind::Nullable(Box::new(string())));
        assert_eq!(convert(&optional), json!({ "type": "string" }));
        assert_eq!(convert(&nullable), json!({ "type": ["string", "null"] }));
        assert!(optional.accepts_undefined());
        assert!(!nullable.accepts_undefined());
    }

    #[test]
    fn object_record_array_and_required_fields_match_zod_conversion() {
        let object = schema(FieldSchemaKind::Object(BTreeMap::from([
            ("required".into(), string()),
            (
                "optional".into(),
                schema(FieldSchemaKind::Optional(Box::new(schema(
                    FieldSchemaKind::Boolean,
                )))),
            ),
            (
                "items".into(),
                schema(FieldSchemaKind::Array(Box::new(schema(
                    FieldSchemaKind::Number,
                )))),
            ),
            (
                "record".into(),
                schema(FieldSchemaKind::Record {
                    key: Box::new(string()),
                    value: Box::new(schema(FieldSchemaKind::Boolean)),
                }),
            ),
        ])));
        let converted = convert(&object);
        assert_eq!(
            converted["required"],
            json!(["items", "record", "required"])
        );
        assert_eq!(converted["properties"]["items"]["items"]["type"], "number");
        assert_eq!(
            converted["properties"]["record"],
            json!({
                "type": "object",
                "propertyNames": { "type": "string" },
                "additionalProperties": { "type": "boolean" },
            })
        );
    }

    #[test]
    fn compatible_intersections_merge_and_incompatible_ones_use_all_of() {
        let merged = schema(FieldSchemaKind::Intersection(
            Box::new(schema(FieldSchemaKind::Object(BTreeMap::from([(
                "left".into(),
                string(),
            )])))),
            Box::new(schema(FieldSchemaKind::Object(BTreeMap::from([(
                "right".into(),
                schema(FieldSchemaKind::Number),
            )])))),
        ));
        assert_eq!(
            convert(&merged),
            json!({
                "type": "object",
                "properties": {
                    "left": { "type": "string" },
                    "right": { "type": "number" },
                },
                "required": ["left", "right"],
            })
        );

        let incompatible = schema(FieldSchemaKind::Intersection(
            Box::new(string()),
            Box::new(schema(FieldSchemaKind::Number)),
        ));
        assert_eq!(
            convert(&incompatible),
            json!({ "allOf": [{ "type": "string" }, { "type": "number" }] })
        );
    }

    #[test]
    fn unions_drop_undefined_collapse_and_preserve_exclusivity() {
        let collapsed = schema(FieldSchemaKind::Union {
            options: vec![schema(FieldSchemaKind::Undefined), string()],
            exclusive: false,
        });
        assert_eq!(convert(&collapsed), json!({ "type": "string" }));
        assert!(collapsed.accepts_undefined());

        let exclusive = schema(FieldSchemaKind::Union {
            options: vec![string(), schema(FieldSchemaKind::Number)],
            exclusive: true,
        });
        assert_eq!(
            convert(&exclusive),
            json!({ "oneOf": [{ "type": "string" }, { "type": "number" }] })
        );
    }

    #[test]
    fn pipes_wrappers_metadata_and_bounds_match_171() {
        let bounded = schema(FieldSchemaKind::String {
            min_length: Some(2),
            max_length: Some(9),
        })
        .described("bounded")
        .with_metadata("format", json!("email"))
        .with_metadata("deprecated", json!(true));
        let pipe = schema(FieldSchemaKind::Pipe {
            input: Box::new(schema(FieldSchemaKind::Number)),
            output: Box::new(bounded),
            transform_input: true,
        });
        assert_eq!(
            convert(&pipe),
            json!({
                "type": "string",
                "minLength": 2,
                "maxLength": 9,
                "description": "bounded",
                "format": "email",
                "deprecated": true,
            })
        );
        for kind in [
            FieldSchemaKind::Any,
            FieldSchemaKind::Unknown,
            FieldSchemaKind::Undefined,
            FieldSchemaKind::Void,
        ] {
            assert_eq!(convert(&schema(kind)), json!({}));
        }
        assert_eq!(
            convert(&schema(FieldSchemaKind::Null)),
            json!({ "type": "null" })
        );
    }
}
