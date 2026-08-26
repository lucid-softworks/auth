use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;

/// Theme supported by Polar checkout and customer-portal URLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolarTheme {
    Light,
    Dark,
}

impl PolarTheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

/// Product-id to slug mapping accepted by the Polar checkout feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolarProduct {
    pub product_id: String,
    pub slug: String,
}

impl PolarProduct {
    pub fn new(product_id: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            product_id: product_id.into(),
            slug: slug.into(),
        }
    }
}

/// Primitive value allowed by Polar customer and checkout metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolarPrimitive {
    String(String),
    Number(Number),
    Boolean(bool),
}

impl From<PolarPrimitive> for Value {
    fn from(value: PolarPrimitive) -> Self {
        match value {
            PolarPrimitive::String(value) => Self::String(value),
            PolarPrimitive::Number(value) => Self::Number(value),
            PolarPrimitive::Boolean(value) => Self::Bool(value),
        }
    }
}

pub type PolarPrimitiveMetadata = BTreeMap<String, PolarPrimitive>;

pub(crate) fn metadata_to_json(metadata: PolarPrimitiveMetadata) -> Map<String, Value> {
    metadata
        .into_iter()
        .map(|(key, value)| (key, value.into()))
        .collect()
}

/// User data visible during Better Auth's ID-less before-create phase.
#[derive(Debug, Clone, PartialEq)]
pub struct PolarUser {
    pub id: Option<String>,
    pub name: String,
    pub email: String,
    pub is_anonymous: bool,
    pub fields: Map<String, Value>,
}

impl PolarUser {
    pub(crate) fn from_record(record: &crate::DatabaseCreateRecord) -> Self {
        Self {
            id: string_id(record),
            name: string_field(record, "name"),
            email: string_field(record, "email"),
            is_anonymous: record
                .get("isAnonymous")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            fields: record.fields().clone(),
        }
    }
}

fn string_id(record: &crate::DatabaseCreateRecord) -> Option<String> {
    match record.id() {
        crate::store::DatabaseIdInput::String(id) => Some(id.clone()),
        _ => None,
    }
}

fn string_field(record: &crate::DatabaseCreateRecord, field: &str) -> String {
    record
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DatabaseCreateRecord, DatabaseModel};
    use serde_json::json;

    #[test]
    fn create_callback_user_preserves_the_idless_complete_draft() {
        let fields = Map::from_iter([
            ("name".into(), json!("Ada")),
            ("email".into(), json!("ada@example.com")),
            ("isAnonymous".into(), json!(false)),
            ("customDraft".into(), json!({ "nested": true })),
        ]);
        let user = PolarUser::from_record(&DatabaseCreateRecord::new(
            DatabaseModel::User,
            fields.clone(),
        ));

        assert_eq!(user.id, None);
        assert_eq!(user.name, "Ada");
        assert_eq!(user.email, "ada@example.com");
        assert_eq!(user.fields, fields);
    }
}
