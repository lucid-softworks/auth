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

/// Complete user value passed to `getCustomerCreateParams` by the adapter.
/// The alias preserves Better Auth custom fields instead of narrowing the
/// callback to only the fields used internally by Polar customer creation.
pub type PolarUser = crate::AuthUser;
