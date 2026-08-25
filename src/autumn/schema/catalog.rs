use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, sync::LazyLock};

pub(super) static CATALOG: LazyLock<Catalog> = LazyLock::new(|| {
    serde_json::from_str(include_str!("sdk-0.10.18.json"))
        .expect("the generated Autumn SDK schema catalog is valid")
});

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Catalog {
    #[allow(dead_code)]
    pub generated_from: String,
    pub roots: BTreeMap<String, usize>,
    pub nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub(super) enum Node {
    #[serde(rename = "any")]
    Any,
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "boolean")]
    Boolean,
    #[serde(rename = "string")]
    String { format: Option<String> },
    #[serde(rename = "number")]
    Number { format: Option<String> },
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "undefined")]
    Undefined,
    #[serde(rename = "literal")]
    Literal { values: Vec<Value> },
    #[serde(rename = "nullable")]
    Nullable { inner: usize },
    #[serde(rename = "optional")]
    Optional { inner: usize },
    #[serde(rename = "default")]
    Default { inner: usize, value: Value },
    #[serde(rename = "zeroDefault")]
    ZeroDefault { value: Value },
    #[serde(rename = "array")]
    Array { element: usize },
    #[serde(rename = "record")]
    Record { key: usize, value: usize },
    #[serde(rename = "union")]
    Union { options: Vec<usize> },
    #[serde(rename = "smartUnion")]
    SmartUnion { options: Vec<usize> },
    #[serde(rename = "intersection")]
    Intersection { left: usize, right: usize },
    #[serde(rename = "object")]
    Object { fields: Vec<Field> },
    #[serde(rename = "unrecognized")]
    Unrecognized { inner: usize },
    #[serde(rename = "reference")]
    Reference { inner: usize },
    #[serde(rename = "toUndefined")]
    ToUndefined { inner: usize },
    #[serde(rename = "coerceNumber")]
    CoerceNumber { inner: usize },
    #[serde(rename = "coerceBoolean")]
    CoerceBoolean { inner: usize },
    #[serde(rename = "jsonStringify")]
    JsonStringify { inner: usize },
}

#[derive(Debug, Deserialize)]
pub(super) struct Field {
    pub input: String,
    pub output: String,
    pub schema: usize,
}
