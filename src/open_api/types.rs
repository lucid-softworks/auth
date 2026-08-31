use crate::PluginHttpMethod;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Better Auth's OpenAPI 3.1 document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiSchema {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub components: OpenApiComponents,
    pub security: Vec<BTreeMap<String, Vec<String>>>,
    pub servers: Vec<OpenApiServer>,
    pub tags: Vec<OpenApiTag>,
    pub paths: BTreeMap<String, OpenApiPath>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub description: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiComponents {
    pub schemas: BTreeMap<String, OpenApiModelSchema>,
    pub security_schemes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiServer {
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiTag {
    pub name: String,
    pub description: String,
}

/// Operations keyed by lowercase HTTP method.
pub type OpenApiPath = BTreeMap<String, OpenApiOperation>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiOperation {
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub security: Vec<BTreeMap<String, Vec<String>>>,
    pub parameters: Vec<OpenApiParameter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<OpenApiRequestBody>,
    pub responses: BTreeMap<String, OpenApiResponse>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiParameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    pub schema: Value,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl OpenApiParameter {
    pub fn new(name: impl Into<String>, location: impl Into<String>, schema: Value) -> Self {
        Self {
            name: name.into(),
            location: location.into(),
            required: None,
            schema,
            extensions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenApiRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    pub content: BTreeMap<String, OpenApiMediaType>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiMediaType {
    pub schema: Value,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiResponse {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<BTreeMap<String, OpenApiMediaType>>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenApiModelSchema {
    #[serde(rename = "type")]
    pub schema_type: String,
    pub properties: BTreeMap<String, Value>,
    pub required: Vec<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

/// Native input-schema vocabulary converted with Better Auth 1.7.2 semantics.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSchema {
    pub kind: FieldSchemaKind,
    pub description: Option<String>,
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldSchemaKind {
    String {
        min_length: Option<u64>,
        max_length: Option<u64>,
    },
    Number,
    Boolean,
    Array(Box<FieldSchema>),
    Object(BTreeMap<String, FieldSchema>),
    Record {
        key: Box<FieldSchema>,
        value: Box<FieldSchema>,
    },
    Intersection(Box<FieldSchema>, Box<FieldSchema>),
    Union {
        options: Vec<FieldSchema>,
        exclusive: bool,
    },
    Literal(Vec<Value>),
    Enum(Vec<String>),
    Optional(Box<FieldSchema>),
    Nullable(Box<FieldSchema>),
    Default(Box<FieldSchema>),
    Prefault(Box<FieldSchema>),
    Catch(Box<FieldSchema>),
    Readonly(Box<FieldSchema>),
    NonOptional(Box<FieldSchema>),
    Pipe {
        input: Box<FieldSchema>,
        output: Box<FieldSchema>,
        transform_input: bool,
    },
    Any,
    Unknown,
    Undefined,
    Void,
    Null,
    Raw(Value),
}

impl FieldSchema {
    pub fn new(kind: FieldSchemaKind) -> Self {
        Self {
            kind,
            description: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn described(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    pub fn accepts_undefined(&self) -> bool {
        match &self.kind {
            FieldSchemaKind::Optional(_)
            | FieldSchemaKind::Default(_)
            | FieldSchemaKind::Prefault(_)
            | FieldSchemaKind::Catch(_)
            | FieldSchemaKind::Any
            | FieldSchemaKind::Unknown
            | FieldSchemaKind::Undefined
            | FieldSchemaKind::Void => true,
            FieldSchemaKind::NonOptional(_) => false,
            FieldSchemaKind::Nullable(inner) | FieldSchemaKind::Readonly(inner) => {
                inner.accepts_undefined()
            }
            FieldSchemaKind::Pipe {
                input,
                output,
                transform_input,
            } => {
                if *transform_input {
                    output.accepts_undefined()
                } else {
                    input.accepts_undefined()
                }
            }
            FieldSchemaKind::Union { options, .. } => {
                options.iter().any(FieldSchema::accepts_undefined)
            }
            FieldSchemaKind::Intersection(left, right) => {
                left.accepts_undefined() && right.accepts_undefined()
            }
            _ => false,
        }
    }

    pub fn to_open_api_value(&self) -> Value {
        crate::open_api::schema::convert(self)
    }
}

impl Serialize for FieldSchema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_open_api_value().serialize(serializer)
    }
}

/// OpenAPI details contributed by a native endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenApiEndpoint {
    pub path: String,
    pub methods: Vec<PluginHttpMethod>,
    pub server_only: bool,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub operation_id: Option<String>,
    pub parameters: Option<Vec<OpenApiParameter>>,
    pub query: Option<FieldSchema>,
    pub body: Option<FieldSchema>,
    pub request_body: Option<OpenApiRequestBody>,
    pub responses: BTreeMap<String, OpenApiResponse>,
}

impl OpenApiEndpoint {
    pub fn new(path: impl Into<String>, methods: impl Into<Vec<PluginHttpMethod>>) -> Self {
        Self {
            path: path.into(),
            methods: methods.into(),
            server_only: false,
            tags: Vec::new(),
            description: None,
            operation_id: None,
            parameters: None,
            query: None,
            body: None,
            request_body: None,
            responses: BTreeMap::new(),
        }
    }
}

/// Additional database model exposed by a plugin in the generated components.
#[derive(Debug, Clone)]
pub struct OpenApiModel {
    pub name: String,
    pub fields: BTreeMap<String, crate::AdditionalField>,
}

pub(crate) fn json_object(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Object(Map::from_iter(entries))
}

pub(crate) fn endpoints_from_descriptor(
    descriptor: &crate::PluginDescriptor,
) -> Vec<OpenApiEndpoint> {
    descriptor
        .endpoints
        .iter()
        .map(|endpoint| OpenApiEndpoint::new(endpoint.path.as_ref(), vec![endpoint.method]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_client_map_keys_are_not_invented_openapi_operation_ids() {
        let descriptor = crate::PluginDescriptor {
            id: "contract",
            display_name: "Contract",
            version: "1",
            provenance: crate::PluginProvenance::lucid_extension(),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Owned(vec![crate::PluginEndpoint {
                method: PluginHttpMethod::Get,
                path: std::borrow::Cow::Borrowed("/contract"),
                client_method: "namespace.contract",
            }]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        };
        let endpoints = endpoints_from_descriptor(&descriptor);
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].operation_id, None);
    }
}
