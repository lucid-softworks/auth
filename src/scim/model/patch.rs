use crate::scim::{SCIM_PATCH_SCHEMA, ScimError, ScimErrorType};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ScimPatchRequest {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

impl ScimPatchRequest {
    pub fn validate(&self) -> Result<(), ScimError> {
        if self.schemas != [SCIM_PATCH_SCHEMA] {
            return Err(ScimError::typed(
                400,
                format!("schemas must contain only {SCIM_PATCH_SCHEMA}"),
                ScimErrorType::InvalidValue,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ScimPatchOperation {
    #[serde(default = "default_patch_operation")]
    pub op: String,
    pub path: Option<String>,
    pub value: Option<Value>,
}

fn default_patch_operation() -> String {
    "replace".into()
}
