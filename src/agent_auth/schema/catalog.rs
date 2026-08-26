use super::{
    AgentAuthModel, AgentAuthModelSchema, AgentAuthSchema, DEFINITIONS, FieldDefinition,
    ModelDefinition, Reference,
};
use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldReference, AdditionalFieldType,
    DatabaseIdType, PluginSchemaTable,
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(crate) fn schema_tables(schema: &AgentAuthSchema) -> Vec<PluginSchemaTable> {
    DEFINITIONS
        .iter()
        .map(|definition| table(definition, config(schema, definition.model)))
        .collect()
}

fn table(definition: &ModelDefinition, config: &AgentAuthModelSchema) -> PluginSchemaTable {
    let model = definition.model;
    let mut table = PluginSchemaTable::new(definition.logical_name).id_type(DatabaseIdType::String);
    if let Some(model_name) = config.model_name.as_deref().filter(|name| !name.is_empty()) {
        table = table.model_name(model_name);
    }
    for definition in definition.fields {
        let mut field = field(definition, model);
        if let Some(physical) = config
            .fields
            .get(definition.logical)
            .filter(|name| !name.is_empty())
        {
            field = field.field_name(physical);
        }
        table = table.field(definition.logical, field);
    }
    table
}

fn field(definition: &FieldDefinition, model: AgentAuthModel) -> AdditionalField {
    let mut field = AdditionalField::new(field_type(model, definition.logical));
    if !required(model, definition.logical) {
        field = field.optional();
    }
    field = field.input(model == AgentAuthModel::Agent && definition.logical == "metadata");
    if definition.index {
        field = field.index(true);
    }
    if definition.logical == "status" {
        field = field.default_value(if model == AgentAuthModel::ApprovalRequest {
            json!("pending")
        } else {
            json!("active")
        });
    } else if model == AgentAuthModel::Agent && definition.logical == "mode" {
        field = field.default_value(json!("delegated"));
    }
    if matches!(
        definition.logical,
        "defaultCapabilities" | "metadata" | "constraints"
    ) {
        field = json_string(
            field,
            definition.logical == "defaultCapabilities",
            definition.logical == "constraints",
        );
    }
    if let Some(reference) = definition.reference {
        let model = match reference {
            Reference::CoreUser => "user",
            Reference::AgentAuth(model) => logical_name(model),
        };
        field = field.references(AdditionalFieldReference {
            model: model.into(),
            field: "id".into(),
            on_delete: Some(AdditionalFieldOnDelete::Cascade),
        });
    }
    field
}

fn field_type(model: AgentAuthModel, logical: &str) -> AdditionalFieldType {
    if matches!(
        logical,
        "enrollmentTokenExpiresAt"
            | "activatedAt"
            | "expiresAt"
            | "lastUsedAt"
            | "createdAt"
            | "updatedAt"
            | "lastPolledAt"
    ) {
        AdditionalFieldType::Date
    } else if model == AgentAuthModel::ApprovalRequest && logical == "interval" {
        AdditionalFieldType::Number
    } else {
        AdditionalFieldType::String
    }
}

fn required(model: AgentAuthModel, logical: &str) -> bool {
    match model {
        AgentAuthModel::AgentHost => matches!(logical, "status" | "createdAt" | "updatedAt"),
        AgentAuthModel::Agent => matches!(
            logical,
            "name" | "hostId" | "status" | "mode" | "publicKey" | "createdAt" | "updatedAt"
        ),
        AgentAuthModel::AgentCapabilityGrant => {
            matches!(
                logical,
                "agentId" | "capability" | "createdAt" | "updatedAt" | "status"
            )
        }
        AgentAuthModel::ApprovalRequest => matches!(
            logical,
            "method" | "status" | "interval" | "expiresAt" | "createdAt" | "updatedAt"
        ),
    }
}

fn json_string(
    field: AdditionalField,
    empty_array_fallback: bool,
    pass_strings_through: bool,
) -> AdditionalField {
    field
        .transform_input(Arc::new(move |value: Value| {
            json_string_input(value, pass_strings_through)
        }))
        .transform_output(Arc::new(move |value: Value| {
            if !json_truthy(&value) {
                return Ok(if empty_array_fallback {
                    json!([])
                } else {
                    Value::Null
                });
            }
            let Some(value) = value.as_str() else {
                return Ok(value);
            };
            Ok(serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_owned())))
        }))
}

fn json_string_input(value: Value, pass_strings_through: bool) -> Result<Value, crate::AuthError> {
    if pass_strings_through && value.is_string() {
        return Ok(value);
    }
    serde_json::to_string(&value)
        .map(Value::String)
        .map_err(|error| crate::AuthError::InvalidRequest(error.to_string()))
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) | Value::Bool(true) => true,
    }
}

fn logical_name(model: AgentAuthModel) -> &'static str {
    DEFINITIONS
        .iter()
        .find(|definition| definition.model == model)
        .expect("every Agent Auth model has one definition")
        .logical_name
}

fn config(schema: &AgentAuthSchema, model: AgentAuthModel) -> &AgentAuthModelSchema {
    match model {
        AgentAuthModel::AgentHost => &schema.agent_host,
        AgentAuthModel::Agent => &schema.agent,
        AgentAuthModel::AgentCapabilityGrant => &schema.agent_capability_grant,
        AgentAuthModel::ApprovalRequest => &schema.approval_request,
    }
}

#[cfg(test)]
#[path = "catalog/contract.rs"]
mod catalog_contract;
