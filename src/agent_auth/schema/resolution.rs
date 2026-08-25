use super::{AgentAuthModel, AgentAuthModelSchema, AgentAuthSchema, DEFINITIONS, ModelDefinition};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentAuthSchemaError {
    #[error("unknown Better Auth Agent Auth field `{field}` on model `{model}`")]
    UnknownField { model: String, field: String },
    #[error("invalid {kind} identifier `{identifier}`: {reason}")]
    InvalidIdentifier {
        kind: &'static str,
        identifier: String,
        reason: &'static str,
    },
    #[error("duplicate {kind} identifier `{identifier}` in the Agent Auth schema")]
    DuplicateIdentifier {
        kind: &'static str,
        identifier: String,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedAgentAuthModel {
    table: Identifier,
    fields: BTreeMap<&'static str, Identifier>,
}

impl ResolvedAgentAuthModel {
    pub(crate) fn table(&self) -> &str {
        &self.table.quoted
    }

    pub(crate) fn column(&self, logical: &str) -> &str {
        if logical == "id" {
            return "\"id\"";
        }
        &self
            .fields
            .get(logical)
            .expect("Agent Auth SQL requested a declared Better Auth field")
            .quoted
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn columns(&self, fields: &[(&str, &str)]) -> String {
        fields
            .iter()
            .map(|(logical, _)| self.column(logical))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[cfg(feature = "postgres")]
    pub(crate) fn projection(&self, fields: &[(&str, &str)]) -> String {
        fields
            .iter()
            .map(|(logical, rust_name)| format!("{} AS \"{rust_name}\"", self.column(logical)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedAgentAuthSchema {
    models: BTreeMap<AgentAuthModel, ResolvedAgentAuthModel>,
    fingerprint: String,
}

impl ResolvedAgentAuthSchema {
    pub(crate) fn new(schema: &AgentAuthSchema) -> Result<Self, AgentAuthSchemaError> {
        let mut models = BTreeMap::new();
        let mut tables = BTreeSet::new();
        for definition in DEFINITIONS {
            let configured = configured_model(schema, definition.model);
            let table = Identifier::new(
                "model",
                configured
                    .model_name
                    .as_deref()
                    .unwrap_or(definition.default_table),
            )?;
            if !tables.insert(table.raw.clone()) {
                return Err(AgentAuthSchemaError::DuplicateIdentifier {
                    kind: "model",
                    identifier: table.raw,
                });
            }
            let fields = resolve_fields(definition, configured, &table)?;
            models.insert(definition.model, ResolvedAgentAuthModel { table, fields });
        }
        let fingerprint = schema_fingerprint(&models);
        Ok(Self {
            models,
            fingerprint,
        })
    }

    pub(crate) fn model(&self, model: AgentAuthModel) -> &ResolvedAgentAuthModel {
        self.models
            .get(&model)
            .expect("all Agent Auth models are resolved")
    }

    pub(crate) fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub(crate) fn migration_sql(&self) -> String {
        super::migration::render_migration(self)
    }
}

fn resolve_fields(
    definition: &ModelDefinition,
    configured: &AgentAuthModelSchema,
    table: &Identifier,
) -> Result<BTreeMap<&'static str, Identifier>, AgentAuthSchemaError> {
    let known = definition
        .fields
        .iter()
        .map(|field| field.logical)
        .collect::<BTreeSet<_>>();
    if let Some(field) = configured
        .fields
        .keys()
        .find(|field| !known.contains(field.as_str()))
    {
        return Err(AgentAuthSchemaError::UnknownField {
            model: definition.logical_name.to_owned(),
            field: field.clone(),
        });
    }

    let mut fields = BTreeMap::new();
    let mut physical_fields = BTreeSet::from(["id".to_owned()]);
    for field in definition.fields {
        let identifier = Identifier::new(
            "field",
            configured
                .fields
                .get(field.logical)
                .map(String::as_str)
                .unwrap_or(field.default_column),
        )?;
        if !physical_fields.insert(identifier.raw.clone()) {
            return Err(AgentAuthSchemaError::DuplicateIdentifier {
                kind: "field",
                identifier: format!("{}.{}", table.raw, identifier.raw),
            });
        }
        fields.insert(field.logical, identifier);
    }
    Ok(fields)
}

fn configured_model(schema: &AgentAuthSchema, model: AgentAuthModel) -> &AgentAuthModelSchema {
    match model {
        AgentAuthModel::AgentHost => &schema.agent_host,
        AgentAuthModel::Agent => &schema.agent,
        AgentAuthModel::AgentCapabilityGrant => &schema.agent_capability_grant,
        AgentAuthModel::ApprovalRequest => &schema.approval_request,
    }
}

fn schema_fingerprint(models: &BTreeMap<AgentAuthModel, ResolvedAgentAuthModel>) -> String {
    let mut digest = Sha256::new();
    for (model, resolved) in models {
        digest.update(format!("{model:?}:{};", resolved.table.raw));
        for (logical, field) in &resolved.fields {
            digest.update(format!("{logical}:{};", field.raw));
        }
    }
    hex::encode(digest.finalize())[..12].to_owned()
}

#[derive(Debug, Clone)]
struct Identifier {
    raw: String,
    quoted: String,
}

impl Identifier {
    fn new(kind: &'static str, value: &str) -> Result<Self, AgentAuthSchemaError> {
        let reason = if value.is_empty() {
            Some("must not be empty")
        } else if value.len() > 63 {
            Some("must not exceed PostgreSQL's 63-byte identifier limit")
        } else if value.chars().any(char::is_control) {
            Some("must not contain control characters")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(AgentAuthSchemaError::InvalidIdentifier {
                kind,
                identifier: value.to_owned(),
                reason,
            });
        }
        Ok(Self {
            raw: value.to_owned(),
            quoted: format!("\"{}\"", value.replace('"', "\"\"")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_declared_model_and_field_can_be_remapped() {
        let mut schema = AgentAuthSchema::default();
        for definition in DEFINITIONS {
            let model = match definition.model {
                AgentAuthModel::AgentHost => &mut schema.agent_host,
                AgentAuthModel::Agent => &mut schema.agent,
                AgentAuthModel::AgentCapabilityGrant => &mut schema.agent_capability_grant,
                AgentAuthModel::ApprovalRequest => &mut schema.approval_request,
            };
            model.model_name = Some(format!("mapped_{}", definition.logical_name));
            for field in definition.fields {
                model
                    .fields
                    .insert(field.logical.into(), format!("mapped_{}", field.logical));
            }
        }
        let resolved = ResolvedAgentAuthSchema::new(&schema).unwrap();
        for definition in DEFINITIONS {
            let model = resolved.model(definition.model);
            assert_eq!(model.fields.len(), definition.fields.len());
            assert_eq!(
                model.table(),
                format!("\"mapped_{}\"", definition.logical_name)
            );
            for field in definition.fields {
                assert_eq!(
                    model.column(field.logical),
                    format!("\"mapped_{}\"", field.logical)
                );
            }
        }
    }

    #[test]
    fn rejects_unknown_duplicate_and_invalid_identifiers() {
        let mut schema = AgentAuthSchema::default();
        schema
            .agent
            .fields
            .insert("hostID".into(), "host_id".into());
        assert!(matches!(
            ResolvedAgentAuthSchema::new(&schema),
            Err(AgentAuthSchemaError::UnknownField { .. })
        ));

        schema.agent.fields.clear();
        schema.agent.fields.insert("name".into(), "id".into());
        assert!(matches!(
            ResolvedAgentAuthSchema::new(&schema),
            Err(AgentAuthSchemaError::DuplicateIdentifier { kind: "field", .. })
        ));

        schema.agent.fields.clear();
        schema.agent.model_name = Some("bad\0model".into());
        assert!(matches!(
            ResolvedAgentAuthSchema::new(&schema),
            Err(AgentAuthSchemaError::InvalidIdentifier { .. })
        ));

        schema.agent.model_name = Some("lucid_auth_agent_hosts".into());
        assert!(matches!(
            ResolvedAgentAuthSchema::new(&schema),
            Err(AgentAuthSchemaError::DuplicateIdentifier { kind: "model", .. })
        ));

        schema.agent.model_name = Some(String::new());
        assert!(matches!(
            ResolvedAgentAuthSchema::new(&schema),
            Err(AgentAuthSchemaError::InvalidIdentifier { .. })
        ));
    }

    #[test]
    fn fingerprint_is_deterministic_and_changes_with_any_mapping() {
        let original = ResolvedAgentAuthSchema::new(&AgentAuthSchema::default()).unwrap();
        let repeated = ResolvedAgentAuthSchema::new(&AgentAuthSchema::default()).unwrap();
        assert_eq!(original.fingerprint(), repeated.fingerprint());

        let mut remapped = AgentAuthSchema::default();
        remapped
            .approval_request
            .fields
            .insert("interval".into(), "poll_interval".into());
        let remapped = ResolvedAgentAuthSchema::new(&remapped).unwrap();
        assert_ne!(original.fingerprint(), remapped.fingerprint());
    }

    #[test]
    fn identifier_limit_is_measured_in_postgres_bytes() {
        let mut schema = AgentAuthSchema::default();
        schema.agent.model_name = Some("é".repeat(32));
        assert!(matches!(
            ResolvedAgentAuthSchema::new(&schema),
            Err(AgentAuthSchemaError::InvalidIdentifier { .. })
        ));
    }
}
