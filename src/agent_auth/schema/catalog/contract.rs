use super::*;

const EXPECTED_FIELDS: &[&str] = &[
    "name,userId,defaultCapabilities,publicKey,kid,jwksUrl,enrollmentTokenHash,enrollmentTokenExpiresAt,status,activatedAt,expiresAt,lastUsedAt,createdAt,updatedAt",
    "name,userId,hostId,status,mode,publicKey,kid,jwksUrl,lastUsedAt,activatedAt,expiresAt,metadata,createdAt,updatedAt",
    "agentId,capability,deniedBy,grantedBy,expiresAt,createdAt,updatedAt,status,reason,constraints",
    "method,agentId,hostId,userId,capabilities,status,userCodeHash,loginHint,bindingMessage,clientNotificationToken,clientNotificationEndpoint,deliveryMode,interval,lastPolledAt,expiresAt,createdAt,updatedAt",
];

const INDEXED_FIELDS: &[&str] = &[
    "userId,kid,enrollmentTokenHash,status",
    "userId,hostId,status,kid",
    "agentId,capability,grantedBy,status",
    "agentId,hostId,userId,status",
];

const REQUIRED_FIELDS: &[&str] = &[
    "status,createdAt,updatedAt",
    "name,hostId,status,mode,publicKey,createdAt,updatedAt",
    "agentId,capability,createdAt,updatedAt,status",
    "method,status,interval,expiresAt,createdAt,updatedAt",
];

#[test]
fn exact_models_fields_and_text_ids_match_agent_auth_0_6_2() {
    let tables = schema_tables(&AgentAuthSchema::default());
    assert_eq!(
        tables
            .iter()
            .map(|table| table.logical_name.as_str())
            .collect::<Vec<_>>(),
        [
            "agentHost",
            "agent",
            "agentCapabilityGrant",
            "approvalRequest"
        ]
    );
    for (table, expected) in tables.iter().zip(EXPECTED_FIELDS) {
        assert_eq!(table.model_name, None);
        assert_eq!(
            table.fields.keys().map(String::as_str).collect::<Vec<_>>(),
            expected.split(',').collect::<Vec<_>>()
        );
    }
}

#[test]
fn exact_input_index_and_required_policy() {
    let tables = schema_tables(&AgentAuthSchema::default());
    for ((table, indexed), required) in tables.iter().zip(INDEXED_FIELDS).zip(REQUIRED_FIELDS) {
        for (logical, field) in &table.fields {
            assert_eq!(
                field.input,
                table.logical_name == "agent" && logical == "metadata"
            );
        }
        assert_eq!(
            selected_fields(table, |field| field.index),
            indexed.split(',').collect::<Vec<_>>()
        );
        assert_eq!(
            selected_fields(table, |field| field.required),
            required.split(',').collect::<Vec<_>>()
        );
    }
}

#[test]
fn exact_reference_policy() {
    let tables = schema_tables(&AgentAuthSchema::default());
    assert_reference(&tables[0].fields["userId"], "user", true);
    assert_reference(&tables[1].fields["userId"], "user", true);
    assert_reference(&tables[1].fields["hostId"], "agentHost", true);
    assert_reference(&tables[2].fields["agentId"], "agent", true);
    assert_reference(&tables[2].fields["deniedBy"], "user", false);
    assert_reference(&tables[2].fields["grantedBy"], "user", true);
    assert_reference(&tables[3].fields["agentId"], "agent", true);
    assert_reference(&tables[3].fields["hostId"], "agentHost", true);
    assert_reference(&tables[3].fields["userId"], "user", true);
}

#[test]
fn exact_defaults_and_storage_types() {
    let tables = schema_tables(&AgentAuthSchema::default());
    assert_default(&tables[0], "status", json!("active"));
    assert_default(&tables[1], "status", json!("active"));
    assert_default(&tables[1], "mode", json!("delegated"));
    assert_default(&tables[2], "status", json!("active"));
    assert_default(&tables[3], "status", json!("pending"));
    assert_eq!(
        tables[3].fields["interval"].field_type,
        AdditionalFieldType::Number
    );
    for (table, field) in [
        (0, "enrollmentTokenExpiresAt"),
        (0, "createdAt"),
        (1, "lastUsedAt"),
        (2, "expiresAt"),
        (3, "lastPolledAt"),
    ] {
        assert_eq!(
            tables[table].fields[field].field_type,
            AdditionalFieldType::Date
        );
    }
    for (table, field) in [
        (0, "defaultCapabilities"),
        (1, "metadata"),
        (2, "constraints"),
    ] {
        assert!(tables[table].fields[field].has_input_transform());
        assert!(tables[table].fields[field].has_output_transform());
    }
}

#[test]
fn schema_remaps_are_truthy_and_unknown_fields_are_ignored() {
    let mut schema = AgentAuthSchema::default();
    schema.agent.model_name = Some("bots".into());
    schema.agent.fields.insert("name".into(), "".into());
    schema
        .agent
        .fields
        .insert("unknown".into(), "ignored".into());
    let tables = schema_tables(&schema);
    assert_eq!(tables[1].model_name.as_deref(), Some("bots"));
    assert_eq!(tables[1].fields["name"].field_name, None);
    assert!(!tables[1].fields.contains_key("unknown"));
}

#[test]
fn constraints_input_preserves_strings_and_encodes_structures() {
    assert_eq!(
        json_string_input(json!("already encoded"), true).unwrap(),
        json!("already encoded")
    );
    assert_eq!(
        json_string_input(json!({ "limit": { "max": 5 } }), true).unwrap(),
        json!(r#"{"limit":{"max":5}}"#)
    );
}

fn selected_fields(
    table: &PluginSchemaTable,
    predicate: impl Fn(&AdditionalField) -> bool,
) -> Vec<&str> {
    table
        .fields
        .iter()
        .filter_map(|(logical, field)| predicate(field).then_some(logical.as_str()))
        .collect()
}

fn assert_default(table: &PluginSchemaTable, field: &str, expected: Value) {
    assert_eq!(table.fields[field].static_default_value(), Some(&expected));
}

fn assert_reference(field: &AdditionalField, model: &str, indexed: bool) {
    assert_eq!(
        field.references,
        Some(AdditionalFieldReference {
            model: model.into(),
            field: "id".into(),
            on_delete: Some(AdditionalFieldOnDelete::Cascade),
        })
    );
    assert_eq!(field.index, indexed);
}
