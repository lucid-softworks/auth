use super::OrganizationPluginConfig;
use crate::{AdditionalField, AdditionalFieldReference, AdditionalFieldType, PluginSchemaTable};
use serde_json::json;
use std::sync::Arc;

pub(super) fn tables(config: &OrganizationPluginConfig) -> Vec<PluginSchemaTable> {
    let mut tables = vec![organization()];
    if config.dynamic_access_control.enabled {
        tables.push(role());
    }
    if config.teams.enabled {
        tables.extend([team(), team_member()]);
    }
    tables.extend([
        member(),
        invitation(config.teams.enabled),
        session(config.teams.enabled),
    ]);
    tables
        .into_iter()
        .map(|table| {
            let (schema, additional) = match table.logical_name.as_str() {
                "organization" => (&config.schema.organization, true),
                "member" => (&config.schema.member, true),
                "invitation" => (&config.schema.invitation, true),
                "team" => (&config.schema.team, true),
                "teamMember" => (&config.schema.team_member, false),
                "organizationRole" => (&config.schema.organization_role, true),
                "session" => (&config.schema.session, false),
                _ => unreachable!("organization catalog has a closed table set"),
            };
            remap_table(table, schema, additional)
        })
        .collect()
}

fn remap_table(
    mut table: PluginSchemaTable,
    schema: &crate::DatabaseModelSchema,
    include_additional_fields: bool,
) -> PluginSchemaTable {
    // The organization plugin assigns its schema overrides directly instead of
    // passing them through Better Auth's mergeSchema helper. Consequently an
    // explicitly configured empty string remains observable in the schema.
    if let Some(model_name) = &schema.model_name {
        table.model_name = Some(model_name.clone());
    }
    for (logical_name, field) in &mut table.fields {
        if let Some(field_name) = schema.fields.get(logical_name) {
            field.field_name = Some(field_name.clone());
        }
    }
    if include_additional_fields {
        table.fields.extend(schema.additional_fields.clone());
    }
    table
}

fn organization() -> PluginSchemaTable {
    PluginSchemaTable::new("organization")
        .field(
            "name",
            AdditionalField::new(AdditionalFieldType::String).sortable(true),
        )
        .field(
            "slug",
            AdditionalField::new(AdditionalFieldType::String)
                .unique(true)
                .sortable(true)
                .index(true),
        )
        .field("logo", optional(AdditionalFieldType::String))
        .field("createdAt", AdditionalField::new(AdditionalFieldType::Date))
        .field("metadata", optional(AdditionalFieldType::String))
}

fn member() -> PluginSchemaTable {
    PluginSchemaTable::new("member")
        .field("organizationId", reference("organization").index(true))
        .field("userId", reference("user").index(true))
        .field(
            "role",
            AdditionalField::new(AdditionalFieldType::String)
                .sortable(true)
                .default_value(json!("member")),
        )
        .field("createdAt", AdditionalField::new(AdditionalFieldType::Date))
}

fn invitation(team_support: bool) -> PluginSchemaTable {
    let mut table = PluginSchemaTable::new("invitation")
        .field("organizationId", reference("organization").index(true))
        .field(
            "email",
            AdditionalField::new(AdditionalFieldType::String)
                .sortable(true)
                .index(true),
        )
        .field("role", optional(AdditionalFieldType::String).sortable(true));
    if team_support {
        table = table.field(
            "teamId",
            optional(AdditionalFieldType::String).sortable(true),
        );
    }
    table
        .field(
            "status",
            AdditionalField::new(AdditionalFieldType::String)
                .sortable(true)
                .default_value(json!("pending")),
        )
        .field("expiresAt", AdditionalField::new(AdditionalFieldType::Date))
        .field(
            "createdAt",
            AdditionalField::new(AdditionalFieldType::Date).default_with(date_now()),
        )
        .field("inviterId", reference("user"))
}

fn role() -> PluginSchemaTable {
    PluginSchemaTable::new("organizationRole")
        .field("organizationId", reference("organization").index(true))
        .field(
            "role",
            AdditionalField::new(AdditionalFieldType::String).index(true),
        )
        .field(
            "permission",
            AdditionalField::new(AdditionalFieldType::String),
        )
        .field(
            "createdAt",
            AdditionalField::new(AdditionalFieldType::Date).default_with(date_now()),
        )
        .field(
            "updatedAt",
            optional(AdditionalFieldType::Date).on_update_with(date_now()),
        )
}

fn team() -> PluginSchemaTable {
    PluginSchemaTable::new("team")
        .field("name", AdditionalField::new(AdditionalFieldType::String))
        .field(
            "memberCount",
            AdditionalField::new(AdditionalFieldType::Number)
                .default_value(json!(0))
                .input(false)
                .returned(false),
        )
        .field("organizationId", reference("organization").index(true))
        .field("createdAt", AdditionalField::new(AdditionalFieldType::Date))
        .field(
            "updatedAt",
            optional(AdditionalFieldType::Date).on_update_with(date_now()),
        )
}

fn team_member() -> PluginSchemaTable {
    PluginSchemaTable::new("teamMember")
        .field("teamId", reference("team").index(true))
        .field("userId", reference("user").index(true))
        .field(
            "membershipKey",
            optional(AdditionalFieldType::String)
                .unique(true)
                .input(false)
                .returned(false),
        )
        .field("createdAt", optional(AdditionalFieldType::Date))
}

fn session(team_support: bool) -> PluginSchemaTable {
    let mut table = PluginSchemaTable::new("session").field(
        "activeOrganizationId",
        optional(AdditionalFieldType::String).input(false),
    );
    if team_support {
        table = table.field(
            "activeTeamId",
            optional(AdditionalFieldType::String).input(false),
        );
    }
    table
}

fn reference(model: &str) -> AdditionalField {
    AdditionalField::new(AdditionalFieldType::String).references(AdditionalFieldReference {
        model: model.into(),
        field: "id".into(),
        on_delete: None,
    })
}

fn optional(field_type: AdditionalFieldType) -> AdditionalField {
    AdditionalField::new(field_type).optional()
}

fn date_now() -> Arc<dyn crate::AdditionalFieldDefault> {
    Arc::new(|| Ok(json!(chrono::Utc::now().to_rfc3339())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_schema_overrides_preserve_explicit_empty_strings() {
        let mut config = OrganizationPluginConfig::default();
        config.schema.organization.model_name = Some(String::new());
        config
            .schema
            .organization
            .fields
            .insert("name".into(), String::new());

        let organization = tables(&config).remove(0);

        assert_eq!(organization.model_name.as_deref(), Some(""));
        assert_eq!(organization.fields["name"].field_name.as_deref(), Some(""));
    }
}
