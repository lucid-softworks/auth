use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldReference, AdditionalFieldType,
    PluginSchemaTable,
};

pub(super) fn tables(managed: bool) -> Vec<PluginSchemaTable> {
    let mut tables = Vec::new();
    if managed {
        tables.extend(managed_tables());
    }
    tables.extend([
        connection_binding(),
        identity_tombstone(),
        subject(),
        user(),
        projection_grant(),
        group(),
        group_member(),
    ]);
    tables
}

fn string() -> AdditionalField {
    AdditionalField::new(AdditionalFieldType::String)
}

fn number() -> AdditionalField {
    AdditionalField::new(AdditionalFieldType::Number)
}

fn date() -> AdditionalField {
    AdditionalField::new(AdditionalFieldType::Date)
}

fn boolean() -> AdditionalField {
    AdditionalField::new(AdditionalFieldType::Boolean)
}

fn hidden(field: AdditionalField) -> AdditionalField {
    field.returned(false)
}

fn reference(model: &str) -> AdditionalFieldReference {
    AdditionalFieldReference {
        model: model.into(),
        field: "id".into(),
        on_delete: None,
    }
}

fn cascade(model: &str) -> AdditionalFieldReference {
    AdditionalFieldReference {
        on_delete: Some(AdditionalFieldOnDelete::Cascade),
        ..reference(model)
    }
}

fn connection_binding() -> PluginSchemaTable {
    PluginSchemaTable::new("scimConnectionBinding")
        .field("connectionId", string().index(true))
        .field("connectionKey", hidden(string().unique(true)))
        .field("provisioningDomainId", string())
        .field("createdAt", date())
        .field("decommissionedAt", date().optional())
        .field(
            "decommissionStatus",
            string().default_value(serde_json::json!("active")),
        )
        .field("decommissionCursorUserId", hidden(string().optional()))
        .field(
            "decommissionReconciledUserCount",
            number().default_value(serde_json::json!(0)),
        )
        .field(
            "decommissionBatchCount",
            number().default_value(serde_json::json!(0)),
        )
        .field(
            "decommissionRevision",
            hidden(number().default_value(serde_json::json!(0))),
        )
        .field("decommissionCompletedAt", date().optional())
        .field("decommissionLeaseId", hidden(string().optional()))
        .field("decommissionLeaseExpiresAt", hidden(date().optional()))
}

fn identity_tombstone() -> PluginSchemaTable {
    PluginSchemaTable::new("scimIdentityTombstone")
        .field("connectionId", string().index(true))
        .field("provisioningDomainId", string().index(true))
        .field("externalId", string())
        .field("externalIdKey", hidden(string().unique(true)))
        .field("userId", string().index(true).references(reference("user")))
        .field("profile", string())
        .field("deletedAt", date())
}

fn subject() -> PluginSchemaTable {
    PluginSchemaTable::new("scimSubject")
        .field("userId", string().unique(true).references(reference("user")))
        .field("profileSourceId", string().optional().index(true))
        .field("revision", number())
        .field("createdAt", date())
        .field("updatedAt", date())
}

fn user() -> PluginSchemaTable {
    PluginSchemaTable::new("scimUser")
        .field("connectionId", string().index(true))
        .field("provisioningDomainId", string().index(true))
        .field("userId", string().index(true).references(reference("user")))
        .field("connectionUserKey", hidden(string().unique(true)))
        .field("userName", string())
        .field("userNameKey", hidden(string().unique(true)))
        .field("primaryEmail", string())
        .field("workEmailValueIndex", hidden(string()))
        .field("emailValueIndex", hidden(string()))
        .field("displayName", string())
        .field("formattedName", string())
        .field("givenName", string().optional())
        .field("familyName", string().optional())
        .field("serializedEmails", hidden(string()))
        .field("serializedAttributes", hidden(string().optional()))
        .field("externalId", string().optional())
        .field("externalIdKey", hidden(string().optional().unique(true)))
        .field("active", boolean())
        .field("orderKey", hidden(string().unique(true)))
        .field("createdAt", date())
        .field("updatedAt", date())
}

fn projection_grant() -> PluginSchemaTable {
    PluginSchemaTable::new("scimProjectionGrant")
        .field("connectionId", string().index(true))
        .field("provisioningDomainId", string().index(true))
        .field(
            "scimUserId",
            string().index(true).references(reference("scimUser")),
        )
        .field("userId", string().index(true).references(reference("user")))
        .field("sourceKind", string())
        .field("sourceId", string())
        .field("sourceValue", string().optional())
        .field("role", string())
        .field("grantKey", hidden(string().unique(true)))
        .field("createdAt", date())
        .field("updatedAt", date())
}

fn group() -> PluginSchemaTable {
    PluginSchemaTable::new("scimGroup")
        .field("connectionId", string().index(true))
        .field("provisioningDomainId", string().index(true))
        .field(
            "revision",
            hidden(number().default_value(serde_json::json!(0))),
        )
        .field("displayName", string())
        .field("displayNameKey", hidden(string().unique(true)))
        .field("externalId", string().optional())
        .field("externalIdKey", hidden(string().optional().unique(true)))
        .field("orderKey", hidden(string().unique(true)))
        .field("createdAt", date())
        .field("updatedAt", date())
}

fn group_member() -> PluginSchemaTable {
    PluginSchemaTable::new("scimGroupMember")
        .field("connectionId", string().index(true))
        .field(
            "groupId",
            string().index(true).references(reference("scimGroup")),
        )
        .field(
            "scimUserId",
            string().index(true).references(reference("scimUser")),
        )
        .field("membershipKey", hidden(string().unique(true)))
        .field("createdAt", date())
}

fn managed_tables() -> [PluginSchemaTable; 3] {
    [
        PluginSchemaTable::new("scimManagedConnection")
            .field("creationRequestId", string().unique(true))
            .field("connectionId", string().unique(true))
            .field("provisioningDomainId", string().index(true))
            .field("status", string())
            .field("revision", hidden(number()))
            .field("createdAt", date())
            .field("createdBy", string())
            .field("decommissionStartedAt", date().optional())
            .field("decommissionStartedBy", string().optional())
            .field("decommissionedAt", date().optional())
            .field("decommissionedBy", string().optional()),
        PluginSchemaTable::new("scimManagedCredential")
            .field(
                "connectionRecordId",
                string()
                    .index(true)
                    .references(cascade("scimManagedConnection")),
            )
            .field("credentialId", string().unique(true))
            .field("tokenDigest", hidden(string()))
            .field("hashVersion", hidden(string()))
            .field("activeSlotKey", hidden(string().unique(true)))
            .field("status", string())
            .field("serializedScopes", hidden(string()))
            .field("expiresAt", date())
            .field("createdAt", date())
            .field("createdBy", string())
            .field("lastUsedAt", date().optional())
            .field("revokedAt", date().optional())
            .field("revokedBy", string().optional())
            .field("decommissionedAt", date().optional()),
        PluginSchemaTable::new("scimManagedConnectionEvent")
            .field(
                "connectionRecordId",
                string()
                    .index(true)
                    .references(cascade("scimManagedConnection")),
            )
            .field("eventKey", hidden(string().unique(true)))
            .field("sequence", number())
            .field("type", string())
            .field("actorId", string())
            .field("credentialId", string().optional())
            .field("createdAt", date()),
    ]
}
