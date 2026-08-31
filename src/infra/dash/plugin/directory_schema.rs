use crate::{AdditionalField, AdditionalFieldType, PluginSchemaTable};
use serde_json::json;

pub(super) fn tables() -> [PluginSchemaTable; 2] {
    [connection(), membership_provenance()]
}

fn connection() -> PluginSchemaTable {
    PluginSchemaTable::new("directorySyncConnection")
        .field("organizationId", string().index(true))
        .field("providerId", string())
        .field("aliasKey", hidden_string().unique(true))
        .field("provisioningDomainId", string().unique(true))
        .field("activeOrganizationKey", hidden_string().unique(true))
        .field("connectionId", optional_string().unique(true))
        .field("creationRequestId", hidden_string().unique(true))
        .field("status", string())
        .field(
            "revision",
            AdditionalField::new(AdditionalFieldType::Number)
                .default_value(json!(0))
                .returned(false),
        )
        .field("createdAt", AdditionalField::new(AdditionalFieldType::Date))
        .field("createdByActorId", string())
        .field("updatedAt", AdditionalField::new(AdditionalFieldType::Date))
        .field("lastActorId", string())
        .field("ssoProviderId", optional_string())
        .field("ssoProviderRecordId", optional_string().index(true))
        .field("activeSsoProviderKey", hidden_string().unique(true))
        .field("serializedSsoPairing", optional_string().returned(false))
        .field(
            "pairingEnforced",
            AdditionalField::new(AdditionalFieldType::Boolean).default_value(json!(false)),
        )
        .field(
            "unpairedAt",
            AdditionalField::new(AdditionalFieldType::Date).optional(),
        )
        .field("unpairedBy", optional_string())
        .field(
            "decommissionStartedAt",
            AdditionalField::new(AdditionalFieldType::Date).optional(),
        )
        .field(
            "decommissionedAt",
            AdditionalField::new(AdditionalFieldType::Date).optional(),
        )
        .field("lastError", optional_string().returned(false))
}

fn membership_provenance() -> PluginSchemaTable {
    PluginSchemaTable::new("directorySyncMembershipProvenance")
        .field("membershipKey", hidden_string().unique(true))
        .field("organizationId", string().index(true))
        .field("userId", string().index(true))
        .field("memberId", string().unique(true))
        .field("ownership", hidden_string())
        .field("provisioningDomainId", string().index(true))
        .field("createdAt", AdditionalField::new(AdditionalFieldType::Date))
        .field("updatedAt", AdditionalField::new(AdditionalFieldType::Date))
}

fn string() -> AdditionalField {
    AdditionalField::new(AdditionalFieldType::String)
}

fn hidden_string() -> AdditionalField {
    string().returned(false)
}

fn optional_string() -> AdditionalField {
    string().optional()
}
