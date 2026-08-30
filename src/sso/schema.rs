use crate::{
    AdditionalField, AdditionalFieldReference, AdditionalFieldType, PluginSchemaTable,
};

pub(super) fn table(domain_verification: bool) -> PluginSchemaTable {
    let string = || AdditionalField::new(AdditionalFieldType::String);
    let mut table = PluginSchemaTable::new("ssoProvider")
        .model_name("ssoProvider")
        .field("issuer", string())
        .field("oidcConfig", string().optional())
        .field("samlConfig", string().optional())
        .field(
            "userId",
            string().optional().references(AdditionalFieldReference {
                model: "user".into(),
                field: "id".into(),
                on_delete: None,
            }),
        )
        .field("providerId", string().unique(true))
        .field("organizationId", string().optional())
        .field("domain", string());
    if domain_verification {
        table = table.field(
            "domainVerified",
            AdditionalField::new(AdditionalFieldType::Boolean).optional(),
        );
    }
    table
}
