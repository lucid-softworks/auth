use super::SsoOptions;
use crate::{AdditionalField, AdditionalFieldReference, AdditionalFieldType, PluginSchemaTable};
use std::collections::BTreeSet;

const BUILT_IN_FIELDS: &[&str] = &[
    "id",
    "issuer",
    "oidcConfig",
    "samlConfig",
    "userId",
    "providerId",
    "organizationId",
    "domain",
    "domainVerified",
];

const RESPONSE_FIELDS: &[&str] = &[
    "type",
    "spMetadataUrl",
    "redirectURI",
    "domainVerificationToken",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SsoSchemaError {
    #[error("ssoProvider additional field \"{0}\" conflicts with a built-in field")]
    BuiltInField(String),
    #[error("ssoProvider additional field \"{0}\" conflicts with a returned provider field")]
    ResponseField(String),
    #[error("ssoProvider additional field \"{field}\" maps to built-in field \"{physical}\"")]
    BuiltInPhysicalField { field: String, physical: String },
}

pub(super) fn validate(options: &SsoOptions) -> Result<(), SsoSchemaError> {
    let built_in_physical = BUILT_IN_FIELDS
        .iter()
        .map(|logical| configured_field_name(options, logical).to_owned())
        .collect::<BTreeSet<_>>();
    for (logical, field) in &options.schema.sso_provider.additional_fields {
        if BUILT_IN_FIELDS.contains(&logical.as_str()) {
            return Err(SsoSchemaError::BuiltInField(logical.clone()));
        }
        if RESPONSE_FIELDS.contains(&logical.as_str()) {
            return Err(SsoSchemaError::ResponseField(logical.clone()));
        }
        let physical = field.field_name.as_deref().unwrap_or(logical);
        if built_in_physical.contains(physical) {
            return Err(SsoSchemaError::BuiltInPhysicalField {
                field: logical.clone(),
                physical: physical.to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn table(options: &SsoOptions) -> PluginSchemaTable {
    let string = || AdditionalField::new(AdditionalFieldType::String);
    let mut table = PluginSchemaTable::new("ssoProvider")
        .model_name(configured_model_name(options))
        .field("issuer", configured_field(options, "issuer", string()))
        .field(
            "oidcConfig",
            configured_field(options, "oidcConfig", string().optional()),
        )
        .field(
            "samlConfig",
            configured_field(options, "samlConfig", string().optional()),
        )
        .field(
            "userId",
            configured_field(
                options,
                "userId",
                string().optional().references(AdditionalFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    on_delete: None,
                }),
            ),
        )
        .field(
            "providerId",
            configured_field(options, "providerId", string().unique(true)),
        )
        .field(
            "organizationId",
            configured_field(options, "organizationId", string().optional()),
        )
        .field("domain", configured_field(options, "domain", string()));
    if options.domain_verification {
        table = table.field(
            "domainVerified",
            configured_field(
                options,
                "domainVerified",
                AdditionalField::new(AdditionalFieldType::Boolean).optional(),
            ),
        );
    }
    table
        .fields
        .extend(options.schema.sso_provider.additional_fields.clone());
    table
}

fn configured_model_name(options: &SsoOptions) -> String {
    options
        .model_name
        .as_deref()
        .or(options.schema.sso_provider.model_name.as_deref())
        .unwrap_or("ssoProvider")
        .to_owned()
}

fn configured_field(
    options: &SsoOptions,
    logical: &str,
    field: AdditionalField,
) -> AdditionalField {
    field.field_name(configured_field_name(options, logical))
}

fn configured_field_name<'a>(options: &'a SsoOptions, logical: &'a str) -> &'a str {
    let top_level = (logical != "domainVerified")
        .then(|| options.fields.get(logical))
        .flatten();
    top_level
        .or_else(|| options.schema.sso_provider.fields.get(logical))
        .unwrap_or(logical)
}
