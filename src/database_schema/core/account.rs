use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldReference, AdditionalFieldSet,
    AdditionalFieldType, AuthConfig, DatabaseSchemaIndex,
};
use serde_json::json;
use std::sync::Arc;

pub(super) fn fields(config: &AuthConfig) -> AdditionalFieldSet {
    let mappings = &config.account.fields;
    let mut result = AdditionalFieldSet::new();
    result.insert("issuer".into(), string(&mappings.issuer, "issuer", true));
    result.insert(
        "accountId".into(),
        string(&mappings.account_id, "accountId", true),
    );
    result.insert(
        "providerId".into(),
        string(&mappings.provider_id, "providerId", true),
    );
    result.insert(
        "userId".into(),
        string(&mappings.user_id, "userId", true)
            .references(AdditionalFieldReference {
                model: "user".into(),
                field: "id".into(),
                on_delete: Some(AdditionalFieldOnDelete::Cascade),
            })
            .index(true),
    );
    for (logical, mapping) in [
        ("accessToken", &mappings.access_token),
        ("refreshToken", &mappings.refresh_token),
        ("idToken", &mappings.id_token),
    ] {
        result.insert(
            logical.into(),
            string(mapping, logical, false).returned(false),
        );
    }
    for (logical, mapping) in [
        ("accessTokenExpiresAt", &mappings.access_token_expires_at),
        ("refreshTokenExpiresAt", &mappings.refresh_token_expires_at),
    ] {
        result.insert(
            logical.into(),
            field(AdditionalFieldType::Date, mapping, logical)
                .optional()
                .returned(false),
        );
    }
    result.insert("scope".into(), string(&mappings.scope, "scope", false));
    result.insert(
        "password".into(),
        string(&mappings.password, "password", false).returned(false),
    );
    result.insert(
        "createdAt".into(),
        field(AdditionalFieldType::Date, &mappings.created_at, "createdAt")
            .default_with(date_now()),
    );
    result.insert(
        "updatedAt".into(),
        field(AdditionalFieldType::Date, &mappings.updated_at, "updatedAt")
            .on_update_with(date_now()),
    );
    result
}

pub(super) fn indexes() -> Vec<DatabaseSchemaIndex> {
    vec![DatabaseSchemaIndex::new(["issuer", "accountId"]).unique(true)]
}

fn string(mapping: &Option<String>, logical: &str, required: bool) -> AdditionalField {
    let field = field(AdditionalFieldType::String, mapping, logical);
    if required { field } else { field.optional() }
}

fn field(
    field_type: AdditionalFieldType,
    mapping: &Option<String>,
    logical: &str,
) -> AdditionalField {
    AdditionalField::new(field_type).field_name(
        mapping
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(logical),
    )
}

fn date_now() -> Arc<dyn crate::AdditionalFieldDefault> {
    Arc::new(|| Ok(json!(chrono::Utc::now().to_rfc3339())))
}
