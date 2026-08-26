use super::catalog::{SchemaTable, truthy};
use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldReference, AdditionalFieldSet,
    AdditionalFieldType, AuthConfig, RateLimitStorageMode,
};
use indexmap::IndexMap;
use serde_json::json;
use std::sync::Arc;

mod account;

pub(super) fn build_tables(
    config: &AuthConfig,
    mut plugin: IndexMap<String, SchemaTable>,
    id_type: super::catalog::DatabaseIdType,
) -> IndexMap<String, SchemaTable> {
    let user_plugin = plugin.shift_remove("user");
    let session_plugin = plugin.shift_remove("session");
    let account_plugin = plugin.shift_remove("account");
    let verification_plugin = plugin.shift_remove("verification");
    let mut tables = IndexMap::new();
    tables.insert(
        "user".into(),
        core_table(
            config.user.model_name.as_deref(),
            "user",
            user_fields(config),
            user_plugin,
            &config.user.additional_fields,
            1,
            id_type,
        ),
    );
    if database_sessions(config) {
        tables.insert(
            "session".into(),
            core_table(
                config.session.model_name.as_deref(),
                "session",
                session_fields(config),
                session_plugin,
                &config.session.additional_fields,
                2,
                id_type,
            ),
        );
    }
    let mut account = core_table(
        config.account.model_name.as_deref(),
        "account",
        account::fields(config),
        account_plugin,
        &config.account.additional_fields,
        3,
        id_type,
    );
    let mut account_indexes = account::indexes();
    for index in account.indexes {
        if !account_indexes.iter().any(|existing| existing == &index) {
            account_indexes.push(index);
        }
    }
    account.indexes = account_indexes;
    tables.insert("account".into(), account);
    if database_verifications(config) {
        tables.insert(
            "verification".into(),
            core_table(
                config.verification.model_name.as_deref(),
                "verification",
                verification_fields(config),
                verification_plugin,
                &config.verification.additional_fields,
                4,
                id_type,
            ),
        );
    }
    tables.extend(plugin);
    if matches!(config.rate_limit.storage, RateLimitStorageMode::Database) {
        tables.insert("rateLimit".into(), rate_limit_table(config, id_type));
    }
    tables
}

fn core_table(
    configured_model_name: Option<&str>,
    canonical: &str,
    mut fields: AdditionalFieldSet,
    plugin: Option<SchemaTable>,
    host_additional: &AdditionalFieldSet,
    order: u32,
    id_type: super::catalog::DatabaseIdType,
) -> SchemaTable {
    let mut indexes = Vec::new();
    if let Some(plugin) = plugin {
        fields.extend(plugin.fields);
        indexes = plugin.indexes;
    }
    fields.extend(host_additional.clone());
    SchemaTable {
        model_name: truthy(configured_model_name).unwrap_or(canonical).into(),
        id_type,
        fields,
        indexes,
        disable_migrations: false,
        order: Some(order),
    }
}

fn mapped(configured: &Option<String>, canonical: &str) -> Option<String> {
    Some(truthy(configured.as_deref()).unwrap_or(canonical).into())
}

fn field(field_type: AdditionalFieldType, physical: Option<String>) -> AdditionalField {
    let mut field = AdditionalField::new(field_type);
    field.field_name = physical;
    field
}

fn date_now() -> Arc<dyn crate::AdditionalFieldDefault> {
    Arc::new(|| Ok(json!(chrono::Utc::now().to_rfc3339())))
}

fn unix_millis() -> Arc<dyn crate::AdditionalFieldDefault> {
    Arc::new(|| Ok(json!(chrono::Utc::now().timestamp_millis())))
}

fn created_date(physical: Option<String>) -> AdditionalField {
    field(AdditionalFieldType::Date, physical).default_with(date_now())
}

fn updated_date(physical: Option<String>, has_default: bool) -> AdditionalField {
    let field = field(AdditionalFieldType::Date, physical).on_update_with(date_now());
    if has_default {
        field.default_with(date_now())
    } else {
        field
    }
}

fn user_fields(config: &AuthConfig) -> AdditionalFieldSet {
    let fields = &config.user.fields;
    let mut result = AdditionalFieldSet::new();
    result.insert(
        "name".into(),
        field(AdditionalFieldType::String, mapped(&fields.name, "name")).sortable(true),
    );
    result.insert(
        "email".into(),
        field(AdditionalFieldType::String, mapped(&fields.email, "email"))
            .unique(true)
            .sortable(true),
    );
    result.insert(
        "emailVerified".into(),
        field(
            AdditionalFieldType::Boolean,
            mapped(&fields.email_verified, "emailVerified"),
        )
        .default_value(json!(false))
        .input(false),
    );
    result.insert(
        "image".into(),
        field(AdditionalFieldType::String, mapped(&fields.image, "image")).optional(),
    );
    result.insert(
        "createdAt".into(),
        created_date(mapped(&fields.created_at, "createdAt")),
    );
    result.insert(
        "updatedAt".into(),
        updated_date(mapped(&fields.updated_at, "updatedAt"), true),
    );
    result
}

fn session_fields(config: &AuthConfig) -> AdditionalFieldSet {
    let fields = &config.session.fields;
    let mut result = AdditionalFieldSet::new();
    result.insert(
        "expiresAt".into(),
        field(
            AdditionalFieldType::Date,
            mapped(&fields.expires_at, "expiresAt"),
        ),
    );
    result.insert(
        "token".into(),
        field(AdditionalFieldType::String, mapped(&fields.token, "token")).unique(true),
    );
    result.insert(
        "createdAt".into(),
        created_date(mapped(&fields.created_at, "createdAt")),
    );
    result.insert(
        "updatedAt".into(),
        updated_date(mapped(&fields.updated_at, "updatedAt"), false),
    );
    result.insert(
        "ipAddress".into(),
        field(
            AdditionalFieldType::String,
            mapped(&fields.ip_address, "ipAddress"),
        )
        .optional(),
    );
    result.insert(
        "userAgent".into(),
        field(
            AdditionalFieldType::String,
            mapped(&fields.user_agent, "userAgent"),
        )
        .optional(),
    );
    result.insert(
        "userId".into(),
        field(
            AdditionalFieldType::String,
            mapped(&fields.user_id, "userId"),
        )
        .references(AdditionalFieldReference {
            model: "user".into(),
            field: "id".into(),
            on_delete: Some(AdditionalFieldOnDelete::Cascade),
        })
        .index(true),
    );
    result
}

fn verification_fields(config: &AuthConfig) -> AdditionalFieldSet {
    let fields = &config.verification.fields;
    let mut result = AdditionalFieldSet::new();
    result.insert(
        "identifier".into(),
        field(
            AdditionalFieldType::String,
            mapped(&fields.identifier, "identifier"),
        )
        .index(true),
    );
    result.insert(
        "value".into(),
        field(AdditionalFieldType::String, mapped(&fields.value, "value")),
    );
    result.insert(
        "expiresAt".into(),
        field(
            AdditionalFieldType::Date,
            mapped(&fields.expires_at, "expiresAt"),
        ),
    );
    result.insert(
        "createdAt".into(),
        created_date(mapped(&fields.created_at, "createdAt")),
    );
    result.insert(
        "updatedAt".into(),
        updated_date(mapped(&fields.updated_at, "updatedAt"), true),
    );
    result
}

fn rate_limit_table(config: &AuthConfig, id_type: super::catalog::DatabaseIdType) -> SchemaTable {
    let fields = &config.rate_limit.fields;
    let mut result = AdditionalFieldSet::new();
    result.insert(
        "key".into(),
        field(AdditionalFieldType::String, mapped(&fields.key, "key")).unique(true),
    );
    result.insert(
        "count".into(),
        field(AdditionalFieldType::Number, mapped(&fields.count, "count")),
    );
    result.insert(
        "lastRequest".into(),
        field(
            AdditionalFieldType::Number,
            mapped(&fields.last_request, "lastRequest"),
        )
        .bigint(true)
        .default_with(unix_millis()),
    );
    SchemaTable {
        model_name: truthy(config.rate_limit.model_name.as_deref())
            .unwrap_or("rateLimit")
            .into(),
        id_type,
        fields: result,
        indexes: Vec::new(),
        disable_migrations: false,
        order: None,
    }
}

fn database_sessions(config: &AuthConfig) -> bool {
    config.secondary_storage.is_none() || config.session.store_session_in_database
}

fn database_verifications(config: &AuthConfig) -> bool {
    config.secondary_storage.is_none() || config.verification.store_in_database
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthSchemaCatalog, MemorySecondaryStorage, SessionStorageMode};

    #[test]
    fn table_presence_uses_the_exact_better_auth_secondary_storage_predicate() {
        let mut config = AuthConfig::new([11; 32]).unwrap();
        config.session.storage_mode = SessionStorageMode::Stateless;
        let catalog = AuthSchemaCatalog::build(&config, []).unwrap();
        assert!(catalog.table("session").is_some());
        assert!(catalog.table("verification").is_some());

        config.secondary_storage = Some(Arc::new(MemorySecondaryStorage::default()));
        let catalog = AuthSchemaCatalog::build(&config, []).unwrap();
        assert!(catalog.table("session").is_none());
        assert!(catalog.table("verification").is_none());

        config.session.store_session_in_database = true;
        config.verification.store_in_database = true;
        let catalog = AuthSchemaCatalog::build(&config, []).unwrap();
        assert!(catalog.table("session").is_some());
        assert!(catalog.table("verification").is_some());
    }

    #[test]
    fn core_time_policies_match_the_pinned_schema() {
        let catalog = AuthSchemaCatalog::build(&AuthConfig::new([12; 32]).unwrap(), []).unwrap();
        assert!(catalog.table("user").unwrap().fields["createdAt"].has_default_factory());
        assert!(catalog.table("user").unwrap().fields["updatedAt"].has_on_update());
        assert!(!catalog.table("session").unwrap().fields["updatedAt"].has_default());
        assert!(catalog.table("account").unwrap().fields["updatedAt"].has_on_update());
        assert!(catalog.table("verification").unwrap().fields["updatedAt"].has_default());
    }
}
