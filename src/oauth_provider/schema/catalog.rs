use crate::{
    AdditionalField, AdditionalFieldOnDelete, AdditionalFieldReference, AdditionalFieldType,
    DatabaseIdType, DatabaseSchemaIndex, PluginSchemaTable,
};
use serde_json::json;

pub(crate) fn schema_tables(schema: &OAuthProviderSchema) -> Vec<PluginSchemaTable> {
    DEFINITIONS
        .iter()
        .map(|definition| schema_table(definition, model_config(schema, definition.model)))
        .collect()
}

fn schema_table(
    definition: &ModelDefinition,
    config: &OAuthProviderModelSchema,
) -> PluginSchemaTable {
    let model = definition.model;
    let mut table = PluginSchemaTable::new(definition.logical_name);
    if model == OAuthProviderModel::ClientAssertion {
        table = table.id_type(DatabaseIdType::String);
    }
    let default_model_name = (definition.model != OAuthProviderModel::RefreshToken)
        .then_some(definition.logical_name);
    if let Some(model_name) = config
        .model_name
        .as_deref()
        .filter(|name| !name.is_empty())
        .or(default_model_name)
    {
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
    for fields in definition.unique {
        table = table.index(DatabaseSchemaIndex::new(fields.iter().copied()).unique(true));
    }
    table
}

fn field(definition: &FieldDefinition, model: OAuthProviderModel) -> AdditionalField {
    let mut field = AdditionalField::new(field_type(model, definition.logical));
    if !required(model, definition.logical) {
        field = field.optional();
    }
    if unique(model, definition.logical) {
        field = field.unique(true);
    }
    if definition.index {
        field = field.index(true);
    }
    if matches!(
        definition.logical,
        "disabled" | "dpopBoundAccessTokens" | "dpopBoundAccessTokensRequired"
    ) {
        field = field.default_value(json!(false));
    } else if definition.logical == "policyVersion" {
        field = field.default_value(json!(1));
    } else if definition.logical == "clientCredentialsScopes" {
        field = field.default_value(json!([]));
    }
    if let Some(reference) = definition.reference {
        field = field.references(reference_field(reference, definition.on_delete));
    }
    field
}

fn required(model: OAuthProviderModel, logical: &str) -> bool {
    match model {
        OAuthProviderModel::Client => matches!(logical, "clientId" | "redirectUris"),
        OAuthProviderModel::Resource => matches!(logical, "identifier" | "name"),
        OAuthProviderModel::ClientResource => matches!(logical, "clientId" | "resourceId"),
        OAuthProviderModel::RefreshToken => matches!(
            logical,
            "token" | "clientId" | "userId" | "expiresAt" | "createdAt" | "scopes"
        ),
        OAuthProviderModel::AccessToken => matches!(
            logical,
            "token" | "clientId" | "expiresAt" | "createdAt" | "scopes"
        ),
        OAuthProviderModel::Consent => {
            matches!(logical, "clientId" | "scopes" | "createdAt" | "updatedAt")
        }
        OAuthProviderModel::ClientAssertion => logical == "expiresAt",
    }
}

fn unique(model: OAuthProviderModel, logical: &str) -> bool {
    matches!(
        (model, logical),
        (OAuthProviderModel::Client, "clientId")
            | (OAuthProviderModel::Resource, "identifier")
            | (OAuthProviderModel::RefreshToken, "token")
            | (OAuthProviderModel::AccessToken, "token")
    )
}

fn field_type(model: OAuthProviderModel, logical: &str) -> AdditionalFieldType {
    if matches!(
        (model, logical),
        (OAuthProviderModel::Client, "disabled" | "skipConsent" | "enableEndSession" | "backchannelLogoutSessionRequired" | "requirePKCE" | "dpopBoundAccessTokens")
            | (OAuthProviderModel::Resource, "dpopBoundAccessTokensRequired" | "disabled")
    ) {
        AdditionalFieldType::Boolean
    } else if model == OAuthProviderModel::Resource
        && matches!(logical, "accessTokenTtl" | "refreshTokenTtl" | "policyVersion")
    {
        AdditionalFieldType::Number
    } else if matches!(
        logical,
        "scopes"
            | "clientCredentialsScopes"
            | "contacts"
            | "redirectUris"
            | "postLogoutRedirectUris"
            | "grantTypes"
            | "responseTypes"
            | "allowedScopes"
            | "resources"
            | "requestedUserInfoClaims"
    ) {
        AdditionalFieldType::StringArray
    } else if matches!(logical, "metadata" | "customClaims" | "confirmation") {
        AdditionalFieldType::Json
    } else if matches!(
        logical,
        "createdAt"
            | "updatedAt"
            | "expiresAt"
            | "revoked"
            | "rotatedAt"
            | "rotationReplayExpiresAt"
            | "authTime"
    ) {
        AdditionalFieldType::Date
    } else {
        AdditionalFieldType::String
    }
}

fn reference_field(
    reference: Reference,
    on_delete: Option<&'static str>,
) -> AdditionalFieldReference {
    let (model, field) = match reference {
        Reference::Core(model) => (model, "id"),
        Reference::Provider(model, field) => (logical_name(model), field),
    };
    AdditionalFieldReference {
        model: model.into(),
        field: field.into(),
        on_delete: on_delete.map(|action| match action {
            "CASCADE" => AdditionalFieldOnDelete::Cascade,
            "SET NULL" => AdditionalFieldOnDelete::SetNull,
            _ => unreachable!("OAuth Provider has only pinned CASCADE and SET NULL actions"),
        }),
    }
}

fn logical_name(model: OAuthProviderModel) -> &'static str {
    DEFINITIONS
        .iter()
        .find(|definition| definition.model == model)
        .expect("every OAuth Provider model has one definition")
        .logical_name
}

fn model_config(
    schema: &OAuthProviderSchema,
    model: OAuthProviderModel,
) -> &OAuthProviderModelSchema {
    match model {
        OAuthProviderModel::Client => &schema.oauth_client,
        OAuthProviderModel::Resource => &schema.oauth_resource,
        OAuthProviderModel::ClientResource => &schema.oauth_client_resource,
        OAuthProviderModel::RefreshToken => &schema.oauth_refresh_token,
        OAuthProviderModel::AccessToken => &schema.oauth_access_token,
        OAuthProviderModel::Consent => &schema.oauth_consent,
        OAuthProviderModel::ClientAssertion => &schema.oauth_client_assertion,
    }
}

#[cfg(test)]
mod catalog_tests {
    use super::*;

    #[test]
    fn exact_order_model_names_references_and_unique_index() {
        let tables = schema_tables(&OAuthProviderSchema::default());
        assert_eq!(
            tables
                .iter()
                .map(|table| table.logical_name.as_str())
                .collect::<Vec<_>>(),
            [
                "oauthClient",
                "oauthResource",
                "oauthClientResource",
                "oauthRefreshToken",
                "oauthAccessToken",
                "oauthConsent",
                "oauthClientAssertion",
            ]
        );
        assert!(tables[0].model_name.is_some());
        assert!(tables[3].model_name.is_none());
        assert_eq!(tables[6].id_type, Some(DatabaseIdType::String));
        assert_eq!(tables[2].indexes.len(), 1);
        assert_eq!(tables[2].indexes[0].fields, ["clientId", "resourceId"]);
        assert!(tables[2].indexes[0].unique);
        assert_eq!(
            tables[3].fields["sessionId"]
                .references
                .as_ref()
                .unwrap()
                .on_delete,
            Some(AdditionalFieldOnDelete::SetNull)
        );
        assert_eq!(
            tables[3].fields["userId"]
                .references
                .as_ref()
                .unwrap()
                .on_delete,
            None
        );
        assert!(!tables[0].fields["disabled"].required);
        assert_eq!(
            tables[0].fields["disabled"].static_default_value(),
            Some(&json!(false))
        );
        assert!(!tables[1].fields["policyVersion"].required);
        assert!(!tables[1].fields["policyVersion"].bigint);
        assert!(!tables[1].fields["accessTokenTtl"].bigint);
    }

    #[test]
    fn remaps_are_truthy_and_unknown_fields_are_ignored() {
        let mut schema = OAuthProviderSchema::default();
        schema.oauth_client.model_name = Some("clients".into());
        schema.oauth_client.fields.insert("clientId".into(), "".into());
        schema.oauth_client.fields.insert("unknown".into(), "invented".into());
        let table = schema_tables(&schema).remove(0);
        assert_eq!(table.model_name.as_deref(), Some("clients"));
        assert_eq!(table.fields["clientId"].field_name, None);
        assert!(!table.fields.contains_key("unknown"));
    }
}
