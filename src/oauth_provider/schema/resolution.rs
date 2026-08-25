#[derive(Debug, Clone)]
pub(crate) struct ResolvedModel {
    table: Identifier,
    fields: BTreeMap<&'static str, Identifier>,
}

impl ResolvedModel {
    pub(crate) fn table(&self) -> &str {
        &self.table.quoted
    }

    pub(crate) fn column(&self, logical: &str) -> &str {
        if logical == "id" {
            return "\"id\"";
        }
        if logical == "__clientExpiresAt" {
            return "\"expires_at\"";
        }
        &self
            .fields
            .get(logical)
            .expect("OAuth Provider SQL requested a declared Better Auth field")
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
pub(crate) struct ResolvedOAuthProviderSchema {
    models: BTreeMap<OAuthProviderModel, ResolvedModel>,
    fingerprint: String,
}

impl ResolvedOAuthProviderSchema {
    pub(crate) fn new(schema: &OAuthProviderSchema) -> Result<Self, OAuthProviderConfigError> {
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
                return Err(OAuthProviderConfigError::DuplicateSchemaIdentifier {
                    kind: "model",
                    identifier: table.raw,
                });
            }
            let known: BTreeSet<_> = definition
                .fields
                .iter()
                .map(|field| field.logical)
                .collect();
            for field in configured.fields.keys() {
                if !known.contains(field.as_str()) {
                    return Err(OAuthProviderConfigError::UnknownSchemaField {
                        model: definition.logical_name.to_owned(),
                        field: field.clone(),
                    });
                }
            }
            let mut fields = BTreeMap::new();
            let mut physical_fields = BTreeSet::from(["id".to_owned()]);
            physical_fields.extend(
                definition
                    .extra_columns
                    .iter()
                    .map(|(column, _)| (*column).to_owned()),
            );
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
                    return Err(OAuthProviderConfigError::DuplicateSchemaIdentifier {
                        kind: "field",
                        identifier: format!("{}.{}", table.raw, identifier.raw),
                    });
                }
                fields.insert(field.logical, identifier);
            }
            models.insert(definition.model, ResolvedModel { table, fields });
        }
        let fingerprint = schema_fingerprint(&models);
        Ok(Self {
            models,
            fingerprint,
        })
    }

    pub(crate) fn model(&self, model: OAuthProviderModel) -> &ResolvedModel {
        self.models
            .get(&model)
            .expect("all OAuth Provider models are resolved")
    }

    pub(crate) fn migration_sql(&self) -> String {
        render_migration(self)
    }
}

#[derive(Debug, Clone)]
struct Identifier {
    raw: String,
    quoted: String,
}

impl Identifier {
    fn new(kind: &'static str, value: &str) -> Result<Self, OAuthProviderConfigError> {
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
            return Err(OAuthProviderConfigError::InvalidSchemaIdentifier {
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

fn configured_model(
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

fn schema_fingerprint(models: &BTreeMap<OAuthProviderModel, ResolvedModel>) -> String {
    let mut digest = Sha256::new();
    for (key, model) in models {
        digest.update(format!("{key:?}:{};", model.table.raw));
        for (logical, field) in &model.fields {
            digest.update(format!("{logical}:{};", field.raw));
        }
    }
    hex::encode(digest.finalize())[..12].to_owned()
}

pub(crate) fn migration(
    schema: &OAuthProviderSchema,
) -> Result<PluginMigration, OAuthProviderConfigError> {
    let resolved = ResolvedOAuthProviderSchema::new(schema)?;
    let default = ResolvedOAuthProviderSchema::new(&OAuthProviderSchema::default())?;
    let id = if resolved.fingerprint == default.fingerprint {
        "better-auth-oauth-provider-schema".to_owned()
    } else {
        format!("better-auth-oauth-provider-schema-{}", resolved.fingerprint)
    };
    Ok(PluginMigration::owned(
        id,
        "Better Auth 1.7.1 OAuth Provider schema",
        resolved.migration_sql(),
    ))
}
