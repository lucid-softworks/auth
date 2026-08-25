fn render_migration(schema: &ResolvedOAuthProviderSchema) -> String {
    let mut sql = String::new();
    for definition in DEFINITIONS {
        let model = schema.model(definition.model);
        sql.push_str(&format!(
            "CREATE TABLE IF NOT EXISTS {} (\n    \"id\" {} PRIMARY KEY",
            model.table(),
            definition.id_sql
        ));
        for field in definition.fields {
            sql.push_str(&format!(
                ",\n    {} {}",
                model.column(field.logical),
                field.sql
            ));
            if let Some(reference) = field.reference {
                let (table, column) = match reference {
                    Reference::Core(table) => (format!("\"{table}\""), "\"id\""),
                    Reference::Provider(target, logical) => {
                        let target = schema.model(target);
                        (target.table().to_owned(), target.column(logical))
                    }
                };
                sql.push_str(&format!(" REFERENCES {table}({column})"));
                if let Some(on_delete) = field.on_delete {
                    sql.push_str(&format!(" ON DELETE {on_delete}"));
                }
            }
        }
        for (column, column_sql) in definition.extra_columns {
            sql.push_str(&format!(",\n    \"{column}\" {column_sql}"));
        }
        for fields in definition.unique {
            let fields = fields
                .iter()
                .map(|field| model.column(field))
                .collect::<Vec<_>>()
                .join(", ");
            sql.push_str(&format!(",\n    UNIQUE ({fields})"));
        }
        sql.push_str("\n);\n");
        for field in definition.fields.iter().filter(|field| field.index) {
            let index = index_name(schema, definition.logical_name, field.logical);
            sql.push_str(&format!(
                "CREATE INDEX IF NOT EXISTS {index} ON {}({});\n",
                model.table(),
                model.column(field.logical)
            ));
        }
        sql.push('\n');
    }
    sql
}

fn index_name(schema: &ResolvedOAuthProviderSchema, model: &str, field: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(schema.fingerprint.as_bytes());
    digest.update(model.as_bytes());
    digest.update(field.as_bytes());
    let suffix = &hex::encode(digest.finalize())[..10];
    let model = model.trim_start_matches("oauth").to_ascii_lowercase();
    let field = field.to_ascii_lowercase();
    format!("\"lucid_auth_oauth_{model}_{field}_{suffix}\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_names_are_quoted_and_used_in_foreign_keys() {
        let mut schema = OAuthProviderSchema::default();
        schema.oauth_client.model_name = Some("Client Records".into());
        schema
            .oauth_client
            .fields
            .insert("clientId".into(), "client\"key".into());
        schema.oauth_client_resource.model_name = Some("Client Resources".into());
        schema
            .oauth_client_resource
            .fields
            .insert("clientId".into(), "client key".into());
        let sql = migration(&schema).unwrap().sql.into_owned();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS \"Client Records\""));
        assert!(sql.contains("\"client\"\"key\" TEXT NOT NULL UNIQUE"));
        assert!(sql.contains(
            "\"client key\" TEXT NOT NULL REFERENCES \"Client Records\"(\"client\"\"key\")"
        ));
    }

    #[test]
    fn unknown_and_unsafe_mappings_are_rejected() {
        let mut schema = OAuthProviderSchema::default();
        schema
            .oauth_client
            .fields
            .insert("requirePkce".into(), "wrong_case".into());
        assert!(matches!(
            ResolvedOAuthProviderSchema::new(&schema),
            Err(OAuthProviderConfigError::UnknownSchemaField { .. })
        ));
        schema.oauth_client.fields.clear();
        schema.oauth_client.model_name = Some("bad\0table".into());
        assert!(matches!(
            ResolvedOAuthProviderSchema::new(&schema),
            Err(OAuthProviderConfigError::InvalidSchemaIdentifier { .. })
        ));

        schema.oauth_client.model_name = Some(String::new());
        assert!(matches!(
            ResolvedOAuthProviderSchema::new(&schema),
            Err(OAuthProviderConfigError::InvalidSchemaIdentifier { .. })
        ));
        schema.oauth_client.model_name = Some("x".repeat(64));
        assert!(matches!(
            ResolvedOAuthProviderSchema::new(&schema),
            Err(OAuthProviderConfigError::InvalidSchemaIdentifier { .. })
        ));
    }

    #[test]
    fn all_seven_models_and_every_declared_field_can_be_remapped() {
        let mut schema = OAuthProviderSchema::default();
        for definition in DEFINITIONS {
            let configured = match definition.model {
                OAuthProviderModel::Client => &mut schema.oauth_client,
                OAuthProviderModel::Resource => &mut schema.oauth_resource,
                OAuthProviderModel::ClientResource => &mut schema.oauth_client_resource,
                OAuthProviderModel::RefreshToken => &mut schema.oauth_refresh_token,
                OAuthProviderModel::AccessToken => &mut schema.oauth_access_token,
                OAuthProviderModel::Consent => &mut schema.oauth_consent,
                OAuthProviderModel::ClientAssertion => &mut schema.oauth_client_assertion,
            };
            configured.model_name = Some(format!("mapped_{}", definition.logical_name));
            for field in definition.fields {
                configured
                    .fields
                    .insert(field.logical.into(), format!("mapped_{}", field.logical));
            }
        }
        let resolved = ResolvedOAuthProviderSchema::new(&schema).unwrap();
        for definition in DEFINITIONS {
            let model = resolved.model(definition.model);
            assert_eq!(model.fields.len(), definition.fields.len());
            assert!(
                model
                    .table()
                    .contains(&format!("mapped_{}", definition.logical_name))
            );
            for field in definition.fields {
                assert_eq!(
                    model.column(field.logical),
                    format!("\"mapped_{}\"", field.logical)
                );
            }
        }
        let sql = resolved.migration_sql();
        assert!(!sql.contains("lucid_auth_oauth_clients"));
        assert!(sql.contains("\"mapped_requirePKCE\" BOOLEAN"));
        assert!(sql.contains("\"mapped_expiresAt\" TIMESTAMPTZ NOT NULL"));
    }
}
