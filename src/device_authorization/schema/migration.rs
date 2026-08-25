use super::{OAUTH_FIELDS, ResolvedDeviceAuthorizationSchema, STANDALONE_FIELDS};

pub(super) fn render_migration(schema: &ResolvedDeviceAuthorizationSchema) -> String {
    let model = schema.model();
    let mut sql = format!(
        "CREATE TABLE IF NOT EXISTS {} (\n    \"id\" UUID PRIMARY KEY",
        model.table()
    );
    for (logical, _, field_sql) in STANDALONE_FIELDS {
        sql.push_str(&format!(",\n    {} {}", model.column(logical), field_sql));
    }
    if schema.oauth_mode() {
        for (logical, _, field_sql) in OAUTH_FIELDS {
            sql.push_str(&format!(",\n    {} {}", model.column(logical), field_sql));
        }
    }
    sql.push_str("\n);\n");
    sql
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_authorization::{DeviceAuthorizationModelSchema, DeviceAuthorizationSchema};
    use std::collections::BTreeMap;

    #[test]
    fn standalone_schema_excludes_oauth_grant_fields() {
        let schema =
            ResolvedDeviceAuthorizationSchema::new(&DeviceAuthorizationSchema::default(), false)
                .unwrap();
        let sql = schema.migration_sql();
        assert!(sql.contains("\"device_code\" TEXT NOT NULL UNIQUE"));
        assert!(!sql.contains("\"resources\""));
        assert!(!sql.contains("\"oauth_client_id\""));
    }

    #[test]
    fn oauth_effective_schema_adds_only_grant_owned_fields() {
        let schema =
            ResolvedDeviceAuthorizationSchema::new(&DeviceAuthorizationSchema::default(), true)
                .unwrap();
        let sql = schema.migration_sql();
        assert!(sql.contains("\"resources\" TEXT[]"));
        assert!(sql.contains("\"oauth_client_id\" TEXT"));
    }

    #[test]
    fn standalone_model_and_fields_are_remappable_and_quoted() {
        let schema = DeviceAuthorizationSchema {
            device_code: DeviceAuthorizationModelSchema {
                model_name: Some("device requests".into()),
                fields: BTreeMap::from([
                    ("deviceCode".into(), "device\"secret".into()),
                    ("userCode".into(), "user secret".into()),
                ]),
            },
        };
        let sql = ResolvedDeviceAuthorizationSchema::new(&schema, false)
            .unwrap()
            .migration_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS \"device requests\""));
        assert!(sql.contains("\"device\"\"secret\" TEXT NOT NULL UNIQUE"));
        assert!(sql.contains("\"user secret\" TEXT NOT NULL UNIQUE"));
    }

    #[test]
    fn oauth_fields_cannot_be_added_to_standalone_schema_options() {
        let schema = DeviceAuthorizationSchema {
            device_code: DeviceAuthorizationModelSchema {
                fields: BTreeMap::from([("resources".into(), "custom_resources".into())]),
                ..DeviceAuthorizationModelSchema::default()
            },
        };
        assert!(ResolvedDeviceAuthorizationSchema::new(&schema, true).is_err());
    }
}
