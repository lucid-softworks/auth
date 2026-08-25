use super::{DEFINITIONS, Reference, ResolvedAgentAuthSchema};
use sha2::{Digest, Sha256};

pub(super) fn render_migration(schema: &ResolvedAgentAuthSchema) -> String {
    let mut sql = String::new();
    for definition in DEFINITIONS {
        let model = schema.model(definition.model);
        sql.push_str(&format!(
            "CREATE TABLE IF NOT EXISTS {} (\n    \"id\" TEXT PRIMARY KEY",
            model.table()
        ));
        for field in definition.fields {
            sql.push_str(&format!(
                ",\n    {} {}",
                model.column(field.logical),
                field.sql
            ));
            if let Some(reference) = field.reference {
                let (table, column) = reference_target(schema, reference);
                sql.push_str(&format!(" REFERENCES {table}({column}) ON DELETE CASCADE"));
            }
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

fn reference_target(
    schema: &ResolvedAgentAuthSchema,
    reference: Reference,
) -> (String, &'static str) {
    match reference {
        Reference::CoreUser => ("\"lucid_auth_users\"".to_owned(), "\"id\""),
        Reference::AgentAuth(target) => (schema.model(target).table().to_owned(), "\"id\""),
    }
}

fn index_name(schema: &ResolvedAgentAuthSchema, model: &str, field: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(schema.fingerprint().as_bytes());
    digest.update(model.as_bytes());
    digest.update(field.as_bytes());
    let suffix = &hex::encode(digest.finalize())[..10];
    format!("\"lucid_auth_agent_{model}_{field}_{suffix}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::{AgentAuthModelSchema, AgentAuthSchema};
    use std::collections::BTreeMap;

    #[test]
    fn default_migration_matches_the_four_upstream_models() {
        let schema = ResolvedAgentAuthSchema::new(&AgentAuthSchema::default()).unwrap();
        let sql = schema.migration_sql();
        for table in [
            "lucid_auth_agent_hosts",
            "lucid_auth_agents",
            "lucid_auth_agent_capability_grants",
            "lucid_auth_agent_approval_requests",
        ] {
            assert!(sql.contains(&format!("CREATE TABLE IF NOT EXISTS \"{table}\"")));
        }
        assert!(sql.contains("\"status\" TEXT NOT NULL DEFAULT 'active'"));
        assert!(sql.contains("\"mode\" TEXT NOT NULL DEFAULT 'delegated'"));
        assert!(sql.contains("\"status\" TEXT NOT NULL DEFAULT 'pending'"));
        assert!(sql.contains("\"interval\" DOUBLE PRECISION NOT NULL"));
        assert_eq!(sql.matches("CREATE INDEX IF NOT EXISTS").count(), 16);
    }

    #[test]
    fn custom_names_are_quoted_and_propagated_into_foreign_keys() {
        let schema = AgentAuthSchema {
            agent_host: AgentAuthModelSchema {
                model_name: Some("Agent Hosts".into()),
                fields: BTreeMap::from([("status".into(), "host\"status".into())]),
            },
            agent: AgentAuthModelSchema {
                model_name: Some("Agents".into()),
                fields: BTreeMap::from([("hostId".into(), "host key".into())]),
            },
            ..AgentAuthSchema::default()
        };
        let sql = ResolvedAgentAuthSchema::new(&schema)
            .unwrap()
            .migration_sql();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS \"Agent Hosts\""));
        assert!(sql.contains("\"host\"\"status\" TEXT NOT NULL DEFAULT 'active'"));
        assert!(sql.contains(
            "\"host key\" TEXT NOT NULL REFERENCES \"Agent Hosts\"(\"id\") ON DELETE CASCADE"
        ));
    }

    #[test]
    fn every_upstream_reference_cascades() {
        let sql = ResolvedAgentAuthSchema::new(&AgentAuthSchema::default())
            .unwrap()
            .migration_sql();
        assert_eq!(sql.matches("REFERENCES").count(), 9);
        assert_eq!(sql.matches("ON DELETE CASCADE").count(), 9);
    }

    #[test]
    fn no_private_key_or_invented_secret_columns_are_created() {
        let sql = ResolvedAgentAuthSchema::new(&AgentAuthSchema::default())
            .unwrap()
            .migration_sql();
        assert!(!sql.contains("private_key"));
        assert!(!sql.contains("agent_secret"));
        assert!(sql.contains("\"enrollment_token_hash\" TEXT"));
        assert!(sql.contains("\"user_code_hash\" TEXT"));
    }
}
