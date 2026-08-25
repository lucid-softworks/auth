use crate::agent_auth::schema::{AgentAuthModel, ResolvedAgentAuthSchema};

pub(super) fn insert(
    schema: &ResolvedAgentAuthSchema,
    model: AgentAuthModel,
    fields: &[(&str, &str)],
) -> String {
    let model = schema.model(model);
    let placeholders = (1..=fields.len())
        .map(|index| format!("${index}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "INSERT INTO {} ({}) VALUES ({placeholders}) RETURNING {}",
        model.table(),
        model.columns(fields),
        model.projection(fields),
    )
}

pub(super) fn update(
    schema: &ResolvedAgentAuthSchema,
    model: AgentAuthModel,
    fields: &[(&str, &str)],
) -> String {
    let model = schema.model(model);
    let assignments = fields[1..]
        .iter()
        .enumerate()
        .map(|(index, (logical, _))| format!("{}=${}", model.column(logical), index + 2))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "UPDATE {} SET {assignments} WHERE \"id\"=$1 RETURNING {}",
        model.table(),
        model.projection(fields),
    )
}

pub(super) fn select(
    schema: &ResolvedAgentAuthSchema,
    model: AgentAuthModel,
    fields: &[(&str, &str)],
    predicates: &[&str],
    suffix: &str,
) -> String {
    let model = schema.model(model);
    let predicates = predicates
        .iter()
        .enumerate()
        .map(|(index, logical)| format!("{}=${}", model.column(logical), index + 1))
        .collect::<Vec<_>>()
        .join(" AND ");
    format!(
        "SELECT {} FROM {} WHERE {predicates}{suffix}",
        model.projection(fields),
        model.table(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::{AgentAuthModelSchema, AgentAuthSchema};
    use std::collections::BTreeMap;

    #[test]
    fn builders_quote_and_apply_complete_remapping() {
        let schema = AgentAuthSchema {
            agent: AgentAuthModelSchema {
                model_name: Some("Agent Records".into()),
                fields: BTreeMap::from([
                    ("name".into(), "display name".into()),
                    ("hostId".into(), "host\"id".into()),
                ]),
            },
            ..AgentAuthSchema::default()
        };
        let schema = ResolvedAgentAuthSchema::new(&schema).unwrap();
        let fields = &[("id", "id"), ("name", "name"), ("hostId", "host_id")];
        assert_eq!(
            insert(&schema, AgentAuthModel::Agent, fields),
            "INSERT INTO \"Agent Records\" (\"id\", \"display name\", \"host\"\"id\") VALUES ($1,$2,$3) RETURNING \"id\" AS \"id\", \"display name\" AS \"name\", \"host\"\"id\" AS \"host_id\""
        );
        assert_eq!(
            update(&schema, AgentAuthModel::Agent, fields),
            "UPDATE \"Agent Records\" SET \"display name\"=$2,\"host\"\"id\"=$3 WHERE \"id\"=$1 RETURNING \"id\" AS \"id\", \"display name\" AS \"name\", \"host\"\"id\" AS \"host_id\""
        );
        assert_eq!(
            select(
                &schema,
                AgentAuthModel::Agent,
                fields,
                &["hostId"],
                " LIMIT 1"
            ),
            "SELECT \"id\" AS \"id\", \"display name\" AS \"name\", \"host\"\"id\" AS \"host_id\" FROM \"Agent Records\" WHERE \"host\"\"id\"=$1 LIMIT 1"
        );
    }
}
