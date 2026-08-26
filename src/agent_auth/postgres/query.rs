use crate::{
    AuthError,
    postgres::{PostgresModel, PostgresWrite},
};
use serde_json::Value;
use sqlx::{Postgres, QueryBuilder};

pub(super) fn insert(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    for (index, write) in writes.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column());
    }
    query.push(") VALUES (");
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        write.push_bind(&mut query);
    }
    query.push(")");
    query
}

pub(super) fn update(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
    id: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    let writes = writes
        .into_iter()
        .filter(|write| write.logical() != "id")
        .collect::<Vec<_>>();
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column()).push(" = ");
        write.push_bind(&mut query);
    }
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", Value::String(id.to_owned()))?
        .push_bind(&mut query);
    Ok(query)
}

pub(super) fn select(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}

pub(super) fn filter(
    model: &PostgresModel<'_>,
    predicates: impl IntoIterator<Item = (&'static str, Value)>,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = select(model);
    query.push(" WHERE ");
    for (index, (field, value)) in predicates.into_iter().enumerate() {
        if index > 0 {
            query.push(" AND ");
        }
        query.push(model.quoted_column(field)?).push(" = ");
        model.encode(field, value)?.push_bind(&mut query);
    }
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_auth::{AgentIdentity, AgentMode, AgentStatus};
    use chrono::Utc;

    #[tokio::test]
    async fn create_find_update_and_atomic_lock_use_hostile_bound_schema() {
        let store = super::super::test_support::store();
        let model = store.model("agent").unwrap();
        let value = agent("value that must be bound");

        let insert = insert(
            &model,
            super::super::rows::agent_writes(&model, &value).unwrap(),
        );
        assert!(
            insert
                .sql()
                .starts_with("INSERT INTO \"agent\"\"recordss\"")
        );
        assert!(insert.sql().contains("\"select\"\"name\""));
        assert!(insert.sql().contains("\"host key\""));
        assert!(!insert.sql().contains(&value.name));

        let find = filter(&model, [("hostId", serde_json::json!(value.host_id))]).unwrap();
        assert!(find.sql().contains("FROM \"agent\"\"recordss\""));
        assert!(find.sql().contains("WHERE \"host key\" = $1"));
        assert!(!find.sql().contains("host value"));

        let update = update(
            &model,
            super::super::rows::agent_writes(&model, &value).unwrap(),
            &value.id,
        )
        .unwrap();
        assert!(update.sql().starts_with("UPDATE \"agent\"\"recordss\" SET"));
        assert!(update.sql().contains("\"changed at\" = $"));
        assert!(update.sql().contains("WHERE \"id\" = $"));
        assert!(!update.sql().contains(&value.id));

        let locked = super::super::transition::locked_agent_query(&model, &value.id).unwrap();
        assert!(locked.sql().contains("WHERE \"id\" = $1 FOR UPDATE"));
        assert!(!locked.sql().contains(&value.id));
    }

    fn agent(name: &str) -> AgentIdentity {
        let now = Utc::now();
        AgentIdentity {
            id: "agent value".into(),
            name: name.into(),
            user_id: None,
            host_id: "host value".into(),
            status: AgentStatus::Active,
            mode: AgentMode::Delegated,
            public_key: "public value".into(),
            kid: Some("kid value".into()),
            jwks_url: None,
            last_used_at: None,
            activated_at: None,
            expires_at: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        }
    }
}
