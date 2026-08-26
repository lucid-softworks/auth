use super::PostgresAgentAuthStore;
use crate::{
    AuthConfig, AuthSchemaCatalog, AuthStore,
    agent_auth::{AgentAuthModelSchema, AgentAuthSchema, schema::schema_tables},
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn store() -> PostgresAgentAuthStore {
    let auth = AuthConfig::new([61; 32]).unwrap();
    let schema = AgentAuthSchema {
        agent_host: mapping(
            "host\"records",
            [
                ("publicKey", "host key"),
                ("enrollmentTokenHash", "enrollment hash"),
            ],
        ),
        agent: mapping(
            "agent\"records",
            [
                ("name", "select\"name"),
                ("hostId", "host key"),
                ("publicKey", "public key"),
                ("updatedAt", "changed at"),
            ],
        ),
        agent_capability_grant: mapping(
            "grant\"records",
            [
                ("agentId", "agent key"),
                ("capability", "capability name"),
                ("status", "grant state"),
            ],
        ),
        approval_request: mapping(
            "approval\"records",
            [
                ("agentId", "agent key"),
                ("status", "approval state"),
                ("userCodeHash", "user code hash"),
            ],
        ),
    };
    let catalog = Arc::new(AuthSchemaCatalog::build(&auth, schema_tables(&schema)).unwrap());
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/lucid_auth")
        .unwrap();
    let postgres = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
    postgres.bind_schema(catalog).unwrap();
    PostgresAgentAuthStore::new(postgres)
}

fn mapping<const N: usize>(model: &str, fields: [(&str, &str); N]) -> AgentAuthModelSchema {
    AgentAuthModelSchema {
        model_name: Some(model.into()),
        fields: BTreeMap::from_iter(
            fields.map(|(logical, physical)| (logical.into(), physical.into())),
        ),
    }
}
