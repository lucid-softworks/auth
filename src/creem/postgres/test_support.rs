use super::PostgresCreemStore;
use crate::{
    AuthConfig, AuthSchemaCatalog, AuthStore,
    creem::{CreemModelSchema, CreemSchema, creem_schema_tables},
    postgres::{PostgresAdapterConfig, PostgresStore},
};
use sqlx::postgres::PgPoolOptions;
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn store() -> PostgresCreemStore {
    let mut auth = AuthConfig::new([52; 32]).unwrap();
    auth.user.model_name = Some("creem\"users".into());
    let mut schema = CreemSchema::default();
    schema.insert_model(
        "user",
        mapping(
            "creem\"users",
            [
                ("creemCustomerId", "customer id"),
                ("hadTrial", "used trial"),
            ],
        ),
    );
    schema.insert_model(
        "creem_subscription",
        mapping(
            "creem\"subscriptions",
            [
                ("referenceId", "owner id"),
                ("creemSubscriptionId", "provider id"),
            ],
        ),
    );
    let catalog = Arc::new(
        AuthSchemaCatalog::build(&auth, creem_schema_tables(&schema, true).unwrap()).unwrap(),
    );
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/lucid_auth")
        .unwrap();
    let postgres = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
    postgres.bind_schema(catalog).unwrap();
    PostgresCreemStore::new(postgres)
}

fn mapping<const N: usize>(model: &str, fields: [(&str, &str); N]) -> CreemModelSchema {
    CreemModelSchema {
        model_name: Some(model.into()),
        fields: BTreeMap::from_iter(
            fields.map(|(logical, physical)| (logical.into(), physical.into())),
        ),
    }
}
