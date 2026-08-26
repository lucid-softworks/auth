use super::PostgresStripeStore;
use crate::{
    AuthConfig, AuthSchemaCatalog, AuthStore,
    postgres::{PostgresAdapterConfig, PostgresStore},
    stripe::{StripeModelSchema, StripeSchema, schema_tables},
};
use sqlx::postgres::PgPoolOptions;
use std::{collections::BTreeMap, sync::Arc};

pub(super) fn store() -> PostgresStripeStore {
    let mut auth = AuthConfig::new([51; 32]).unwrap();
    auth.user.model_name = Some("billing\"users".into());
    let schema = StripeSchema {
        user: remap("billing\"users", [("stripeCustomerId", "stripe customer")]),
        organization: remap("billing\"orgs", [("stripeCustomerId", "stripe customer")]),
        subscription: remap(
            "billing\"subscriptions",
            [
                ("referenceId", "owner id"),
                ("stripeSubscriptionId", "provider id"),
                ("createdAt", "ignored"),
            ],
        ),
    };
    let catalog =
        Arc::new(AuthSchemaCatalog::build(&auth, schema_tables(&schema, true, true)).unwrap());
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/lucid_auth")
        .unwrap();
    let postgres = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
    postgres.bind_schema(catalog).unwrap();
    PostgresStripeStore::new(postgres)
}

pub(super) fn plural_store() -> PostgresStripeStore {
    let auth = AuthConfig::new([54; 32]).unwrap();
    let schema = StripeSchema::default();
    let catalog =
        Arc::new(AuthSchemaCatalog::build(&auth, schema_tables(&schema, true, false)).unwrap());
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://localhost/lucid_auth")
        .unwrap();
    let postgres = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
    postgres.bind_schema(catalog).unwrap();
    PostgresStripeStore::new(postgres)
}

fn remap<const N: usize>(model: &str, fields: [(&str, &str); N]) -> StripeModelSchema {
    StripeModelSchema {
        model_name: Some(model.into()),
        fields: BTreeMap::from_iter(
            fields.map(|(logical, physical)| (logical.into(), physical.into())),
        ),
    }
}
