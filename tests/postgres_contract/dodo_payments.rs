use lucid_auth::{
    AuthConfig, AuthError, AuthPlugin, AuthService, AuthStore, DatabaseModel,
    DodoPaymentsHttpClient, DodoPaymentsOptions, DodoPaymentsPlugin, DodoPaymentsProviderConfig,
    UserProfileUpdate, postgres::PostgresStore,
};
use serde_json::{Map, Value};
use std::sync::Arc;
use uuid::Uuid;

pub(super) fn register(
    config: &mut AuthConfig,
    store: Arc<PostgresStore>,
) -> Result<(), AuthError> {
    let client = Arc::new(DodoPaymentsHttpClient::new(
        DodoPaymentsProviderConfig::test("dodo_postgres_contract"),
    ));
    let plugin = DodoPaymentsPlugin::new(DodoPaymentsOptions::new(client, Vec::new()), store);
    assert!(plugin.migrations().is_empty());
    config.add_plugin(plugin)
}

pub(super) async fn assert_schema_and_persistence(
    service: &AuthService,
    store: &PostgresStore,
    user_id: Uuid,
) -> Result<(), Box<dyn std::error::Error>> {
    let fields = service.database_schema_fields(DatabaseModel::User);
    let field = fields
        .get("dodoCustomerId")
        .expect("Dodo Payments contributes its customer field");
    assert!(!field.required);
    assert!(!field.input);

    store
        .update_user_profile(
            user_id,
            UserProfileUpdate {
                additional_fields: Map::from_iter([(
                    "dodoCustomerId".into(),
                    Value::String("customer_postgres".into()),
                )]),
                ..UserProfileUpdate::default()
            },
        )
        .await?;
    let stored = store
        .find_user_by_id(user_id)
        .await?
        .expect("Dodo Payments fixture user persists");
    assert_eq!(
        stored.additional_fields["dodoCustomerId"],
        "customer_postgres"
    );
    Ok(())
}
