use lucid_auth::{
    DatabaseSsoStore, NewSsoProvider, SsoProviderUpdate, SsoStore, postgres::PostgresStore,
};
use serde_json::{Map, json};
use std::sync::Arc;

pub(super) async fn assert_persistence(
    store: &Arc<PostgresStore>,
    owner_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let providers = DatabaseSsoStore::new(store.clone());
    let created = providers
        .create(NewSsoProvider {
            id: "postgres-sso-provider".into(),
            issuer: "https://idp.enterprise.example".into(),
            oidc_config: Some(json!({
                "clientId": "postgres-client",
                "clientSecret": "plaintext-upstream"
            })),
            saml_config: None,
            user_id: owner_id.into(),
            provider_id: "postgres-workforce".into(),
            organization_id: None,
            domain: "enterprise.example".into(),
            domain_verified: None,
            additional_fields: Map::from_iter([("tenantCode".into(), json!("blue"))]),
        })
        .await?;
    assert_eq!(created.additional_fields["tenantCode"], "blue");
    assert_eq!(
        providers.find_by_provider_id("postgres-workforce").await?,
        Some(created)
    );

    let updated = providers
        .update(
            "postgres-sso-provider",
            SsoProviderUpdate {
                domain: Some("login.enterprise.example".into()),
                additional_fields: Map::from_iter([("tenantCode".into(), json!("green"))]),
                ..SsoProviderUpdate::default()
            },
        )
        .await?;
    assert_eq!(updated.domain, "login.enterprise.example");
    assert_eq!(updated.additional_fields["tenantCode"], "green");
    assert!(providers.delete("postgres-sso-provider").await?.is_some());
    Ok(())
}
