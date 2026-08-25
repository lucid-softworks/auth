use super::client::{FakeChargebeeClient, shared_client};
use axum::Router;
use lucid_auth::{
    AuthConfig, AuthService, ChargebeeOptions, ChargebeePlan, ChargebeePlanType, ChargebeePlugin,
    ChargebeeSubscriptionOptions, MemoryChargebeeStore, MemoryStore, NewPasswordUser,
    StaticChargebeePlans,
};
use serde_json::json;
use std::sync::Arc;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) client: Arc<FakeChargebeeClient>,
    pub(crate) store: Arc<MemoryChargebeeStore>,
    pub(crate) cookie: Option<String>,
    pub(crate) user_id: Option<uuid::Uuid>,
}

pub(crate) async fn fixture<F>(authenticated: bool, configure: F) -> Fixture
where
    F: FnOnce(&mut ChargebeeOptions),
{
    let client = shared_client();
    let auth_store = Arc::new(MemoryStore::default());
    let store = Arc::new(MemoryChargebeeStore::new(auth_store.clone()));
    let mut options = ChargebeeOptions::new(client.clone());
    options.subscription = Some(ChargebeeSubscriptionOptions::new(
        true,
        Arc::new(StaticChargebeePlans(vec![ChargebeePlan {
            name: "Pro".into(),
            item_price_id: "price_pro".into(),
            item_id: Some("pro".into()),
            item_family_id: None,
            plan_type: ChargebeePlanType::Plan,
            billing_cycles: None,
            free_trial: None,
            limits: Some(json!({"projects": 10})),
        }])),
    ));
    configure(&mut options);
    let mut config = AuthConfig::new([52_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(ChargebeePlugin::new(options, store.clone()))
        .unwrap();
    let service = Arc::new(AuthService::try_new(auth_store, config).unwrap());
    let (cookie, user_id) = authenticate(&service, authenticated).await;
    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        store,
        cookie,
        user_id,
    }
}

async fn authenticate(
    service: &Arc<AuthService>,
    authenticated: bool,
) -> (Option<String>, Option<uuid::Uuid>) {
    if !authenticated {
        return (None, None);
    }
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "chargebee_contract_owner".into(),
            name: "Chargebee Contract Owner".into(),
            email: Some("owner@example.test".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "chargebee_contract_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    (
        Some(format!(
            "better-auth.session_token={}",
            service.signed_cookie_value(&signed_in.token)
        )),
        Some(user.id),
    )
}
