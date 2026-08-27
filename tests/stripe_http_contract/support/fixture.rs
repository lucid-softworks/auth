use super::{FakeStripeClient, models::plan};
use axum::Router;
use lucid_auth::{
    AuthConfig, AuthService, MemoryStore, MemoryStripeStore, NewPasswordUser, ReferenceAuthorizer,
    StaticPlans, StripePlugin, SubscriptionConfiguration, SubscriptionOptions,
};
use std::sync::Arc;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) stripe: Arc<MemoryStripeStore>,
    pub(crate) client: Arc<FakeStripeClient>,
    pub(crate) cookie: String,
    pub(crate) user_id: String,
}

pub(crate) async fn fixture(authorizer: Option<Arc<dyn ReferenceAuthorizer>>) -> Fixture {
    let stripe = Arc::new(MemoryStripeStore::new());
    let client = Arc::new(FakeStripeClient::default());
    let mut subscription = SubscriptionOptions::new(Arc::new(StaticPlans(vec![plan()])));
    subscription.authorize_reference = authorizer;
    let mut options = lucid_auth::StripeOptions::new(client.clone(), "whsec_contract");
    options.subscription = SubscriptionConfiguration::Enabled(subscription);

    let mut config = AuthConfig::new([164_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(StripePlugin::new(options, stripe.clone()))
        .unwrap();
    let service = Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config)
            .expect("Stripe plugin configuration is valid"),
    );
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "stripe_owner".into(),
            name: "Stripe Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "stripe_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let cookie = format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(&signed_in.token)
    );
    Fixture {
        app: lucid_auth::axum::router(service),
        stripe,
        client,
        cookie,
        user_id: user.id,
    }
}

pub(crate) fn disabled_app() -> Router {
    let options =
        lucid_auth::StripeOptions::new(Arc::new(FakeStripeClient::default()), "whsec_contract");
    let mut config = AuthConfig::new([165_u8; 32]).unwrap();
    config
        .add_plugin(StripePlugin::new(
            options,
            Arc::new(MemoryStripeStore::new()),
        ))
        .unwrap();
    lucid_auth::axum::router(Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap(),
    ))
}
