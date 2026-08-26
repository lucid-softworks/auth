use super::FakePolarClient;
use axum::Router;
use lucid_auth::{
    AnonymousPlugin, AnonymousPluginConfig, AuthConfig, AuthService, CheckoutOptions, MemoryStore,
    NewPasswordUser, PolarFeature, PolarOptions, PolarPlugin, PolarProduct, PolarProducts,
    PolarTheme, PortalOptions, UsageOptions, WebhooksOptions,
};
use std::sync::Arc;

pub(crate) struct Fixture {
    pub(crate) app: Router,
    pub(crate) client: Arc<FakePolarClient>,
    pub(crate) cookie: String,
    pub(crate) anonymous_cookie: String,
    pub(crate) user_id: String,
}

pub(crate) async fn fixture() -> Fixture {
    let client = Arc::new(FakePolarClient::default());
    let features = vec![
        PolarFeature::Checkout(CheckoutOptions {
            products: Some(PolarProducts::static_products(vec![PolarProduct::new(
                "product_pro",
                "pro",
            )])),
            success_url: Some("/configured-success".into()),
            return_url: None,
            authenticated_users_only: true,
            theme: Some(PolarTheme::Dark),
        }),
        PolarFeature::Portal(
            PortalOptions::new(
                Some("https://app.example.test/account%20home?next=a%2Fb"),
                Some(PolarTheme::Dark),
            )
            .unwrap(),
        ),
        PolarFeature::Usage(UsageOptions::default()),
        PolarFeature::Webhooks(WebhooksOptions::new("whsec_contract")),
    ];
    let mut config = AuthConfig::new([174_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(AnonymousPlugin::new(AnonymousPluginConfig::default()))
        .unwrap();
    config
        .add_plugin(PolarPlugin::new(PolarOptions::new(
            client.clone(),
            features,
        )))
        .unwrap();
    let service = Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config)
            .expect("Polar plugin configuration is valid"),
    );
    let user = service
        .provision_password_user(NewPasswordUser {
            username: "polar_owner".into(),
            name: "Polar Owner".into(),
            email: Some("owner@example.com".into()),
            password: "correct horse battery staple".into(),
            role: "owner".into(),
        })
        .await
        .unwrap();
    let signed_in = service
        .sign_in_username(
            "polar_owner",
            "correct horse battery staple".into(),
            None,
            None,
        )
        .await
        .unwrap();
    let anonymous = service.sign_in_anonymous(None, None).await.unwrap();
    let cookie = session_cookie(&service, &signed_in.token);
    let anonymous_cookie = session_cookie(&service, &anonymous.token);
    Fixture {
        app: lucid_auth::axum::router(service),
        client,
        cookie,
        anonymous_cookie,
        user_id: user.id,
    }
}

pub(crate) fn selective_app(features: Vec<PolarFeature>) -> Router {
    let client = Arc::new(FakePolarClient::default());
    let mut config = AuthConfig::new([175_u8; 32]).unwrap();
    config.set_base_url("http://localhost/api/auth").unwrap();
    config
        .add_plugin(PolarPlugin::new(PolarOptions::new(client, features)))
        .unwrap();
    lucid_auth::axum::router(Arc::new(
        AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap(),
    ))
}

fn session_cookie(service: &AuthService, token: &str) -> String {
    format!(
        "better-auth.session_token={}",
        service.signed_cookie_value(token)
    )
}
