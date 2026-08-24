use lucid_auth::{
    Auth0Options, BaseOAuthProviderOptions, GumroadOptions, HubSpotOptions, KeycloakOptions,
    LineOptions, MicrosoftEntraIdOptions, OktaOptions, PatreonOptions, SlackOptions, YandexOptions,
    auth0, gumroad, hubspot, keycloak, line, microsoft_entra_id, okta, patreon, slack, yandex,
};

#[test]
fn bundled_helpers_match_the_better_auth_1_7_1_presets() {
    let base = || BaseOAuthProviderOptions {
        client_id: "client".into(),
        client_secret: Some("secret".into()),
        ..BaseOAuthProviderOptions::default()
    };
    let auth0 = auth0(Auth0Options {
        base: base(),
        domain: "http://tenant.auth0.com///".into(),
    });
    assert_eq!(
        auth0.discovery_url.as_deref(),
        Some("https://tenant.auth0.com/.well-known/openid-configuration")
    );
    assert_eq!(
        auth0.account_issuer.as_deref(),
        Some("https://tenant.auth0.com/")
    );
    let gumroad = gumroad(GumroadOptions(base()));
    assert_eq!(gumroad.provider_id, "gumroad");
    assert_eq!(gumroad.scopes, ["view_profile"]);
    assert!(gumroad.get_user_info.is_some());
    let hubspot = hubspot(HubSpotOptions(base()));
    assert_eq!(
        hubspot.token_url.as_deref(),
        Some("https://api.hubapi.com/oauth/v1/token")
    );
    let keycloak = keycloak(KeycloakOptions {
        base: base(),
        issuer: "https://keycloak.example/".into(),
    });
    assert_eq!(
        keycloak.discovery_url.as_deref(),
        Some("https://keycloak.example/.well-known/openid-configuration")
    );
    let line = line(LineOptions {
        base: base(),
        provider_id: Some("line-jp".into()),
    });
    assert_eq!(line.provider_id, "line-jp");
    assert_eq!(
        line.account_issuer.as_deref(),
        Some("https://access.line.me")
    );
    let microsoft = microsoft_entra_id(MicrosoftEntraIdOptions {
        base: base(),
        tenant_id: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE".into(),
    })
    .unwrap();
    assert!(microsoft.require_id_token_verification);
    assert!(
        microsoft
            .discovery_url
            .as_deref()
            .unwrap()
            .contains("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    );
    assert!(
        microsoft_entra_id(MicrosoftEntraIdOptions {
            base: base(),
            tenant_id: "common".into(),
        })
        .is_err()
    );
    let okta = okta(OktaOptions {
        base: base(),
        issuer: "https://okta.example/".into(),
    });
    assert_eq!(okta.account_issuer.as_deref(), Some("https://okta.example"));
    assert_eq!(patreon(PatreonOptions(base())).scopes, ["identity[email]"]);
    assert_eq!(
        slack(SlackOptions(base())).user_info_url.as_deref(),
        Some("https://slack.com/api/openid.connect.userInfo")
    );
    assert_eq!(
        yandex(YandexOptions(base())).scopes,
        ["login:info", "login:email", "login:avatar"]
    );
}
