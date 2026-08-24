use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AuthError, AuthService, AuthorizationRequest, MemoryStore, NewPasswordUser,
    OAuthTokens, OAuthUserInfo, SocialIdTokenInput, SocialProvider, SocialSignInInput,
    SocialSignInResult, UsernamePlugin,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use url::Url;

#[derive(Clone)]
struct AccountProvider {
    id: &'static str,
    subject: &'static str,
    email: &'static str,
    refreshes: Arc<AtomicUsize>,
}

#[async_trait]
impl SocialProvider for AccountProvider {
    fn id(&self) -> &str {
        self.id
    }
    fn issuer(&self) -> Option<&str> {
        Some("https://accounts.fixture")
    }
    fn requires_id_token_nonce(&self) -> bool {
        false
    }
    fn disable_implicit_sign_up(&self) -> bool {
        false
    }
    fn disable_sign_up(&self) -> bool {
        false
    }
    fn require_email_verification(&self) -> bool {
        false
    }
    fn supports_id_token_sign_in(&self) -> bool {
        true
    }
    fn supports_token_refresh(&self) -> bool {
        true
    }
    fn create_authorization_url(&self, _: &AuthorizationRequest) -> Result<Url, AuthError> {
        Url::parse("https://accounts.fixture/authorize").map_err(|_| AuthError::Worker)
    }
    async fn exchange_code(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        Err(AuthError::OAuthInvalidCode)
    }
    async fn get_user_info(
        &self,
        _: &OAuthTokens,
        _: Option<&str>,
        _: Option<&serde_json::Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        Ok(OAuthUserInfo {
            account_id: self.subject.into(),
            issuer: "https://accounts.fixture".into(),
            name: "Fixture User".into(),
            email: self.email.into(),
            email_verified: true,
            image: Some("fixture.png".into()),
            additional_fields: serde_json::Map::new(),
            profile: serde_json::Map::new(),
        })
    }
    async fn refresh_access_token(&self, _: &str) -> Result<OAuthTokens, AuthError> {
        tokio::task::yield_now().await;
        let generation = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(OAuthTokens {
            access_token: Some(format!("access-{generation}")),
            refresh_token: Some(format!("refresh-{generation}")),
            access_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..OAuthTokens::default()
        })
    }
}

fn link_input(provider: &str) -> SocialSignInInput {
    SocialSignInInput {
        provider: provider.into(),
        callback_url: None,
        new_user_callback_url: None,
        error_callback_url: None,
        disable_redirect: false,
        id_token: Some(SocialIdTokenInput {
            token: "id-one".into(),
            nonce: None,
            access_token: Some("access-one".into()),
            refresh_token: Some("refresh-one".into()),
            expires_at: None,
            user: None,
        }),
        scopes: None,
        request_sign_up: false,
        login_hint: None,
        additional_params: BTreeMap::new(),
        additional_data: serde_json::Map::new(),
    }
}

#[tokio::test]
async fn linked_accounts_are_user_bound_refresh_safe_and_never_orphan_authentication() {
    let service = application();
    let owner = provision(&service, "owner", "owner@example.com").await;
    let attacker = provision(&service, "attacker", "attacker@example.com").await;

    assert!(matches!(
        service
            .link_social_account(&owner.session, link_input("fixture"))
            .await
            .unwrap(),
        SocialSignInResult::Linked
    ));
    let accounts = service.list_linked_accounts(&owner.session).await.unwrap();
    assert_eq!(accounts.len(), 2);
    let oauth = accounts
        .iter()
        .find(|account| account.provider_id == "fixture")
        .unwrap();
    let credential = accounts
        .iter()
        .find(|account| account.provider_id == "credential")
        .unwrap();

    assert!(matches!(
        service
            .link_social_account(&attacker.session, link_input("fixture"))
            .await,
        Err(AuthError::SocialAccountAlreadyLinked)
    ));
    assert!(matches!(
        service
            .link_social_account(&owner.session, link_input("different"))
            .await,
        Err(AuthError::LinkingDifferentEmailsNotAllowed)
    ));
    assert_eq!(
        service
            .get_provider_access_token(&owner.session, oauth.id)
            .await
            .unwrap()
            .access_token,
        "access-one"
    );
    let (left, right) = tokio::join!(
        service.refresh_provider_access_token(&owner.session, oauth.id),
        service.refresh_provider_access_token(&owner.session, oauth.id),
    );
    assert_eq!(left.unwrap().access_token, right.unwrap().access_token);
    let info = service
        .provider_account_info(&owner.session, oauth.id)
        .await
        .unwrap();
    assert_eq!(info.account.account_id, "shared");

    service
        .unlink_account(&owner.session, oauth.id)
        .await
        .unwrap();
    assert!(matches!(
        service.unlink_account(&owner.session, credential.id).await,
        Err(AuthError::FailedToUnlinkLastAccount)
    ));
}

fn application() -> AuthService {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let mut config = AuthConfig::new([91_u8; 32]).unwrap();
    config.set_base_url("http://localhost:3000").unwrap();
    config.add_plugin(UsernamePlugin::default()).unwrap();
    for provider in [
        AccountProvider {
            id: "fixture",
            subject: "shared",
            email: "owner@example.com",
            refreshes: refreshes.clone(),
        },
        AccountProvider {
            id: "different",
            subject: "other",
            email: "other@example.com",
            refreshes: refreshes.clone(),
        },
    ] {
        config.add_social_provider(provider).unwrap();
    }
    AuthService::new(Arc::new(MemoryStore::default()), config)
}

async fn provision(service: &AuthService, username: &str, email: &str) -> lucid_auth::SignInResult {
    service
        .provision_password_user(NewPasswordUser {
            username: username.into(),
            name: username.into(),
            email: Some(email.into()),
            password: "correct horse battery staple".into(),
            role: "user".into(),
        })
        .await
        .unwrap();
    service
        .sign_in_username(username, "correct horse battery staple".into(), None, None)
        .await
        .unwrap()
}
