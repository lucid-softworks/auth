use super::{AuthService, SignInResult, oauth_identity::OAuthSignInPolicy};
use crate::{
    AuthError, OAuthTokens, OAuthUserInfo, OneTapError,
    oauth::google_id_token::{GoogleIdTokenError, GoogleIdTokenVerifier},
};

impl AuthService {
    pub async fn sign_in_one_tap(
        &self,
        id_token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.sign_in_one_tap_with_source(id_token, ip_address, user_agent, None)
            .await
    }

    pub(crate) async fn sign_in_one_tap_with_source(
        &self,
        id_token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        source: Option<crate::SessionWithUser>,
    ) -> Result<SignInResult, AuthError> {
        let config = self.one_tap_config()?;
        let google = self.social_provider("google");
        let audiences = config
            .client_id
            .as_ref()
            .filter(|client_id| !client_id.is_empty())
            .map(|client_id| vec![client_id.clone()])
            .unwrap_or_else(|| {
                google
                    .map(|provider| provider.id_token_audiences().to_vec())
                    .unwrap_or_default()
            });
        if audiences.is_empty() {
            return Err(OneTapError::MissingClientId.into());
        }
        let hosted_domain = google.and_then(|provider| provider.hosted_domain());
        let claims = verify_id_token(&config.verifier, id_token, &audiences, hosted_domain).await?;
        let policy = OAuthSignInPolicy {
            provider_id: "google".into(),
            disable_implicit_sign_up: false,
            disable_sign_up: config.disable_signup
                || google.is_some_and(|provider| provider.disable_sign_up()),
            require_email_verification: google
                .is_some_and(|provider| provider.require_email_verification()),
            override_user_info: false,
        };
        let tokens = OAuthTokens {
            id_token: Some(id_token.into()),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            ..OAuthTokens::default()
        };
        let user_info = OAuthUserInfo {
            account_id: claims.subject,
            issuer: "https://accounts.google.com".into(),
            name: claims.name,
            email: claims.email,
            email_verified: claims.email_verified,
            image: claims.picture,
            additional_fields: serde_json::Map::new(),
            profile: claims.profile,
        };
        let (result, _) = self
            .finish_oauth_sign_in_with_policy(
                &policy, tokens, user_info, false, ip_address, user_agent,
            )
            .await?;
        if let Some(source) = source.filter(|source| source.user.is_anonymous) {
            self.complete_anonymous_upgrade(&source, &result).await?;
        }
        Ok(result)
    }
}

async fn verify_id_token(
    verifier: &GoogleIdTokenVerifier,
    id_token: &str,
    audiences: &[String],
    hosted_domain: Option<&str>,
) -> Result<crate::oauth::google_id_token::GoogleIdTokenClaims, AuthError> {
    verifier
        .verify(id_token, audiences, hosted_domain)
        .await
        .map_err(|error| match error {
            GoogleIdTokenError::MissingEmail => OneTapError::EmailNotAvailable.into(),
            _ => OneTapError::InvalidIdToken.into(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnonymousPlugin, AuthConfig, AuthStore, BuiltinProvider, BuiltinProviderKind, MemoryStore,
        NewPasswordUser, OAuthAccountStore, OneTapConfig, OneTapPlugin, VerificationEmail,
        VerificationEmailSender, oauth::google_id_token::fixture,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Default)]
    struct VerificationSender(Mutex<Vec<VerificationEmail>>);

    #[async_trait]
    impl VerificationEmailSender for VerificationSender {
        async fn send(&self, email: VerificationEmail) -> Result<(), AuthError> {
            self.0.lock().await.push(email);
            Ok(())
        }
    }

    fn fixture_service(
        claims: serde_json::Value,
        configure: impl FnOnce(&mut AuthConfig, &mut OneTapConfig),
    ) -> (AuthService, Arc<MemoryStore>, String) {
        let (verifier, token) = fixture::verifier_and_token(claims);
        let store = Arc::new(MemoryStore::default());
        let mut auth = AuthConfig::new([115_u8; 32]).unwrap();
        auth.set_base_url("http://localhost").unwrap();
        auth.session.store_session_in_database = true;
        let mut one_tap = OneTapConfig {
            client_id: Some(fixture::AUDIENCE.into()),
            verifier,
            ..OneTapConfig::default()
        };
        configure(&mut auth, &mut one_tap);
        auth.add_plugin(OneTapPlugin::new(one_tap)).unwrap();
        (AuthService::new(store.clone(), auth), store, token)
    }

    #[tokio::test]
    async fn creates_and_reuses_canonical_google_identity() {
        let (service, store, token) = fixture_service(
            json!({
                "iss": "accounts.google.com",
                "sub": "one-tap-subject",
                "email": "One.Tap@EXAMPLE.com",
                "name": "One Tap User",
                "picture": "https://example.com/avatar.png",
                "nonce": "never-checked-server-side"
            }),
            |auth, _| {
                auth.add_social_provider(BuiltinProvider::public_client(
                    BuiltinProviderKind::Google,
                    fixture::AUDIENCE,
                ))
                .unwrap();
                auth.trust_social_provider("google").unwrap();
            },
        );
        let first = service
            .sign_in_one_tap(&token, Some("192.0.2.10".into()), Some("fixture".into()))
            .await
            .unwrap();
        assert_eq!(first.session.user.email, "one.tap@example.com");
        assert_eq!(first.session.user.name, "One Tap User");
        assert_eq!(
            first.session.user.image.as_deref(),
            Some("https://example.com/avatar.png")
        );
        assert!(store.find_session(&first.token).await.unwrap().is_some());

        let owner = store
            .find_oauth_account_owner("https://accounts.google.com", "one-tap-subject")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(owner.account.provider_id, "google");
        assert_eq!(owner.account.scope.as_deref(), Some("openid,profile,email"));
        assert_eq!(owner.account.id_token.as_deref(), Some(token.as_str()));

        let (_, second_token) = fixture::verifier_and_token(json!({
            "iss": "https://accounts.google.com",
            "sub": "one-tap-subject",
            "email": "different@example.com"
        }));
        let second = service
            .sign_in_one_tap(&second_token, None, None)
            .await
            .unwrap();
        assert_eq!(second.session.user.id, first.session.user.id);
        assert_eq!(second.session.user.email, "one.tap@example.com");
    }

    #[tokio::test]
    async fn applies_signup_and_email_verification_policy_only_from_better_auth_options() {
        let (disabled, _, token) = fixture_service(json!({}), |_, one_tap| {
            one_tap.disable_signup = true;
        });
        assert!(matches!(
            disabled.sign_in_one_tap(&token, None, None).await,
            Err(AuthError::OAuthSignupDisabled)
        ));

        let (unverified, _, token) = fixture_service(
            json!({ "sub": "unverified-without-provider", "email_verified": false }),
            |_, _| {},
        );
        assert!(unverified.sign_in_one_tap(&token, None, None).await.is_ok());

        let (required, _, token) = fixture_service(
            json!({ "sub": "unverified-with-provider", "email_verified": false }),
            |auth, _| {
                let mut google =
                    BuiltinProvider::public_client(BuiltinProviderKind::Google, fixture::AUDIENCE);
                google.config_mut().require_email_verification = true;
                auth.add_social_provider(google).unwrap();
            },
        );
        assert!(matches!(
            required.sign_in_one_tap(&token, None, None).await,
            Err(AuthError::EmailNotVerified)
        ));

        let sender = Arc::new(VerificationSender::default());
        let captured = sender.clone();
        let (required_with_delivery, _, token) = fixture_service(
            json!({ "sub": "unverified-email-delivery", "email_verified": false }),
            move |auth, _| {
                auth.email_verification.sender = Some(sender);
                let mut google =
                    BuiltinProvider::public_client(BuiltinProviderKind::Google, fixture::AUDIENCE);
                google.config_mut().require_email_verification = true;
                auth.add_social_provider(google).unwrap();
            },
        );
        assert!(matches!(
            required_with_delivery
                .sign_in_one_tap(&token, None, None)
                .await,
            Err(AuthError::EmailNotVerified)
        ));
        let emails = captured.0.lock().await;
        assert_eq!(emails.len(), 1);
        assert!(emails[0].url.contains("callbackURL=%2F"));

        let (provider_disabled, _, token) =
            fixture_service(json!({ "sub": "provider-disabled-signup" }), |auth, _| {
                let mut google =
                    BuiltinProvider::public_client(BuiltinProviderKind::Google, fixture::AUDIENCE);
                google.config_mut().disable_sign_up = true;
                auth.add_social_provider(google).unwrap();
            });
        assert!(matches!(
            provider_disabled.sign_in_one_tap(&token, None, None).await,
            Err(AuthError::OAuthSignupDisabled)
        ));
    }

    #[tokio::test]
    async fn resolves_client_id_precedence_and_google_hosted_domain() {
        let (fallback, _, token) = fixture_service(
            json!({ "sub": "provider-audience-fallback" }),
            |auth, one_tap| {
                one_tap.client_id = None;
                auth.add_social_provider(BuiltinProvider::public_client(
                    BuiltinProviderKind::Google,
                    fixture::AUDIENCE,
                ))
                .unwrap();
            },
        );
        assert!(fallback.sign_in_one_tap(&token, None, None).await.is_ok());

        let (override_service, _, token) =
            fixture_service(json!({ "sub": "plugin-audience-override" }), |auth, _| {
                auth.add_social_provider(BuiltinProvider::public_client(
                    BuiltinProviderKind::Google,
                    "different-provider-client",
                ))
                .unwrap();
            });
        assert!(
            override_service
                .sign_in_one_tap(&token, None, None)
                .await
                .is_ok()
        );

        let (wildcard, _, token) = fixture_service(
            json!({ "sub": "workspace-wildcard", "hd": "workspace.example" }),
            |auth, _| {
                let mut google =
                    BuiltinProvider::public_client(BuiltinProviderKind::Google, fixture::AUDIENCE);
                google.config_mut().hosted_domain = Some("*".into());
                auth.add_social_provider(google).unwrap();
            },
        );
        assert!(wildcard.sign_in_one_tap(&token, None, None).await.is_ok());

        let (mismatch, _, token) = fixture_service(
            json!({ "sub": "workspace-mismatch", "hd": "other.example" }),
            |auth, _| {
                let mut google =
                    BuiltinProvider::public_client(BuiltinProviderKind::Google, fixture::AUDIENCE);
                google.config_mut().hosted_domain = Some("workspace.example".into());
                auth.add_social_provider(google).unwrap();
            },
        );
        assert!(matches!(
            mismatch.sign_in_one_tap(&token, None, None).await,
            Err(AuthError::OneTap(OneTapError::InvalidIdToken))
        ));
    }

    #[tokio::test]
    async fn links_verified_email_without_crossing_an_owned_subject() {
        let (service, store, token) = fixture_service(
            json!({
                "sub": "linked-subject",
                "email": "linked@example.com",
                "email_verified": true
            }),
            |auth, _| {
                auth.account.account_linking.require_local_email_verified = false;
                auth.add_social_provider(BuiltinProvider::public_client(
                    BuiltinProviderKind::Google,
                    fixture::AUDIENCE,
                ))
                .unwrap();
                auth.trust_social_provider("google").unwrap();
            },
        );
        let local = service
            .provision_password_user(NewPasswordUser {
                username: "linked".into(),
                name: "Linked User".into(),
                email: Some("linked@example.com".into()),
                password: "correct horse battery staple".into(),
                role: "user".into(),
            })
            .await
            .unwrap();
        let linked = service.sign_in_one_tap(&token, None, None).await.unwrap();
        assert_eq!(linked.session.user.id, local.id);

        let (_, changed_email_token) = fixture::verifier_and_token(json!({
            "sub": "linked-subject",
            "email": "attacker@example.com",
            "email_verified": true
        }));
        let owner = service
            .sign_in_one_tap(&changed_email_token, None, None)
            .await
            .unwrap();
        assert_eq!(owner.session.user.id, local.id);
        assert!(
            store
                .find_user_by_email("attacker@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn completes_anonymous_upgrade_through_the_one_tap_callback_path() {
        let (service, store, token) =
            fixture_service(json!({ "sub": "anonymous-upgrade-subject" }), |auth, _| {
                auth.add_plugin(AnonymousPlugin::default()).unwrap();
            });
        let anonymous = service.sign_in_anonymous(None, None).await.unwrap();
        let source_id = anonymous.session.user.id.clone();
        let upgraded = service
            .sign_in_one_tap_with_source(&token, None, None, Some(anonymous.session))
            .await
            .unwrap();
        assert!(!upgraded.session.user.is_anonymous);
        assert!(store.find_user_by_id(&source_id).await.unwrap().is_none());
    }
}
