use super::AuthService;
use crate::{
    AuthConfig, AuthError, AuthStore, MemoryStore, OAuthAccountStore, SiweConfig, SiweEnsLookup,
    SiweEnsProfile, SiweError, SiweMessageVerifier, SiweNonceGenerator, SiwePlugin, SiweStore,
    SiweVerificationRequest,
};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;

const ADDRESS: &str = "0x52908400098527886E0F7030069857D2E4169EE7";

struct Nonce(&'static str);

#[async_trait]
impl SiweNonceGenerator for Nonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(self.0.into())
    }
}

struct OwnedNonce(String);

#[async_trait]
impl SiweNonceGenerator for OwnedNonce {
    async fn generate(&self) -> Result<String, AuthError> {
        Ok(self.0.clone())
    }
}

#[derive(Default)]
struct Verifier(Mutex<Vec<SiweVerificationRequest>>);

#[async_trait]
impl SiweMessageVerifier for Verifier {
    async fn verify(&self, request: SiweVerificationRequest) -> Result<bool, AuthError> {
        self.0.lock().await.push(request);
        Ok(true)
    }
}

#[derive(Default)]
struct EnsLookup(Mutex<Vec<String>>);

#[async_trait]
impl SiweEnsLookup for EnsLookup {
    async fn lookup(&self, wallet_address: &str) -> Result<SiweEnsProfile, AuthError> {
        self.0.lock().await.push(wallet_address.into());
        Ok(SiweEnsProfile {
            name: Some(String::new()),
            avatar: Some("https://example.com/avatar.png".into()),
        })
    }
}

fn fixture(
    nonce: &'static str,
    configure: impl FnOnce(&mut SiweConfig),
) -> (AuthService, Arc<MemoryStore>, Arc<Verifier>) {
    let store = Arc::new(MemoryStore::default());
    let verifier = Arc::new(Verifier::default());
    let mut siwe = SiweConfig::new("example.com", Arc::new(Nonce(nonce)), verifier.clone());
    siwe.email_domain_name = Some("wallet.example".into());
    configure(&mut siwe);
    let mut config = AuthConfig::new([121_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config
        .add_plugin(SiwePlugin::new(store.clone(), siwe))
        .unwrap();
    (AuthService::new(store.clone(), config), store, verifier)
}

fn message(nonce: &str, chain_id: &str, domain: &str) -> String {
    format!(
        "{domain} wants you to sign in with your Ethereum account:\n\
         {ADDRESS}\n\nSign in\n\nURI: https://example.com\nVersion: 1\n\
         Chain ID: {chain_id}\nNonce: {nonce}\nIssued At: invalid-but-ignored"
    )
}

#[tokio::test]
async fn nonce_verify_session_and_callback_match_better_auth() {
    let (service, store, verifier) = fixture("abcDEF12", |_| {});
    assert_eq!(service.create_siwe_nonce().await.unwrap(), "abcDEF12");
    let verified = service
        .verify_siwe_message(
            message("abcDEF12", "1", "example.com"),
            "0xsigned".into(),
            None,
            Some("192.0.2.8".into()),
            Some("siwe-test".into()),
            None,
        )
        .await
        .unwrap();
    assert_eq!(verified.wallet_address, ADDRESS);
    assert_eq!(verified.chain_id, 1.0);
    assert!(store.find_session(&verified.token).await.unwrap().is_some());
    let owner = store
        .find_oauth_account_owner("local:siwe", &format!("{ADDRESS}:1"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.user.id, verified.user_id);
    assert_eq!(owner.account.provider_id, "siwe");
    let captured = verifier.0.lock().await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].address, ADDRESS);
    assert_eq!(captured[0].cacao.header_type, "caip122");
    assert_eq!(captured[0].cacao.signature_type, "eip191");
    drop(captured);
    assert!(matches!(
        service
            .verify_siwe_message(
                message("abcDEF12", "1", "example.com"),
                "0xsigned".into(),
                None,
                None,
                None,
                None,
            )
            .await,
        Err(AuthError::Siwe(SiweError::InvalidOrExpiredNonce))
    ));
}

#[tokio::test]
async fn nonce_is_consumed_before_domain_address_chain_time_and_signature_checks() {
    let (service, _, verifier) = fixture("consume12", |_| {});
    service.create_siwe_nonce().await.unwrap();
    assert!(matches!(
        service
            .verify_siwe_message(
                message("consume12", "1", "evil.example"),
                "0xsigned".into(),
                None,
                None,
                None,
                None,
            )
            .await,
        Err(AuthError::Siwe(SiweError::MessageMismatch))
    ));
    assert!(matches!(
        service
            .verify_siwe_message(
                message("consume12", "1", "example.com"),
                "0xsigned".into(),
                None,
                None,
                None,
                None,
            )
            .await,
        Err(AuthError::Siwe(SiweError::InvalidOrExpiredNonce))
    ));
    assert!(verifier.0.lock().await.is_empty());
}

#[tokio::test]
async fn same_wallet_on_another_chain_reuses_user_and_adds_non_primary_identity() {
    let (service, store, _) = fixture("chain001", |_| {});
    service.create_siwe_nonce().await.unwrap();
    let first = service
        .verify_siwe_message(
            message("chain001", "1", "example.com"),
            "signature".into(),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();

    let second_service = {
        let verifier = Arc::new(Verifier::default());
        let mut config = AuthConfig::new([121_u8; 32]).unwrap();
        config.set_base_url("https://example.com").unwrap();
        let mut siwe = SiweConfig::new("example.com", Arc::new(Nonce("chain002")), verifier);
        siwe.email_domain_name = Some("wallet.example".into());
        config
            .add_plugin(SiwePlugin::new(store.clone(), siwe))
            .unwrap();
        AuthService::new(store.clone(), config)
    };
    second_service.create_siwe_nonce().await.unwrap();
    let second = second_service
        .verify_siwe_message(
            message("chain002", "137", "example.com"),
            "signature".into(),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(second.user_id, first.user_id);
    let primary = store
        .find_wallet_owner(&crate::SiweSchema::default(), ADDRESS, Some(1.0))
        .await
        .unwrap()
        .unwrap();
    let added = store
        .find_wallet_owner(&crate::SiweSchema::default(), ADDRESS, Some(137.0))
        .await
        .unwrap()
        .unwrap();
    assert!(primary.wallet.is_primary);
    assert!(!added.wallet.is_primary);
}

#[tokio::test]
async fn email_mode_and_generated_nonce_bounds_are_exact() {
    let (service, store, _) = fixture("email001", |siwe| siwe.anonymous = false);
    service.create_siwe_nonce().await.unwrap();
    let verified = service
        .verify_siwe_message(
            message("email001", "1", "example.com"),
            "signature".into(),
            Some("Wallet@Example.com".into()),
            None,
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .find_user_by_id(&verified.user_id)
            .await
            .unwrap()
            .unwrap()
            .email,
        "wallet@example.com"
    );

    let (invalid, _, _) = fixture("short", |_| {});
    assert!(matches!(
        invalid.create_siwe_nonce().await,
        Err(AuthError::Siwe(SiweError::InvalidGeneratedNonce))
    ));

    let store = Arc::new(MemoryStore::default());
    let mut config = AuthConfig::new([125_u8; 32]).unwrap();
    config.set_base_url("https://example.com").unwrap();
    config
        .add_plugin(SiwePlugin::new(
            store.clone(),
            SiweConfig::new(
                "example.com",
                Arc::new(OwnedNonce("a".repeat(250))),
                Arc::new(Verifier::default()),
            ),
        ))
        .unwrap();
    let max = AuthService::new(store, config);
    assert_eq!(max.create_siwe_nonce().await.unwrap().len(), 250);
    let stored = max
        .find_verification_value(&format!("siwe:{}", "a".repeat(250)))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.expires_at - stored.created_at,
        chrono::Duration::seconds(900)
    );
}

#[tokio::test]
async fn concurrent_duplicate_email_falls_back_to_the_wallet_address() {
    const SECOND_ADDRESS: &str = "0xde709f2102306220921060314715629080e2fb77";

    let store = Arc::new(MemoryStore::default());
    let make_service = |nonce| {
        let mut config = AuthConfig::new([126_u8; 32]).unwrap();
        config.set_base_url("https://example.com").unwrap();
        let mut siwe = SiweConfig::new(
            "example.com",
            Arc::new(Nonce(nonce)),
            Arc::new(Verifier::default()),
        );
        siwe.anonymous = false;
        siwe.email_domain_name = Some("wallet.example".into());
        config
            .add_plugin(SiwePlugin::new(store.clone(), siwe))
            .unwrap();
        AuthService::new(store.clone(), config)
    };
    let first = make_service("emailrace1");
    let second = make_service("emailrace2");
    first.create_siwe_nonce().await.unwrap();
    second.create_siwe_nonce().await.unwrap();

    let first_message = message("emailrace1", "1", "example.com");
    let second_message =
        message("emailrace2", "1", "example.com").replacen(ADDRESS, SECOND_ADDRESS, 1);
    let (first, second) = tokio::join!(
        first.verify_siwe_message(
            first_message,
            "signature".into(),
            Some("Shared@Example.com".into()),
            None,
            None,
            None,
        ),
        second.verify_siwe_message(
            second_message,
            "signature".into(),
            Some("Shared@Example.com".into()),
            None,
            None,
            None,
        )
    );
    let first_id = first.unwrap().user_id;
    let first = store.find_user_by_id(&first_id).await.unwrap().unwrap();
    let second_id = second.unwrap().user_id;
    let second = store.find_user_by_id(&second_id).await.unwrap().unwrap();
    let emails = [first.email, second.email];
    assert_eq!(
        emails
            .iter()
            .filter(|email| *email == "shared@example.com")
            .count(),
        1
    );
    assert!(
        emails
            .iter()
            .any(|email| email.ends_with("@wallet.example"))
    );
}

#[tokio::test]
async fn ens_lookup_receives_the_checksum_and_preserves_present_empty_values() {
    let ens = Arc::new(EnsLookup::default());
    let (service, store, _) = fixture("enscheck", |siwe| {
        siwe.ens_lookup = Some(ens.clone());
    });
    service.create_siwe_nonce().await.unwrap();
    let verified = service
        .verify_siwe_message(
            message("enscheck", "1", "example.com"),
            "signature".into(),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
    let user = store
        .find_user_by_id(&verified.user_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*ens.0.lock().await, [ADDRESS]);
    assert_eq!(user.name, "");
    assert_eq!(
        user.image.as_deref(),
        Some("https://example.com/avatar.png")
    );
}
