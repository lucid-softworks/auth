use super::*;
use crate::store::{DatabaseIdInput, DatabaseIdPlan, DatabaseWrite};
use crate::{DatabaseIdGeneration, DatabaseWriteOperation};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;

fn create<T>(record: T, model: &str) -> DatabaseCreate<T> {
    DatabaseCreate::new(
        record,
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Uuid,
            model,
            DatabaseIdInput::Absent,
            false,
        ),
    )
}

fn user(email: &str) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: String::new(),
        username: None,
        display_username: None,
        name: "Test".into(),
        email: email.into(),
        email_verified: false,
        image: None,
        additional_fields: serde_json::Map::new(),
        role: "user".into(),
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

fn account() -> OAuthAccount {
    let now = Utc::now();
    OAuthAccount {
        id: String::new(),
        user_id: String::new(),
        issuer: "https://issuer.example".into(),
        account_id: "subject".into(),
        provider_id: "oidc".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: None,
        additional_fields: serde_json::Map::new(),
        created_at: now,
        updated_at: now,
    }
}

#[derive(Clone)]
struct BlockingOAuthPreparer {
    account: DatabaseCreate<OAuthAccount>,
    started: Arc<Notify>,
    release: Arc<Notify>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for BlockingOAuthPreparer {
    fn pending_account_key(&self, _user: &AuthUser) -> Option<(String, String)> {
        Some(("https://issuer.example".into(), "subject".into()))
    }

    async fn prepare_account(
        &self,
        context: crate::DependentAccountContext<'_>,
    ) -> Result<DatabaseWrite<OAuthAccount>, AuthError> {
        assert_eq!(context.user_operation, DatabaseWriteOperation::Create);
        assert!(context.existing_account.is_none());
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        self.release.notified().await;
        Ok(DatabaseWrite::Create(self.account.clone()))
    }
}

#[tokio::test]
async fn concurrent_oauth_account_key_is_reserved_before_hook_execution() {
    let store = MemoryStore::default();
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let preparer = BlockingOAuthPreparer {
        account: create(account(), "account"),
        started: started.clone(),
        release: release.clone(),
        calls: calls.clone(),
    };
    let first_store = store.clone();
    let first = tokio::spawn(async move {
        create_user(
            &first_store,
            create(user("first@example.com"), "user"),
            &preparer,
        )
        .await
    });
    started.notified().await;

    let second_preparer = BlockingOAuthPreparer {
        account: create(account(), "account"),
        started: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
        calls: calls.clone(),
    };
    let second = create_user(
        &store,
        create(user("second@example.com"), "user"),
        &second_preparer,
    )
    .await;
    assert!(matches!(second, Err(AuthError::UserAlreadyExists)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    release.notify_one();
    first.await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
