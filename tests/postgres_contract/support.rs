use chrono::{DateTime, Utc};
use lucid_auth::{
    AuthError, AuthUser, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
    DatabaseWrite, DependentAccountContext, DependentAccountPreparer, OAuthAccount,
};

pub(super) fn database_id_plan(model: &str) -> DatabaseIdPlan {
    DatabaseIdPlan::new(
        DatabaseIdGeneration::Default,
        model,
        DatabaseIdInput::Absent,
        false,
    )
}

pub(super) fn database_create<T>(record: T, model: &str) -> DatabaseCreate<T> {
    DatabaseCreate::new(record, database_id_plan(model))
}

pub(super) fn database_create_with_id<T>(
    record: T,
    model: &str,
    id: impl Into<String>,
) -> DatabaseCreate<T> {
    DatabaseCreate::new(
        record,
        DatabaseIdPlan::new(
            DatabaseIdGeneration::Default,
            model,
            DatabaseIdInput::String(id.into()),
            true,
        ),
    )
}

#[derive(Clone)]
pub(super) struct OAuthAccountFixture {
    account: OAuthAccount,
}

impl OAuthAccountFixture {
    pub(super) fn new(account: OAuthAccount) -> Self {
        Self { account }
    }
}

#[async_trait::async_trait]
impl DependentAccountPreparer for OAuthAccountFixture {
    fn pending_account_key(&self, _user: &AuthUser) -> Option<(String, String)> {
        Some((self.account.issuer.clone(), self.account.account_id.clone()))
    }

    async fn prepare_account(
        &self,
        context: DependentAccountContext<'_>,
    ) -> Result<DatabaseWrite<OAuthAccount>, AuthError> {
        if context.existing_account.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }
        let mut account = self.account.clone();
        account.user_id = context.user.id.clone();
        Ok(DatabaseWrite::Create(database_create(account, "account")))
    }
}

pub(super) struct CredentialAccountFixture {
    password_hash: String,
    now: DateTime<Utc>,
}

impl CredentialAccountFixture {
    pub(super) fn new(password_hash: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            password_hash: password_hash.into(),
            now,
        }
    }
}

#[async_trait::async_trait]
impl DependentAccountPreparer for CredentialAccountFixture {
    fn pending_account_key(&self, user: &AuthUser) -> Option<(String, String)> {
        Some(("local:credential".into(), user.id.clone()))
    }

    async fn prepare_account(
        &self,
        context: DependentAccountContext<'_>,
    ) -> Result<DatabaseWrite<OAuthAccount>, AuthError> {
        if context.existing_account.is_some() {
            return Err(AuthError::UserAlreadyExists);
        }
        Ok(DatabaseWrite::Create(database_create(
            OAuthAccount {
                id: String::new(),
                user_id: context.user.id.clone(),
                issuer: "local:credential".into(),
                account_id: context.user.id.clone(),
                provider_id: "credential".into(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
                password: Some(self.password_hash.clone()),
                additional_fields: serde_json::Map::new(),
                created_at: self.now,
                updated_at: self.now,
            },
            "account",
        )))
    }
}
