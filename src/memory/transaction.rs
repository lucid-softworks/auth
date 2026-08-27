use super::{MemoryState, MemoryStore, oauth, session, user};
use crate::{
    AuthError, DatabaseCreateOperation, DatabaseModel, DatabaseRecord, DatabaseTransaction,
    DatabaseTransactionOperation,
};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, RwLock};

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::{
        AuthStore, AuthUser, DatabaseCreate, DatabaseIdGeneration, DatabaseIdInput, DatabaseIdPlan,
        run_database_transaction,
    };
    use chrono::Utc;
    use serde_json::Map;

    fn user(email: &str) -> AuthUser {
        let now = Utc::now();
        AuthUser {
            id: String::new(),
            username: None,
            display_username: None,
            name: "Transaction Test".into(),
            email: email.into(),
            email_verified: false,
            image: None,
            additional_fields: Map::new(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn create_user(email: &str) -> DatabaseCreateOperation {
        DatabaseCreateOperation::User(DatabaseCreate::new(
            user(email),
            DatabaseIdPlan::new(
                DatabaseIdGeneration::Default,
                "user",
                DatabaseIdInput::Absent,
                true,
            ),
        ))
    }

    #[tokio::test]
    async fn staged_writes_are_visible_to_reentry_and_commit_once() {
        let store = MemoryStore::default();
        let base = store.clone();
        let (user, escaped) = run_database_transaction(&store, move |transaction| {
            Box::pin(async move {
                let DatabaseRecord::User(user) = transaction
                    .create(create_user("commit@example.com"))
                    .await?
                else {
                    unreachable!();
                };
                let committed_id = user.id.clone();
                assert!(
                    tokio::spawn(async move { base.find_user_by_id(&committed_id).await })
                        .await
                        .map_err(|error| AuthError::Storage(format!(
                            "visibility task failed: {error}"
                        )))??
                        .is_none()
                );
                assert_eq!(
                    transaction
                        .find_by_id(DatabaseModel::User, &user.id)
                        .await?,
                    Some(DatabaseRecord::User(user.clone()))
                );
                Ok((user, transaction))
            })
        })
        .await
        .unwrap();

        assert_eq!(store.find_user_by_id(&user.id).await.unwrap(), Some(user));
        assert!(
            escaped
                .find_by_id(DatabaseModel::User, "anything")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn error_rolls_back_the_complete_staged_view() {
        let store = MemoryStore::default();
        let id = Arc::new(std::sync::Mutex::new(None));
        let captured = id.clone();
        let error = run_database_transaction::<(), _>(&store, move |transaction| {
            Box::pin(async move {
                let DatabaseRecord::User(user) = transaction
                    .create(create_user("rollback@example.com"))
                    .await?
                else {
                    unreachable!();
                };
                *captured.lock().unwrap() = Some(user.id);
                Err(AuthError::Storage("cancelled".into()))
            })
        })
        .await
        .unwrap_err();

        assert!(matches!(error, AuthError::Storage(message) if message == "cancelled"));
        let rolled_back_id = id.lock().unwrap().clone().unwrap();
        assert!(
            store
                .find_user_by_id(&rolled_back_id)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn nested_transactions_reuse_the_active_staged_adapter() {
        let store = MemoryStore::default();
        let nested_store = store.clone();
        let user = run_database_transaction(&store, move |outer| {
            Box::pin(async move {
                let nested_store = nested_store.clone();
                let user = run_database_transaction(&nested_store, move |inner| {
                    Box::pin(async move {
                        assert!(Arc::ptr_eq(&outer, &inner));
                        let DatabaseRecord::User(user) =
                            inner.create(create_user("nested@example.com")).await?
                        else {
                            unreachable!();
                        };
                        Ok(user)
                    })
                })
                .await?;
                let committed_store = nested_store.clone();
                let committed_id = user.id.clone();
                assert!(
                    tokio::spawn(
                        async move { committed_store.find_user_by_id(&committed_id).await }
                    )
                    .await
                    .map_err(|error| {
                        AuthError::Storage(format!("visibility task failed: {error}"))
                    })??
                    .is_none()
                );
                Ok(user)
            })
        })
        .await
        .unwrap();

        assert_eq!(store.find_user_by_id(&user.id).await.unwrap(), Some(user));
    }
}

pub(super) async fn run(
    store: &MemoryStore,
    operation: Box<dyn DatabaseTransactionOperation>,
) -> Result<Box<dyn std::any::Any + Send>, AuthError> {
    let _guard = store.transaction_gate.lock().await;
    let staged = staged_store(store).await;
    let transaction = Arc::new(MemoryTransaction {
        store: staged,
        active: AtomicBool::new(true),
    });
    let result = crate::database_hooks::scope_transaction(
        transaction.clone(),
        operation.execute(transaction.clone()),
    )
    .await;
    transaction.active.store(false, Ordering::Release);
    match result {
        Ok(value) => {
            let staged = transaction.store.state.read().await.clone();
            *store.state.write().await = staged;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

async fn staged_store(store: &MemoryStore) -> MemoryStore {
    MemoryStore {
        state: Arc::new(RwLock::new(store.state.read().await.clone())),
        siwe_identity_write: Arc::new(Mutex::new(())),
        transaction_gate: Arc::new(Mutex::new(())),
    }
}

struct MemoryTransaction {
    store: MemoryStore,
    active: AtomicBool,
}

impl MemoryTransaction {
    fn ensure_active(&self) -> Result<(), AuthError> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(AuthError::Storage(
                "database transaction is no longer active".into(),
            ))
        }
    }
}

#[async_trait]
impl DatabaseTransaction for MemoryTransaction {
    async fn find_by_id(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError> {
        self.ensure_active()?;
        let state = self.store.state.read().await;
        let record = match model {
            DatabaseModel::User => state.users.get(id).cloned().map(DatabaseRecord::User),
            DatabaseModel::Session => state
                .sessions
                .values()
                .find(|record| record.id == id)
                .cloned()
                .map(DatabaseRecord::Session),
            DatabaseModel::Account => state
                .oauth_accounts
                .values()
                .find(|record| record.id == id)
                .cloned()
                .map(DatabaseRecord::Account),
            DatabaseModel::Verification => state
                .verifications
                .get(id)
                .cloned()
                .map(DatabaseRecord::Verification),
            DatabaseModel::Organization => {
                return Err(AuthError::InvalidConfiguration(
                    "organization transactions use the organization store boundary".into(),
                ));
            }
        };
        Ok(record)
    }

    async fn create(
        &self,
        operation: DatabaseCreateOperation,
    ) -> Result<DatabaseRecord, AuthError> {
        self.ensure_active()?;
        match operation {
            DatabaseCreateOperation::User(record) => {
                user::create_without_account(&self.store, record)
                    .await
                    .map(DatabaseRecord::User)
            }
            DatabaseCreateOperation::Session(record) => session::create(&self.store, record)
                .await
                .map(DatabaseRecord::Session),
            DatabaseCreateOperation::Account(record) => oauth::link(&self.store, record)
                .await
                .map(DatabaseRecord::Account),
            DatabaseCreateOperation::Verification(record) => {
                let mut state = self.store.state.write().await;
                let (mut record, id) = record.into_parts(&self.store)?;
                record.id = self
                    .store
                    .create_id("verification", id, state.verifications.len())?;
                if state.verifications.contains_key(&record.id) {
                    return Err(AuthError::Storage("verification id already exists".into()));
                }
                state
                    .verifications
                    .insert(record.id.clone(), record.clone());
                Ok(DatabaseRecord::Verification(record))
            }
        }
    }

    async fn update(&self, record: DatabaseRecord) -> Result<DatabaseRecord, AuthError> {
        self.ensure_active()?;
        let mut state = self.store.state.write().await;
        match record {
            DatabaseRecord::User(user) => replace_user(&mut state, user).map(DatabaseRecord::User),
            DatabaseRecord::Session(session) => {
                let stored = state
                    .sessions
                    .values_mut()
                    .find(|stored| stored.id == session.id)
                    .ok_or(AuthError::NotFound)?;
                *stored = session.clone();
                Ok(DatabaseRecord::Session(session))
            }
            DatabaseRecord::Account(account) => {
                let key = state
                    .oauth_accounts
                    .iter()
                    .find(|(_, stored)| stored.id == account.id)
                    .map(|(key, _)| key.clone())
                    .ok_or(AuthError::NotFound)?;
                state.oauth_accounts.insert(key, account.clone());
                Ok(DatabaseRecord::Account(account))
            }
            DatabaseRecord::Verification(value) => {
                if !state.verifications.contains_key(&value.id) {
                    return Err(AuthError::NotFound);
                }
                state.verifications.insert(value.id.clone(), value.clone());
                Ok(DatabaseRecord::Verification(value))
            }
        }
    }

    async fn delete(
        &self,
        model: DatabaseModel,
        id: &str,
    ) -> Result<Option<DatabaseRecord>, AuthError> {
        self.ensure_active()?;
        let mut state = self.store.state.write().await;
        let deleted = match model {
            DatabaseModel::User => state.users.remove(id).map(DatabaseRecord::User),
            DatabaseModel::Session => {
                remove_by_id(&mut state.sessions, id).map(DatabaseRecord::Session)
            }
            DatabaseModel::Account => {
                remove_account_by_id(&mut state, id).map(DatabaseRecord::Account)
            }
            DatabaseModel::Verification => state
                .verifications
                .remove(id)
                .map(DatabaseRecord::Verification),
            DatabaseModel::Organization => {
                return Err(AuthError::InvalidConfiguration(
                    "organization transactions use the organization store boundary".into(),
                ));
            }
        };
        Ok(deleted)
    }
}

fn replace_user(
    state: &mut MemoryState,
    user: crate::AuthUser,
) -> Result<crate::AuthUser, AuthError> {
    let current = state.users.get(&user.id).ok_or(AuthError::NotFound)?;
    if state
        .emails
        .get(&user.email)
        .is_some_and(|owner| owner != &user.id)
    {
        return Err(AuthError::UserAlreadyExists);
    }
    let previous_email = current.email.clone();
    let previous_username = current.username.clone();
    state.emails.remove(&previous_email);
    state.emails.insert(user.email.clone(), user.id.clone());
    if previous_username != user.username {
        if let Some(username) = previous_username {
            state.usernames.remove(&username);
        }
        if let Some(username) = &user.username {
            if state.usernames.contains_key(username) {
                return Err(AuthError::UserAlreadyExists);
            }
            state.usernames.insert(username.clone(), user.id.clone());
        }
    }
    state.users.insert(user.id.clone(), user.clone());
    Ok(user)
}

fn remove_by_id(
    sessions: &mut std::collections::HashMap<String, crate::AuthSession>,
    id: &str,
) -> Option<crate::AuthSession> {
    let token = sessions
        .iter()
        .find(|(_, record)| record.id == id)
        .map(|(token, _)| token.clone())?;
    sessions.remove(&token)
}

fn remove_account_by_id(state: &mut MemoryState, id: &str) -> Option<crate::OAuthAccount> {
    let key = state
        .oauth_accounts
        .iter()
        .find(|(_, record)| record.id == id)
        .map(|(key, _)| key.clone())?;
    state.oauth_accounts.remove(&key)
}
