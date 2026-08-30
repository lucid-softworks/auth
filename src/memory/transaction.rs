use super::{MemoryState, MemoryStore, oauth, session, user};
use crate::{
    AuthError, DashAdapterSort, DashAdapterWhere, DatabaseCreateOperation, DatabaseModel,
    DatabaseRecord, DatabaseTransaction, DatabaseTransactionOperation,
};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, RwLock};

mod records;

#[cfg(test)]
mod coordinator_tests;

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

    async fn find_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&DashAdapterSort>,
        select: &[String],
    ) -> Result<Vec<Map<String, Value>>, AuthError> {
        records::find(self, model, where_clause, limit, offset, sort, select).await
    }

    async fn create_record(
        &self,
        model: &str,
        data: Map<String, Value>,
    ) -> Result<Map<String, Value>, AuthError> {
        records::create(self, model, data).await
    }

    async fn update_record(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        update: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        records::update(self, model, where_clause, update).await
    }

    async fn delete_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
    ) -> Result<u64, AuthError> {
        records::delete(self, model, where_clause).await
    }

    async fn count_records(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
    ) -> Result<u64, AuthError> {
        records::count(self, model, where_clause).await
    }

    async fn increment_record(
        &self,
        model: &str,
        where_clause: &[DashAdapterWhere],
        increments: Map<String, Value>,
        set: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        records::increment(self, model, where_clause, increments, set).await
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
