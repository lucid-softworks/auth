use super::{StepUpSession, StepUpStore};
use crate::AuthError;
use async_trait::async_trait;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Default)]
struct State {
    sessions: HashMap<String, StepUpSession>,
    recovery_codes: HashMap<String, HashSet<String>>,
}

#[derive(Clone, Default)]
pub struct MemoryStepUpStore {
    state: Arc<RwLock<State>>,
}

#[async_trait]
impl StepUpStore for MemoryStepUpStore {
    async fn upsert_step_up_session(&self, session: StepUpSession) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .sessions
            .insert(session.session_id.clone(), session);
        Ok(())
    }

    async fn find_step_up_session(
        &self,
        session_id: &str,
    ) -> Result<Option<StepUpSession>, AuthError> {
        Ok(self.state.read().await.sessions.get(session_id).cloned())
    }

    async fn delete_step_up_session(&self, session_id: &str) -> Result<(), AuthError> {
        self.state.write().await.sessions.remove(session_id);
        Ok(())
    }

    async fn delete_user_step_up_state(&self, user_id: &str) -> Result<(), AuthError> {
        let mut state = self.state.write().await;
        state
            .sessions
            .retain(|_, session| session.user_id != user_id);
        state.recovery_codes.remove(user_id);
        Ok(())
    }

    async fn replace_step_up_recovery_codes(
        &self,
        user_id: &str,
        code_hashes: Vec<String>,
    ) -> Result<(), AuthError> {
        self.state
            .write()
            .await
            .recovery_codes
            .insert(user_id.to_owned(), code_hashes.into_iter().collect());
        Ok(())
    }

    async fn consume_step_up_recovery_code(
        &self,
        user_id: &str,
        code_hash: &str,
    ) -> Result<bool, AuthError> {
        Ok(self
            .state
            .write()
            .await
            .recovery_codes
            .get_mut(user_id)
            .is_some_and(|codes| codes.remove(code_hash)))
    }

    async fn step_up_recovery_code_count(&self, user_id: &str) -> Result<usize, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .recovery_codes
            .get(user_id)
            .map_or(0, HashSet::len))
    }

    async fn delete_step_up_recovery_codes(&self, user_id: &str) -> Result<(), AuthError> {
        self.state.write().await.recovery_codes.remove(user_id);
        Ok(())
    }
}
