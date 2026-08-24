use super::MemoryStore;
use crate::{AuthError, AuthSession, AuthUser};
use chrono::{DateTime, Utc};
use uuid::Uuid;

pub(super) async fn create(store: &MemoryStore, session: AuthSession) -> Result<(), AuthError> {
    store
        .state
        .write()
        .await
        .sessions
        .insert(session.token.clone(), session);
    Ok(())
}

pub(super) async fn find(
    store: &MemoryStore,
    token: &str,
) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
    let state = store.state.read().await;
    let Some(session) = state.sessions.get(token).cloned() else {
        return Ok(None);
    };
    Ok(state
        .users
        .get(&session.user_id)
        .cloned()
        .map(|user| (session, user)))
}

pub(super) async fn find_by_id(
    store: &MemoryStore,
    session_id: Uuid,
) -> Result<Option<AuthSession>, AuthError> {
    Ok(store
        .state
        .read()
        .await
        .sessions
        .values()
        .find(|session| session.id == session_id)
        .cloned())
}

pub(super) async fn update_fields(
    store: &MemoryStore,
    session_id: Uuid,
    fields: serde_json::Map<String, serde_json::Value>,
) -> Result<Option<AuthSession>, AuthError> {
    let mut state = store.state.write().await;
    let Some(session) = state
        .sessions
        .values_mut()
        .find(|session| session.id == session_id)
    else {
        return Ok(None);
    };
    session.additional_fields.extend(fields);
    session.updated_at = Utc::now();
    Ok(Some(session.clone()))
}

pub(super) async fn refresh(
    store: &MemoryStore,
    token: &str,
    expires_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
) -> Result<Option<AuthSession>, AuthError> {
    let mut state = store.state.write().await;
    let Some(session) = state.sessions.get_mut(token) else {
        return Ok(None);
    };
    session.expires_at = expires_at;
    session.updated_at = updated_at;
    Ok(Some(session.clone()))
}

pub(super) async fn delete(store: &MemoryStore, token: &str) -> Result<(), AuthError> {
    let mut state = store.state.write().await;
    if let Some(session) = state.sessions.remove(token) {
        state.guest_sessions.remove(&session.id);
    }
    Ok(())
}

pub(super) async fn expire(
    store: &MemoryStore,
    session_id: Uuid,
    expires_at: DateTime<Utc>,
) -> Result<(), AuthError> {
    if let Some(session) = store
        .state
        .write()
        .await
        .sessions
        .values_mut()
        .find(|session| session.id == session_id)
    {
        session.expires_at = expires_at;
        session.updated_at = expires_at;
    }
    Ok(())
}

pub(super) async fn delete_expired(
    store: &MemoryStore,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    let mut state = store.state.write().await;
    state.sessions.retain(|_, session| session.expires_at > now);
    let active_sessions: std::collections::HashSet<_> =
        state.sessions.values().map(|session| session.id).collect();
    state
        .guest_sessions
        .retain(|session_id, _| active_sessions.contains(session_id));
    Ok(())
}
