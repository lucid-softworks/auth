use super::AuthService;
use crate::{AuthError, AuthSession, AuthUser, SessionStorageMode, SessionWithUser};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::max;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedSession {
    session: AuthSession,
    user: AuthUser,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionReference {
    token: String,
    expires_at: i64,
}

impl AuthService {
    pub(super) async fn persist_session(
        &self,
        token: &str,
        session: &AuthSession,
        user: &AuthUser,
    ) -> Result<(), AuthError> {
        let secondary = self.config.secondary_storage.as_ref();
        let store_in_database = secondary.is_none()
            && self.config.session.storage_mode == SessionStorageMode::Database
            || secondary.is_some() && self.config.session.store_session_in_database;
        if store_in_database {
            self.store.create_session(session.clone()).await?;
        }
        let Some(secondary) = secondary else {
            if self.config.session.storage_mode == SessionStorageMode::Stateless {
                let mut pending = self.pending_stateless_sessions.lock().await;
                pending.retain(|_, value| value.session.expires_at > Utc::now());
                pending.insert(
                    token.into(),
                    SessionWithUser {
                        session: session.clone(),
                        user: user.clone(),
                    },
                );
            }
            return Ok(());
        };
        self.persist_secondary_session(secondary.as_ref(), token, session, user)
            .await
    }

    async fn persist_secondary_session(
        &self,
        secondary: &dyn crate::SecondaryStorage,
        token: &str,
        session: &AuthSession,
        user: &AuthUser,
    ) -> Result<(), AuthError> {
        let ttl = ttl(session.expires_at);
        if ttl == 0 {
            return Ok(());
        }
        secondary
            .set(
                token,
                serde_json::to_string(&CachedSession {
                    session: session.clone(),
                    user: user.clone(),
                })
                .map_err(storage_json)?,
                Some(ttl),
            )
            .await?;
        secondary
            .set(&session_id_key(session.id), token.into(), Some(ttl))
            .await?;
        self.add_active_reference(user.id, token, session.expires_at)
            .await
    }

    #[cfg(feature = "axum")]
    pub(super) async fn refresh_stored_session(
        &self,
        candidate: &SessionWithUser,
    ) -> Result<Option<AuthSession>, AuthError> {
        let token = &candidate.session.token;
        let Some(secondary) = &self.config.secondary_storage else {
            return self
                .store
                .refresh_session(
                    token,
                    candidate.session.expires_at,
                    candidate.session.updated_at,
                )
                .await;
        };
        if self.config.session.store_session_in_database {
            let Some(updated) = self
                .store
                .refresh_session(
                    token,
                    candidate.session.expires_at,
                    candidate.session.updated_at,
                )
                .await?
            else {
                return Ok(None);
            };
            self.persist_secondary_session(secondary.as_ref(), token, &updated, &candidate.user)
                .await?;
            return Ok(Some(updated));
        }
        if secondary.get(token).await?.is_none() {
            return Ok(None);
        }
        self.persist_secondary_session(
            secondary.as_ref(),
            token,
            &candidate.session,
            &candidate.user,
        )
        .await?;
        Ok(Some(candidate.session.clone()))
    }

    #[cfg(feature = "axum")]
    pub(super) async fn take_pending_stateless_session(
        &self,
        token: &str,
    ) -> Option<SessionWithUser> {
        self.pending_stateless_sessions.lock().await.remove(token)
    }

    pub(super) async fn find_stored_session(
        &self,
        token: &str,
    ) -> Result<Option<SessionWithUser>, AuthError> {
        if let Some(secondary) = &self.config.secondary_storage {
            if let Some(value) = secondary.get(token).await? {
                let cached: CachedSession = serde_json::from_str(&value).map_err(storage_json)?;
                return Ok(Some(SessionWithUser {
                    session: cached.session,
                    user: cached.user,
                }));
            }
            if !self.config.session.store_session_in_database
                || self.config.session.preserve_session_in_database
            {
                return Ok(None);
            }
        } else if self.config.session.storage_mode == SessionStorageMode::Stateless {
            return Ok(None);
        }
        Ok(self
            .store
            .find_session(token)
            .await?
            .map(|(session, user)| SessionWithUser { session, user }))
    }

    pub(super) async fn stored_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(String, AuthSession)>, AuthError> {
        if self.config.secondary_storage.is_some() {
            let mut sessions = Vec::new();
            for reference in self.active_references(user_id).await? {
                if let Some(session) = self.find_stored_session(&reference.token).await? {
                    sessions.push((reference.token, session.session));
                }
            }
            return Ok(sessions);
        }
        if self.config.session.storage_mode == SessionStorageMode::Stateless {
            return Ok(Vec::new());
        }
        Ok(self
            .store
            .list_sessions(user_id)
            .await?
            .into_iter()
            .map(|session| (session.token.clone(), session))
            .collect())
    }

    pub(super) async fn find_stored_session_by_id(
        &self,
        session_id: Uuid,
    ) -> Result<Option<(String, AuthSession)>, AuthError> {
        if let Some(secondary) = &self.config.secondary_storage
            && let Some(token) = secondary.get(&session_id_key(session_id)).await?
            && let Some(session) = self.find_stored_session(&token).await?
        {
            return Ok(Some((token, session.session)));
        }
        Ok(self
            .store
            .find_session_by_id(session_id)
            .await?
            .map(|session| (session.token.clone(), session)))
    }

    pub(super) async fn delete_stored_session_token(
        &self,
        token: &str,
    ) -> Result<Option<AuthSession>, AuthError> {
        let current = self.find_stored_session(token).await?;
        if let Some(secondary) = &self.config.secondary_storage {
            secondary.delete(token).await?;
            if let Some(session) = &current {
                secondary
                    .delete(&session_id_key(session.session.id))
                    .await?;
                self.remove_active_reference(session.user.id, token).await?;
            }
            if self.config.session.store_session_in_database {
                if self.config.session.preserve_session_in_database {
                    if let Some(session) = &current {
                        self.store
                            .expire_session(session.session.id, Utc::now())
                            .await?;
                    }
                } else {
                    self.store.delete_session(token).await?;
                }
            }
        } else if self.config.session.storage_mode == SessionStorageMode::Database {
            self.store.delete_session(token).await?;
        }
        Ok(current.map(|session| session.session))
    }

    pub(super) async fn delete_stored_session_id(
        &self,
        session_id: Uuid,
    ) -> Result<Option<AuthSession>, AuthError> {
        if let Some((token, session)) = self.find_stored_session_by_id(session_id).await? {
            if self.config.secondary_storage.is_some() {
                self.delete_stored_session_token(&token).await?;
            } else {
                self.store.delete_session_by_id(session_id).await?;
            }
            return Ok(Some(session));
        }
        Ok(None)
    }

    pub(super) async fn delete_stored_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<AuthSession>, AuthError> {
        if self.config.secondary_storage.is_some() {
            let sessions = self.stored_sessions(user_id).await?;
            let records = sessions
                .iter()
                .map(|(_, session)| session.clone())
                .collect();
            for (token, _) in sessions {
                self.delete_stored_session_token(&token).await?;
            }
            return Ok(records);
        }
        let records = self.store.list_sessions(user_id).await?;
        self.store.delete_user_sessions(user_id).await?;
        Ok(records)
    }

    async fn active_references(&self, user_id: Uuid) -> Result<Vec<SessionReference>, AuthError> {
        let Some(secondary) = &self.config.secondary_storage else {
            return Ok(Vec::new());
        };
        let Some(value) = secondary.get(&active_key(user_id)).await? else {
            return Ok(Vec::new());
        };
        let now = Utc::now().timestamp_millis();
        let mut references: Vec<SessionReference> =
            serde_json::from_str(&value).map_err(storage_json)?;
        references.retain(|reference| reference.expires_at > now);
        Ok(references)
    }

    async fn add_active_reference(
        &self,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let secondary = self
            .config
            .secondary_storage
            .as_ref()
            .expect("secondary storage was checked");
        let mut references = self.active_references(user_id).await?;
        references.retain(|reference| reference.token != token);
        references.push(SessionReference {
            token: token.into(),
            expires_at: expires_at.timestamp_millis(),
        });
        references.sort_by_key(|reference| reference.expires_at);
        let furthest = references
            .last()
            .map(|reference| reference.expires_at)
            .unwrap_or_default();
        secondary
            .set(
                &active_key(user_id),
                serde_json::to_string(&references).map_err(storage_json)?,
                Some(ttl_from_millis(furthest)),
            )
            .await
    }

    async fn remove_active_reference(&self, user_id: Uuid, token: &str) -> Result<(), AuthError> {
        let secondary = self
            .config
            .secondary_storage
            .as_ref()
            .expect("secondary storage was checked");
        let mut references = self.active_references(user_id).await?;
        references.retain(|reference| reference.token != token);
        let key = active_key(user_id);
        if let Some(furthest) = references.last().map(|reference| reference.expires_at) {
            secondary
                .set(
                    &key,
                    serde_json::to_string(&references).map_err(storage_json)?,
                    Some(ttl_from_millis(furthest)),
                )
                .await
        } else {
            secondary.delete(&key).await
        }
    }
}

fn active_key(user_id: Uuid) -> String {
    format!("active-sessions-{user_id}")
}

fn session_id_key(session_id: Uuid) -> String {
    format!("session-id:{session_id}")
}

fn ttl(expires_at: DateTime<Utc>) -> u64 {
    ttl_from_millis(expires_at.timestamp_millis())
}

fn ttl_from_millis(expires_at: i64) -> u64 {
    u64::try_from(max(expires_at - Utc::now().timestamp_millis(), 0) / 1_000).unwrap_or(0)
}

fn storage_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!(
        "secondary-storage session JSON is invalid: {error}"
    ))
}
