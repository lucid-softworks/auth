use super::AuthService;
use crate::{
    AuthError, AuthSession, AuthUser, DatabaseCreate, PreparedDatabaseId, SessionStorageMode,
    SessionWithUser,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::max;

use super::session_references::session_id_key;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CachedSession {
    session: AuthSession,
    user: AuthUser,
}

impl AuthService {
    pub(super) async fn refresh_secondary_user_sessions(
        &self,
        user: &AuthUser,
    ) -> Result<(), AuthError> {
        let Some(secondary) = &self.config.secondary_storage else {
            return Ok(());
        };
        for reference in self.active_references(&user.id).await? {
            let Some(raw) = secondary.get(&reference.token).await? else {
                continue;
            };
            let Ok(mut cached) = serde_json::from_str::<CachedSession>(&raw) else {
                continue;
            };
            let remaining = ttl(cached.session.expires_at);
            if remaining == 0 {
                continue;
            }
            cached.user = user.clone();
            secondary
                .set(
                    &reference.token,
                    serde_json::to_string(&cached).map_err(storage_json)?,
                    Some(remaining),
                )
                .await?;
        }
        Ok(())
    }

    pub(super) async fn persist_session(
        &self,
        token: &str,
        session: DatabaseCreate<AuthSession>,
        user: &AuthUser,
    ) -> Result<AuthSession, AuthError> {
        let secondary = self.config.secondary_storage.as_ref();
        let store_in_database = secondary.is_none()
            && self.config.session.storage_mode == SessionStorageMode::Database
            || secondary.is_some() && self.config.session.store_session_in_database;
        let session = if store_in_database {
            self.store.create_session(session).await?
        } else {
            let mut record = session.record;
            record.id = match session.id.prepare(self.store.as_ref())? {
                PreparedDatabaseId::Value(value) => value.into_output_string(),
                PreparedDatabaseId::Deferred | PreparedDatabaseId::DeferredSerial => {
                    return Err(AuthError::Storage(
                        "session ID generation was deferred without database storage".into(),
                    ));
                }
            };
            record
        };
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
            return Ok(session);
        };
        self.persist_secondary_session(secondary.as_ref(), token, &session, user)
            .await?;
        Ok(session)
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
            .set(&session_id_key(&session.id), token.into(), Some(ttl))
            .await?;
        self.add_active_reference(&user.id, token, session.expires_at)
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

    pub(super) async fn update_stored_session_fields(
        &self,
        current: &SessionWithUser,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        let Some(secondary) = &self.config.secondary_storage else {
            return self
                .store
                .update_session_fields(&current.session.id, fields)
                .await;
        };
        let Some(raw) = secondary.get(&current.session.token).await? else {
            return Ok(None);
        };
        let cached: CachedSession = serde_json::from_str(&raw).map_err(storage_json)?;
        let updated = if self.config.session.store_session_in_database {
            let Some(updated) = self
                .store
                .update_session_fields(&current.session.id, fields)
                .await?
            else {
                return Ok(None);
            };
            updated
        } else {
            let mut updated = cached.session;
            updated.additional_fields.extend(fields);
            updated.updated_at = Utc::now();
            updated
        };
        self.persist_secondary_session(
            secondary.as_ref(),
            &current.session.token,
            &updated,
            &cached.user,
        )
        .await?;
        Ok(Some(updated))
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
        user_id: &str,
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
        session_id: &str,
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
                    .delete(&session_id_key(&session.session.id))
                    .await?;
                self.remove_active_reference(&session.user.id, token)
                    .await?;
            }
            if self.config.session.store_session_in_database {
                if self.config.session.preserve_session_in_database {
                    if let Some(session) = &current {
                        self.store
                            .expire_session(&session.session.id, Utc::now())
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
        session_id: &str,
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
        user_id: &str,
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
}

fn ttl(expires_at: DateTime<Utc>) -> u64 {
    ttl_from_millis(expires_at.timestamp_millis())
}

pub(super) fn ttl_from_millis(expires_at: i64) -> u64 {
    u64::try_from(max(expires_at - Utc::now().timestamp_millis(), 0) / 1_000).unwrap_or(0)
}

pub(super) fn storage_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!(
        "secondary-storage session JSON is invalid: {error}"
    ))
}
