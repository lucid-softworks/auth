use super::AuthService;
#[cfg(feature = "axum")]
use crate::DatabaseRecord;
use crate::{AuthError, SessionWithUser};
#[cfg(any(feature = "axum", test))]
use chrono::DateTime;
use chrono::Utc;

impl AuthService {
    #[cfg(feature = "axum")]
    pub(crate) fn defer_session_refresh(&self) -> bool {
        self.config.session.defer_session_refresh
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn session_for_http(
        &self,
        token: &str,
        delete_expired: bool,
    ) -> Result<Option<SessionWithUser>, AuthError> {
        self.validated_stored_session(token, delete_expired).await
    }

    pub(super) async fn validated_stored_session(
        &self,
        token: &str,
        delete_expired: bool,
    ) -> Result<Option<SessionWithUser>, AuthError> {
        let Some(session) = self.find_stored_session(token).await? else {
            return Ok(None);
        };
        if session.session.expires_at <= Utc::now() {
            if delete_expired {
                self.delete_session_token_with_hooks(token).await?;
            }
            return Ok(None);
        }
        if self.plugins.find::<crate::AdminPlugin>().is_some()
            && session.user.banned
            && session
                .user
                .ban_expires
                .is_none_or(|expires| expires > Utc::now())
        {
            return Ok(None);
        }
        if !self.plugins.validates_session(&session).await? {
            self.delete_session_id_with_hooks(session.session.id)
                .await?;
            return Ok(None);
        }
        Ok(Some(session))
    }

    #[cfg(feature = "axum")]
    pub(crate) fn session_needs_refresh(
        &self,
        session: &SessionWithUser,
        now: DateTime<Utc>,
    ) -> bool {
        needs_refresh(
            session.session.expires_at,
            now,
            self.config.session_ttl,
            self.config.session.update_age,
        ) && !self.config.session.disable_session_refresh
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn refresh_http_session(
        &self,
        current: &SessionWithUser,
        now: DateTime<Utc>,
    ) -> Result<Option<SessionWithUser>, AuthError> {
        let mut candidate = current.clone();
        candidate.session.expires_at = now + self.config.session_ttl;
        candidate.session.updated_at = now;
        candidate.session = match self
            .before_database_update(DatabaseRecord::Session(candidate.session))
            .await?
        {
            DatabaseRecord::Session(session) => session,
            _ => unreachable!("database hook model was validated"),
        };
        if candidate.session.id != current.session.id
            || candidate.session.user_id != current.session.user_id
            || candidate.session.token != current.session.token
            || candidate.session.created_at != current.session.created_at
        {
            return Err(AuthError::InvalidConfiguration(
                "a session refresh database hook changed a protected field".into(),
            ));
        }
        let Some(updated) = self.refresh_stored_session(&candidate).await? else {
            return Ok(None);
        };
        self.after_database_update(&DatabaseRecord::Session(updated.clone()))
            .await?;
        candidate.session = updated;
        Ok(Some(candidate))
    }
}

#[cfg(any(feature = "axum", test))]
fn needs_refresh(
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    expires_in: chrono::Duration,
    update_age: chrono::Duration,
) -> bool {
    expires_at - expires_in + update_age <= now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_boundary_matches_better_auth_inclusively() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).unwrap();
        let expires_in = chrono::Duration::days(7);
        let update_age = chrono::Duration::days(1);
        let boundary = now + expires_in - update_age;

        assert!(needs_refresh(boundary, now, expires_in, update_age));
        assert!(!needs_refresh(
            boundary + chrono::Duration::milliseconds(1),
            now,
            expires_in,
            update_age
        ));
    }
}
