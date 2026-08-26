use super::AuthService;
use crate::{
    AuthError, SessionWithUser,
    session_cache::{self, SessionCachePayload},
};
use chrono::Utc;
use serde_json::Value;

impl AuthService {
    #[cfg(feature = "axum")]
    pub(crate) fn session_data_cookie(&self) -> crate::cookie::ResolvedCookie {
        self.resolve_cookie(crate::cookie::CookieKind::SessionData)
    }

    #[cfg(feature = "axum")]
    pub(crate) fn dont_remember_cookie(&self) -> crate::cookie::ResolvedCookie {
        self.resolve_cookie(crate::cookie::CookieKind::DontRemember)
    }

    pub(crate) fn cookie_cache_enabled(&self) -> bool {
        self.config.session.cookie_cache.enabled
    }

    pub(crate) fn stateless_sessions(&self) -> bool {
        self.config.session.storage_mode == crate::SessionStorageMode::Stateless
            && self.config.secondary_storage.is_none()
    }

    pub(crate) fn cookie_cache_max_age(&self) -> i64 {
        self.config.session.cookie_cache.max_age.num_seconds()
    }

    pub(crate) async fn encode_session_cookie_cache(
        &self,
        token: &str,
        supplied: Option<&SessionWithUser>,
    ) -> Result<Option<String>, AuthError> {
        if !self.cookie_cache_enabled() {
            return Ok(None);
        }
        let owned;
        let session = if let Some(session) = supplied {
            session
        } else if let Some(session) = self.find_stored_session(token).await? {
            owned = session;
            &owned
        } else if let Some(session) = self.take_pending_stateless_session(token).await {
            owned = session;
            &owned
        } else {
            return Ok(None);
        };
        let response = self
            .better_auth_session_response(session, token.to_owned())
            .await?;
        let mut session = serde_json::to_value(response.session).map_err(cache_json)?;
        let mut user = serde_json::to_value(response.user).map_err(cache_json)?;
        normalize_javascript_dates(&mut session);
        normalize_javascript_dates(&mut user);
        let payload = SessionCachePayload {
            session,
            user,
            updated_at: Utc::now().timestamp_millis(),
            version: self.cookie_cache_version().into(),
        };
        if let Some(config) = self.jwt_cookie_cache_config() {
            crate::jwt::encode_cookie_cache(self, config, payload, self.cookie_cache_max_age())
                .await
                .map(Some)
        } else {
            session_cache::encode(
                payload,
                self.config.session.cookie_cache.strategy,
                &self.config.secret,
                self.cookie_cache_max_age(),
            )
            .map(Some)
        }
    }

    pub(crate) async fn decode_session_cookie_cache(
        &self,
        token: &str,
        value: &str,
    ) -> Option<(Value, i64)> {
        let (payload, expires_at) = if let Some(config) = self.jwt_cookie_cache_config() {
            crate::jwt::decode_cookie_cache(self, config, value).await?
        } else {
            session_cache::decode(
                value,
                self.config.session.cookie_cache.strategy,
                &self.config.secret,
            )?
        };
        if payload.version != self.cookie_cache_version()
            || expires_at < Utc::now().timestamp_millis()
            || payload.session.get("token")?.as_str()? != token
            || chrono::DateTime::parse_from_rfc3339(payload.session.get("expiresAt")?.as_str()?)
                .ok()?
                < Utc::now()
        {
            return None;
        }
        let value = serde_json::json!({
            "session": payload.session,
            "user": payload.user,
        });
        serde_json::from_value::<crate::protocol::better_auth::SessionResponse>(value.clone())
            .ok()?;
        Some((value, expires_at))
    }

    pub(crate) async fn decode_cookie_cached_session(
        &self,
        token: &str,
        value: &str,
    ) -> Option<SessionWithUser> {
        let (response, _) = self.decode_session_cookie_cache(token, value).await?;
        let response: crate::protocol::better_auth::SessionResponse =
            serde_json::from_value(response).ok()?;
        let session = native_cookie_session(token, response.session)?;
        let user = response.user;
        Some(SessionWithUser {
            session,
            user: crate::AuthUser {
                id: user.id,
                username: user.username,
                display_username: user.display_username,
                name: user.name,
                email: user.email,
                email_verified: user.email_verified,
                image: user.image,
                additional_fields: user.additional_fields,
                role: user.role.unwrap_or_else(|| "user".into()),
                is_anonymous: user.is_anonymous.unwrap_or(false),
                banned: user.banned.unwrap_or(false),
                ban_reason: user.ban_reason.flatten(),
                ban_expires: user.ban_expires.flatten(),
                created_at: user.created_at,
                updated_at: user.updated_at,
            },
        })
    }

    pub(crate) fn should_refresh_cookie_cache(&self, expires_at: i64) -> bool {
        if !self.stateless_sessions() {
            return false;
        }
        let update_age = match self.config.session.cookie_cache.refresh_cache {
            crate::CookieCacheRefresh::Disabled => return false,
            crate::CookieCacheRefresh::Enabled => {
                self.config.session.cookie_cache.max_age.num_milliseconds() / 5
            }
            crate::CookieCacheRefresh::UpdateAge(update_age) => update_age.num_milliseconds(),
        };
        expires_at - Utc::now().timestamp_millis() < update_age
    }

    pub(crate) async fn refresh_session_cookie_cache(
        &self,
        value: &str,
    ) -> Result<Option<String>, AuthError> {
        let decoded = if let Some(config) = self.jwt_cookie_cache_config() {
            crate::jwt::decode_cookie_cache(self, config, value).await
        } else {
            session_cache::decode(
                value,
                self.config.session.cookie_cache.strategy,
                &self.config.secret,
            )
        };
        let Some((mut payload, _)) = decoded else {
            return Ok(None);
        };
        payload.updated_at = Utc::now().timestamp_millis();
        if let Some(config) = self.jwt_cookie_cache_config() {
            crate::jwt::encode_cookie_cache(self, config, payload, self.cookie_cache_max_age())
                .await
                .map(Some)
        } else {
            session_cache::encode(
                payload,
                self.config.session.cookie_cache.strategy,
                &self.config.secret,
                self.cookie_cache_max_age(),
            )
            .map(Some)
        }
    }

    fn jwt_cookie_cache_config(&self) -> Option<&crate::JwtConfig> {
        self.jwt_plugin()
            .map(crate::JwtPlugin::config)
            .filter(|config| config.session_cookie_cache)
    }

    fn cookie_cache_version(&self) -> &str {
        if self.config.session.cookie_cache.version.is_empty() {
            "1"
        } else {
            &self.config.session.cookie_cache.version
        }
    }
}

fn native_cookie_session(
    token: &str,
    session: crate::protocol::better_auth::BetterAuthSession,
) -> Option<crate::AuthSession> {
    Some(crate::AuthSession {
        id: session.id,
        user_id: session.user_id,
        token: token.into(),
        actor_user_id: session.impersonated_by,
        authentication_method: None,
        expires_at: session.expires_at,
        created_at: session.created_at,
        updated_at: session.updated_at,
        ip_address: session.ip_address,
        user_agent: session.user_agent,
        additional_fields: session.additional_fields,
    })
}

fn cache_json(error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!("session cookie-cache JSON failed: {error}"))
}

fn normalize_javascript_dates(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Ok(date) = chrono::DateTime::parse_from_rfc3339(text) {
                *text = date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(normalize_javascript_dates),
        Value::Object(values) => values.values_mut().for_each(normalize_javascript_dates),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::better_auth::BetterAuthSession;
    use chrono::Duration;
    use uuid::Uuid;

    #[test]
    fn cookie_cache_decode_does_not_fabricate_authentication_method() {
        let now = Utc::now();
        let actor = Uuid::new_v4();
        let session = native_cookie_session(
            "wire-token",
            BetterAuthSession {
                id: Uuid::new_v4().to_string(),
                user_id: Uuid::new_v4().to_string(),
                expires_at: now + Duration::minutes(5),
                token: "wire-token".into(),
                created_at: now,
                updated_at: now,
                ip_address: None,
                user_agent: None,
                additional_fields: serde_json::Map::new(),
                impersonated_by: Some(actor.to_string()),
            },
        )
        .unwrap();

        assert_eq!(session.authentication_method, None);
        assert_eq!(session.actor_user_id, Some(actor.to_string()));
    }
}
