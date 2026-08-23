mod access;
mod api_key;
mod guest;
mod passkey;
mod password;
mod recovery;
mod session;
mod user;

#[cfg(feature = "axum")]
use crate::TrustedOrigin;
#[cfg(feature = "axum")]
use crate::cookie::{CookieKind, ResolvedCookie};
use crate::{
    Assurance, AuthConfig, AuthError, AuthSession, AuthStore, AuthUser, Principal, SessionWithUser,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use session::{hash_token, random_token};
use sha2::Sha256;
#[cfg(feature = "axum")]
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

pub use passkey::PasskeyRegistrationResult;
pub use password::PasswordChangeResult;
pub use recovery::RecoveryCodeStatus;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct SignInResult {
    pub token: String,
    pub session: SessionWithUser,
    pub mfa_setup_required: bool,
}

/// Closed-registration account provisioned from an existing Argon2 password hash.
#[derive(Debug, Clone)]
pub struct HashedPasswordUser {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: String,
    pub must_change_password: bool,
}

#[derive(Clone)]
pub struct AuthService {
    store: Arc<dyn AuthStore>,
    config: Arc<AuthConfig>,
}

impl AuthService {
    pub fn new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }

    pub fn session_ttl(&self) -> Duration {
        self.config.session_ttl
    }

    pub fn cookie_secure(&self) -> bool {
        self.config.use_secure_cookies.unwrap_or_else(|| {
            self.config
                .base_url
                .as_ref()
                .is_some_and(|url| url.scheme() == "https")
        })
    }

    #[cfg(feature = "axum")]
    pub(crate) fn base_path(&self) -> &str {
        self.config.base_path()
    }

    #[cfg(feature = "axum")]
    pub(crate) fn cors_enabled(&self) -> bool {
        self.config.cors_enabled
    }

    #[cfg(feature = "axum")]
    pub(crate) fn session_cookie(&self) -> ResolvedCookie {
        self.resolve_cookie(CookieKind::SessionToken)
    }

    #[cfg(feature = "axum")]
    pub(crate) fn challenge_cookie(&self) -> ResolvedCookie {
        self.resolve_cookie(CookieKind::PasskeyChallenge)
    }

    #[cfg(feature = "axum")]
    fn resolve_cookie(&self, kind: CookieKind) -> ResolvedCookie {
        self.config.cookies.resolve(
            kind,
            self.cookie_secure(),
            self.config.base_url.as_ref().and_then(|url| url.host_str()),
        )
    }

    #[cfg(feature = "axum")]
    pub(crate) fn trusts_origin(&self, origin: &str) -> bool {
        self.config.base_url.as_ref().is_some_and(|url| {
            TrustedOrigin::parse(&url.origin().ascii_serialization())
                .is_ok_and(|trusted| trusted.matches(origin))
        }) || self
            .config
            .trusted_origins
            .iter()
            .any(|trusted| trusted.matches(origin))
    }

    #[cfg(feature = "axum")]
    pub(crate) fn resolve_client_ip<F>(&self, peer: Option<IpAddr>, header: F) -> Option<String>
    where
        F: FnMut(&str) -> Option<String>,
    {
        self.config.ip_address.resolve_client_ip(peer?, header)
    }

    pub fn development_session(&self) -> Option<SessionWithUser> {
        if !self.config.development_bypass {
            return None;
        }
        let now = Utc::now();
        let id = Uuid::nil();
        Some(SessionWithUser {
            session: AuthSession {
                id,
                user_id: id,
                token_hash: String::new(),
                actor_user_id: None,
                guest_grant_id: None,
                assurance: Assurance::Password,
                expires_at: now + Duration::days(1),
                created_at: now,
                updated_at: now,
                ip_address: None,
                user_agent: None,
            },
            user: AuthUser {
                id,
                username: Some("local".into()),
                display_username: Some("Local development".into()),
                name: "Local application".into(),
                email: "local@users.localhost".into(),
                email_verified: false,
                image: None,
                role: "owner".into(),
                is_anonymous: false,
                must_change_password: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            },
        })
    }

    pub async fn sign_in_anonymous(
        &self,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        if !self.config.allow_anonymous {
            return Err(AuthError::AnonymousAccessDisabled);
        }
        let now = Utc::now();
        let id = Uuid::new_v4();
        let user = self
            .store
            .create_anonymous_user(AuthUser {
                id,
                username: None,
                display_username: None,
                name: "Guest".into(),
                email: format!("temp-{id}@users.localhost"),
                email_verified: false,
                image: None,
                role: "guest".into(),
                is_anonymous: true,
                must_change_password: false,
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            })
            .await?;
        self.create_session(
            user,
            Assurance::Anonymous,
            None,
            None,
            ip_address,
            user_agent,
        )
        .await
    }

    pub async fn session(&self, token: &str) -> Result<Option<SessionWithUser>, AuthError> {
        let token_hash = hash_token(token);
        let Some((session, user)) = self.store.find_session(&token_hash).await? else {
            return Ok(None);
        };
        if session.expires_at <= Utc::now() {
            self.store.delete_session(&token_hash).await?;
            return Ok(None);
        }
        if user.banned && user.ban_expires.is_none_or(|expires| expires > Utc::now()) {
            return Ok(None);
        }
        if self.requires_mfa(&user)
            && session.actor_user_id.is_none()
            && session.assurance == Assurance::Password
        {
            self.store.delete_session(&token_hash).await?;
            return Ok(None);
        }
        Ok(Some(SessionWithUser { session, user }))
    }

    pub async fn principal(&self, token: &str) -> Result<Option<Principal>, AuthError> {
        let Some(session) = self.session(token).await? else {
            return Ok(None);
        };
        let mut principal = session.principal();
        if let Some(grant_id) = session.session.guest_grant_id {
            let Some(grant) = self.store.find_guest_grant(grant_id).await? else {
                return Ok(None);
            };
            let now = Utc::now();
            if grant.revoked_at.is_some() || grant.valid_from > now || grant.expires_at <= now {
                self.store.delete_session_by_id(session.session.id).await?;
                return Ok(None);
            }
            principal.permissions = grant.permissions;
            principal.resource_scopes = grant.resource_scopes;
        }
        Ok(Some(principal))
    }

    pub async fn sign_out(&self, token: &str) -> Result<(), AuthError> {
        self.store.delete_session(&hash_token(token)).await
    }

    /// Returns whether a principal must verify a strong credential again before a
    /// security-sensitive operation.
    pub fn step_up_required(&self, principal: &Principal) -> bool {
        self.config.required_mfa_roles.contains(&principal.role)
            && (!principal.assurance.is_strong()
                || principal.authenticated_at + self.config.step_up_ttl <= Utc::now())
    }

    pub fn signed_cookie_value(&self, token: &str) -> String {
        let signature = self.sign(token.as_bytes());
        format!("{token}.{signature}")
    }

    pub fn verify_cookie_value(&self, value: &str) -> Option<String> {
        let (token, signature) = value.rsplit_once('.')?;
        let decoded = URL_SAFE_NO_PAD.decode(signature).ok()?;
        let mut mac = HmacSha256::new_from_slice(&self.config.secret).ok()?;
        mac.update(token.as_bytes());
        mac.verify_slice(&decoded).ok()?;
        Some(token.to_owned())
    }

    async fn create_session(
        &self,
        user: AuthUser,
        assurance: Assurance,
        actor_user_id: Option<Uuid>,
        guest_grant_id: Option<Uuid>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.create_session_until(
            user,
            assurance,
            actor_user_id,
            guest_grant_id,
            None,
            ip_address,
            user_agent,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_session_until(
        &self,
        user: AuthUser,
        assurance: Assurance,
        actor_user_id: Option<Uuid>,
        guest_grant_id: Option<Uuid>,
        expires_at: Option<DateTime<Utc>>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let token = random_token();
        let now = Utc::now();
        let session = AuthSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: hash_token(&token),
            actor_user_id,
            guest_grant_id,
            assurance,
            expires_at: expires_at
                .unwrap_or(now + self.config.session_ttl)
                .min(now + self.config.session_ttl),
            created_at: now,
            updated_at: now,
            ip_address,
            user_agent,
        };
        self.store.delete_expired_sessions(now).await?;
        self.store.create_session(session.clone()).await?;
        Ok(SignInResult {
            token,
            session: SessionWithUser { session, user },
            mfa_setup_required: false,
        })
    }

    async fn enforce_rate_limit(
        &self,
        username: &str,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        let account_limited = self
            .store
            .rate_limit_exceeded(&account_limit_key(username), now, self.config.max_attempts)
            .await?;
        let ip_limited = match ip_address {
            Some(address) => {
                self.store
                    .rate_limit_exceeded(&ip_limit_key(address), now, self.config.max_ip_attempts)
                    .await?
            }
            None => false,
        };
        if account_limited || ip_limited {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    async fn record_failure(
        &self,
        username: &str,
        ip_address: Option<&str>,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        self.store
            .record_auth_failure(
                &account_limit_key(username),
                now,
                self.config.lockout_window,
            )
            .await?;
        if let Some(address) = ip_address {
            self.store
                .record_auth_failure(&ip_limit_key(address), now, self.config.lockout_window)
                .await?;
        }
        Ok(())
    }

    fn sign(&self, value: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.config.secret)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(value);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn requires_mfa(&self, user: &AuthUser) -> bool {
        self.config.required_mfa_roles.contains(&user.role)
    }

    fn require_recent_owner(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        access::require_owner(session)?;
        if self.step_up_required(&session.principal()) {
            return Err(AuthError::StepUpRequired);
        }
        Ok(())
    }
}

fn account_limit_key(username: &str) -> String {
    format!("sign-in:account:{}", hash_token(username))
}

fn ip_limit_key(address: &str) -> String {
    format!("sign-in:ip:{}", hash_token(address))
}
