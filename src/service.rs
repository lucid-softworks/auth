mod access;
mod api_key;
mod guest;
mod passkey;
mod password;
mod recovery;
mod session;
mod user;

use crate::PasswordBreachChecker;
use crate::{Assurance, AuthError, AuthSession, AuthStore, AuthUser, Principal, SessionWithUser};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use passkey::PasskeyCeremony;
use session::{hash_token, random_token};
use sha2::Sha256;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use uuid::Uuid;

pub use passkey::PasskeyRegistrationResult;
pub use password::PasswordChangeResult;
pub use recovery::RecoveryCodeStatus;

type HmacSha256 = Hmac<Sha256>;

/// Runtime behavior for an authentication service.
#[derive(Clone)]
pub struct AuthConfig {
    pub secret: Vec<u8>,
    pub session_ttl: Duration,
    pub cookie_secure: bool,
    pub allow_anonymous: bool,
    pub development_bypass: bool,
    pub max_attempts: usize,
    pub max_ip_attempts: usize,
    pub lockout_window: Duration,
    pub passkeys: Option<PasskeyConfig>,
    pub password_breach_checker: Option<Arc<dyn PasswordBreachChecker>>,
    pub required_mfa_roles: Vec<String>,
    /// Maximum age of strong authentication for security-sensitive operations.
    pub step_up_ttl: Duration,
}

/// Stable relying-party settings used for WebAuthn ceremonies.
#[derive(Debug, Clone)]
pub struct PasskeyConfig {
    pub rp_id: String,
    pub rp_origin: String,
    pub rp_name: String,
}

impl AuthConfig {
    pub fn new(secret: impl Into<Vec<u8>>) -> Result<Self, AuthError> {
        let secret = secret.into();
        if secret.len() < 32 {
            return Err(AuthError::InvalidConfiguration(
                "secret must contain at least 32 bytes".into(),
            ));
        }
        Ok(Self {
            secret,
            session_ttl: Duration::days(7),
            cookie_secure: false,
            allow_anonymous: false,
            development_bypass: false,
            max_attempts: 5,
            max_ip_attempts: 15,
            lockout_window: Duration::minutes(5),
            passkeys: None,
            password_breach_checker: None,
            required_mfa_roles: Vec::new(),
            step_up_ttl: Duration::minutes(15),
        })
    }
}

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
    passkey_ceremonies: Arc<Mutex<HashMap<String, PasskeyCeremony>>>,
}

impl AuthService {
    pub fn new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
            passkey_ceremonies: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn session_ttl(&self) -> Duration {
        self.config.session_ttl
    }

    pub fn cookie_secure(&self) -> bool {
        self.config.cookie_secure
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
                name: "Local Haven".into(),
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
