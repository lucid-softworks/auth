use crate::{
    Assurance, AuthError, AuthSession, AuthStore, AuthUser, NewPasswordUser, Principal,
    SessionWithUser,
};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

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
    pub lockout_window: Duration,
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
            lockout_window: Duration::minutes(5),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SignInResult {
    pub token: String,
    pub session: SessionWithUser,
}

/// Closed-registration account provisioned from an existing Argon2 password hash.
#[derive(Debug, Clone)]
pub struct HashedPasswordUser {
    pub username: String,
    pub name: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub role: String,
}

#[derive(Clone)]
pub struct AuthService {
    store: Arc<dyn AuthStore>,
    config: Arc<AuthConfig>,
    failures: Arc<Mutex<HashMap<String, VecDeque<DateTime<Utc>>>>>,
}

impl AuthService {
    pub fn new(store: Arc<dyn AuthStore>, config: AuthConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
            failures: Arc::new(Mutex::new(HashMap::new())),
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
                banned: false,
                ban_reason: None,
                ban_expires: None,
                created_at: now,
                updated_at: now,
            },
        })
    }

    pub async fn provision_password_user(
        &self,
        input: NewPasswordUser,
    ) -> Result<AuthUser, AuthError> {
        normalize_username(&input.username)?;
        if input.password.is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "password must not be empty".into(),
            ));
        }
        let password = input.password;
        let password_hash = tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|error| AuthError::Storage(error.to_string()))
        })
        .await
        .map_err(|_| AuthError::Worker)??;
        self.provision_password_hash_user(HashedPasswordUser {
            username: input.username,
            name: input.name,
            email: input.email,
            password_hash,
            role: input.role,
        })
        .await
    }

    pub async fn provision_password_hash_user(
        &self,
        input: HashedPasswordUser,
    ) -> Result<AuthUser, AuthError> {
        PasswordHash::new(&input.password_hash).map_err(|error| {
            AuthError::InvalidConfiguration(format!("invalid password hash: {error}"))
        })?;
        let username = normalize_username(&input.username)?;
        let now = Utc::now();
        let email = input
            .email
            .unwrap_or_else(|| format!("{username}@users.localhost"));
        self.store
            .upsert_password_user(
                AuthUser {
                    id: Uuid::new_v4(),
                    username: Some(username.clone()),
                    display_username: Some(input.username),
                    name: input.name,
                    email,
                    email_verified: false,
                    image: None,
                    role: input.role,
                    is_anonymous: false,
                    banned: false,
                    ban_reason: None,
                    ban_expires: None,
                    created_at: now,
                    updated_at: now,
                },
                input.password_hash,
            )
            .await
    }

    pub async fn sign_in_username(
        &self,
        username: &str,
        password: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let username = normalize_username(username).map_err(|_| AuthError::InvalidCredentials)?;
        self.enforce_rate_limit(&username).await?;
        let user = self.store.find_user_by_username(&username).await?;
        let password_hash = match &user {
            Some(user) => self.store.find_password_hash(user.id).await?,
            None => None,
        };
        let password_valid = verify_password(password, password_hash).await?;
        let Some(user) = user.filter(|_| password_valid) else {
            self.record_failure(&username).await;
            return Err(AuthError::InvalidCredentials);
        };
        if user.banned && user.ban_expires.is_none_or(|expires| expires > Utc::now()) {
            return Err(AuthError::AccountDisabled);
        }
        self.failures.lock().await.remove(&username);
        self.create_session(
            user,
            Assurance::Password,
            None,
            None,
            ip_address,
            user_agent,
        )
        .await
    }

    pub async fn username_available(&self, username: &str) -> Result<bool, AuthError> {
        let username = normalize_username(username)?;
        Ok(self.store.find_user_by_username(&username).await?.is_none())
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
        Ok(Some(SessionWithUser { session, user }))
    }

    pub async fn principal(&self, token: &str) -> Result<Option<Principal>, AuthError> {
        Ok(self
            .session(token)
            .await?
            .map(|session| session.principal()))
    }

    pub async fn sign_out(&self, token: &str) -> Result<(), AuthError> {
        self.store.delete_session(&hash_token(token)).await
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
        let token = random_token();
        let now = Utc::now();
        let session = AuthSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: hash_token(&token),
            actor_user_id,
            guest_grant_id,
            assurance,
            expires_at: now + self.config.session_ttl,
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
        })
    }

    async fn enforce_rate_limit(&self, username: &str) -> Result<(), AuthError> {
        let now = Utc::now();
        let cutoff = now - self.config.lockout_window;
        let mut failures = self.failures.lock().await;
        let attempts = failures.entry(username.to_owned()).or_default();
        while attempts.front().is_some_and(|failure| *failure <= cutoff) {
            attempts.pop_front();
        }
        if attempts.len() >= self.config.max_attempts {
            return Err(AuthError::RateLimited);
        }
        Ok(())
    }

    async fn record_failure(&self, username: &str) {
        self.failures
            .lock()
            .await
            .entry(username.to_owned())
            .or_default()
            .push_back(Utc::now());
    }

    fn sign(&self, value: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.config.secret)
            .expect("HMAC accepts arbitrary key lengths");
        mac.update(value);
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

fn normalize_username(value: &str) -> Result<String, AuthError> {
    let value = value.trim().to_lowercase();
    if !(3..=30).contains(&value.len())
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
    {
        return Err(AuthError::InvalidConfiguration(
            "username must contain 3-30 ASCII letters, numbers, dots or underscores".into(),
        ));
    }
    Ok(value)
}

async fn verify_password(
    password: String,
    password_hash: Option<String>,
) -> Result<bool, AuthError> {
    tokio::task::spawn_blocking(move || {
        let Some(password_hash) = password_hash else {
            let salt = SaltString::generate(&mut OsRng);
            let _ = Argon2::default().hash_password(password.as_bytes(), &salt);
            return false;
        };
        PasswordHash::new(&password_hash).ok().is_some_and(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .is_ok()
        })
    })
    .await
    .map_err(|_| AuthError::Worker)
}

fn random_token() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStore;

    fn service(allow_anonymous: bool) -> AuthService {
        let mut config = AuthConfig::new([7_u8; 32]).unwrap();
        config.allow_anonymous = allow_anonymous;
        AuthService::new(Arc::new(MemoryStore::default()), config)
    }

    #[tokio::test]
    async fn provisions_and_authenticates_a_password_user() {
        let service = service(false);
        let user = service
            .provision_password_user(NewPasswordUser {
                username: "Luna".into(),
                name: "Luna".into(),
                email: None,
                password: "password".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();

        let result = service
            .sign_in_username("luna", "password".into(), None, None)
            .await
            .unwrap();

        assert_eq!(result.session.user, user);
        assert_eq!(result.session.principal().actor_id, user.id);
        assert_eq!(result.session.principal().assurance, Assurance::Password);
        assert!(service.session(&result.token).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn creates_a_restricted_anonymous_principal() {
        let service = service(true);
        let result = service.sign_in_anonymous(None, None).await.unwrap();

        assert!(result.session.user.is_anonymous);
        assert_eq!(result.session.user.role, "guest");
        assert_eq!(result.session.principal().assurance, Assurance::Anonymous);
    }

    #[test]
    fn rejects_modified_session_cookies() {
        let service = service(false);
        let signed = service.signed_cookie_value("session-token");
        assert_eq!(
            service.verify_cookie_value(&signed).as_deref(),
            Some("session-token")
        );
        assert!(
            service
                .verify_cookie_value(&format!("changed{signed}"))
                .is_none()
        );
    }
}
