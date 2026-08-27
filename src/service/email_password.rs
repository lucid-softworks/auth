use super::{AuthService, SignInResult, password::verify_password};
use crate::{AuthError, AuthUser, AuthenticationMethod, DatabaseModel, SessionWithUser};
use chrono::{Duration, Utc};

use super::context_id::ContextIdFallback;

/// Core fields accepted by Better Auth's email signup flow.
#[derive(Debug, Clone)]
pub struct EmailSignUpInput {
    pub name: String,
    pub email: String,
    pub password: String,
    pub image: Option<String>,
    pub callback_url: Option<String>,
    pub remember_me: Option<bool>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

/// A created or deliberately synthetic signup result.
#[derive(Debug, Clone)]
pub struct EmailSignUpResult {
    pub token: Option<String>,
    pub user: AuthUser,
}

impl AuthService {
    pub async fn verify_current_password(
        &self,
        session: &SessionWithUser,
        password: String,
    ) -> Result<(), AuthError> {
        if session.user.is_anonymous || session.session.actor_user_id.is_some() {
            return Err(AuthError::InvalidPassword);
        }
        let hash = self.store.find_password_hash(&session.user.id).await?;
        if verify_password(password, hash).await? {
            Ok(())
        } else {
            Err(AuthError::InvalidPassword)
        }
    }

    pub async fn sign_up_email(
        &self,
        input: EmailSignUpInput,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<EmailSignUpResult, AuthError> {
        let config = &self.config.email_and_password;
        if !config.enabled || config.disable_sign_up {
            return Err(AuthError::EmailPasswordSignUpDisabled);
        }
        let email = normalize_email(&input.email)?;
        self.validate_new_password(&input.password).await?;
        let (username, display_username) = self
            .prepare_username_signup(input.username, input.display_username)
            .await?;
        let additional_fields =
            self.create_additional_fields(DatabaseModel::User, input.additional_fields)?;
        let generic_duplicates = config.require_email_verification || !config.auto_sign_in;
        if self.store.find_user_by_email(&email).await?.is_some() {
            let _ = self.hash_password(input.password).await?;
            return if generic_duplicates {
                Ok(self.synthetic_signup(input.name, email, input.image, additional_fields))
            } else {
                Err(AuthError::UserAlreadyExistsEmail)
            };
        }

        let password_hash = self.hash_password(input.password).await?;
        let user = new_signup_user(
            username,
            display_username,
            input.name,
            email,
            input.image,
            additional_fields,
            self.default_user_role(),
        );
        let synthetic = (
            user.name.clone(),
            user.email.clone(),
            user.image.clone(),
            user.additional_fields.clone(),
        );
        let user = match self.persist_email_signup_user(user, password_hash).await {
            Ok(user) => user,
            Err(AuthError::UserAlreadyExists) if generic_duplicates => {
                return Ok(self.synthetic_signup(
                    synthetic.0,
                    synthetic.1,
                    synthetic.2,
                    synthetic.3,
                ));
            }
            Err(AuthError::UserAlreadyExists) => return Err(AuthError::UserAlreadyExistsEmail),
            Err(error) => return Err(error),
        };
        self.maybe_send_signup_verification(&user, input.callback_url.as_deref())
            .await?;
        if config.require_email_verification || !config.auto_sign_in {
            return Ok(EmailSignUpResult { token: None, user });
        }
        let result = self
            .create_email_password_session(user, input.remember_me, ip_address, user_agent)
            .await?;
        Ok(EmailSignUpResult {
            token: Some(result.token),
            user: result.session.user,
        })
    }

    async fn persist_email_signup_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError> {
        let owner = self
            .create_user_and_credential_account(user, password_hash)
            .await?;
        Ok(owner.user)
    }

    fn synthetic_signup(
        &self,
        name: String,
        email: String,
        image: Option<String>,
        additional_fields: serde_json::Map<String, serde_json::Value>,
    ) -> EmailSignUpResult {
        let id = self
            .generate_special_database_id("user", ContextIdFallback::Falsey, 32.0)
            .expect("the fixed synthetic-signup ID length is valid");
        synthetic_signup(
            id,
            name,
            email,
            image,
            additional_fields,
            &self.default_user_role(),
        )
    }

    pub async fn sign_in_email(
        &self,
        email: &str,
        password: String,
        remember_me: Option<bool>,
        callback_url: Option<&str>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        if !self.config.email_and_password.enabled {
            return Err(AuthError::EmailPasswordDisabled);
        }
        let email = normalize_email(email)?;
        let user = self.store.find_user_by_email(&email).await?;
        let password_hash = match &user {
            Some(user) => self.store.find_password_hash(&user.id).await?,
            None => None,
        };
        let password_valid = verify_password(password, password_hash).await?;
        let Some(user) = user.filter(|_| password_valid) else {
            return Err(AuthError::InvalidEmailOrPassword);
        };
        if self.config.email_and_password.require_email_verification && !user.email_verified {
            self.maybe_send_signin_verification(&user, callback_url)
                .await?;
            return Err(AuthError::EmailNotVerified);
        }
        self.create_email_password_session(user, remember_me, ip_address, user_agent)
            .await
    }

    pub(super) async fn create_email_password_session(
        &self,
        user: AuthUser,
        remember_me: Option<bool>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        if remember_me == Some(false) {
            return self
                .create_session_expiring_at(
                    user,
                    AuthenticationMethod::Password,
                    None,
                    Utc::now() + Duration::days(1),
                    ip_address,
                    user_agent,
                )
                .await;
        }
        self.create_session(
            user,
            AuthenticationMethod::Password,
            None,
            ip_address,
            user_agent,
        )
        .await
    }
}

pub(super) fn normalize_email(email: &str) -> Result<String, AuthError> {
    if !valid_email(email) {
        return Err(AuthError::InvalidEmail);
    }
    Ok(email.to_lowercase())
}

pub(crate) fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    if domain.contains('@')
        || local.starts_with('.')
        || local.contains("..")
        || local.is_empty()
        || !local
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_'+-.".contains(character))
        || !local
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric() || "_+-".contains(character))
    {
        return false;
    }
    let labels: Vec<_> = domain.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .next()
                    .is_some_and(|character| character.is_ascii_alphanumeric())
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
        && labels.last().is_some_and(|label| {
            label.len() >= 2
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphabetic())
        })
}

fn synthetic_signup(
    id: String,
    name: String,
    email: String,
    image: Option<String>,
    additional_fields: serde_json::Map<String, serde_json::Value>,
    default_role: &str,
) -> EmailSignUpResult {
    let now = Utc::now();
    EmailSignUpResult {
        token: None,
        user: AuthUser {
            id,
            username: None,
            display_username: None,
            name,
            email,
            email_verified: false,
            image,
            additional_fields,
            role: default_role.into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        },
    }
}

fn new_signup_user(
    username: Option<String>,
    display_username: Option<String>,
    name: String,
    email: String,
    image: Option<String>,
    additional_fields: serde_json::Map<String, serde_json::Value>,
    role: String,
) -> AuthUser {
    let now = Utc::now();
    AuthUser {
        id: String::new(),
        username,
        display_username,
        name,
        email,
        email_verified: false,
        image,
        additional_fields,
        role,
        is_anonymous: false,
        banned: false,
        ban_reason: None,
        ban_expires: None,
        created_at: now,
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::valid_email;

    #[test]
    fn email_validation_matches_the_pinned_zod_practical_pattern() {
        for valid in ["person@example.com", "A.B+tag@sub.example.co.uk"] {
            assert!(valid_email(valid), "{valid}");
        }
        for invalid in [
            ".person@example.com",
            "person..tag@example.com",
            "person@example",
            "person@-example.com",
            "person@example.c0m",
        ] {
            assert!(!valid_email(invalid), "{invalid}");
        }
    }
}
