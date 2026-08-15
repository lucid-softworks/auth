use super::{AuthService, SignInResult, password::verify_password, random_token};
use crate::{Assurance, AuthError, SessionWithUser};
use chrono::Utc;
use serde_json::json;

const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeStatus {
    pub remaining: usize,
}

impl AuthService {
    pub async fn generate_recovery_codes(
        &self,
        actor: &SessionWithUser,
        password: String,
    ) -> Result<Vec<String>, AuthError> {
        require_strong_account_session(actor)?;
        if self.store.list_passkeys(actor.user.id).await?.is_empty() {
            return Err(AuthError::RecoveryCodesNotEnabled);
        }
        let password_hash = self
            .store
            .find_password_hash(actor.user.id)
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
        if !verify_password(password, Some(password_hash)).await? {
            return Err(AuthError::InvalidPassword);
        }
        let codes: Vec<_> = (0..RECOVERY_CODE_COUNT).map(|_| recovery_code()).collect();
        let hashes = codes
            .iter()
            .map(|code| self.recovery_code_hash(code))
            .collect();
        self.store
            .replace_recovery_codes(actor.user.id, hashes)
            .await?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "recovery_codes.generated",
            None,
            json!({ "count": codes.len() }),
        )
        .await?;
        Ok(codes)
    }

    pub async fn recovery_code_status(
        &self,
        actor: &SessionWithUser,
    ) -> Result<RecoveryCodeStatus, AuthError> {
        if actor.user.is_anonymous || actor.session.actor_user_id.is_some() {
            return Err(AuthError::Forbidden);
        }
        Ok(RecoveryCodeStatus {
            remaining: self.store.recovery_code_count(actor.user.id).await?,
        })
    }

    pub async fn verify_recovery_code(
        &self,
        actor: &SessionWithUser,
        code: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        if actor.user.is_anonymous
            || actor.session.actor_user_id.is_some()
            || actor.session.assurance != Assurance::PasswordPendingPasskey
        {
            return Err(AuthError::Forbidden);
        }
        let limit_key = recovery_limit_key(actor.user.id);
        let now = Utc::now();
        if self
            .store
            .rate_limit_exceeded(&limit_key, now, self.config.max_attempts)
            .await?
        {
            return Err(AuthError::RateLimited);
        }
        if self.store.recovery_code_count(actor.user.id).await? == 0 {
            return Err(AuthError::RecoveryCodesNotEnabled);
        }
        let valid = self
            .store
            .consume_recovery_code(actor.user.id, &self.recovery_code_hash(code))
            .await?;
        if !valid {
            self.store
                .record_auth_failure(&limit_key, now, self.config.lockout_window)
                .await?;
            return Err(AuthError::InvalidRecoveryCode);
        }
        self.store.clear_auth_failures(&limit_key).await?;
        let result = self
            .create_session(
                actor.user.clone(),
                Assurance::Recovery,
                None,
                None,
                ip_address,
                user_agent,
            )
            .await?;
        self.store.delete_session_by_id(actor.session.id).await?;
        let remaining = self.store.recovery_code_count(actor.user.id).await?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "recovery_code.used",
            Some(result.session.session.id.to_string()),
            json!({ "remaining": remaining }),
        )
        .await?;
        Ok(result)
    }

    fn recovery_code_hash(&self, code: &str) -> String {
        self.sign(normalize_recovery_code(code).as_bytes())
    }
}

fn require_strong_account_session(session: &SessionWithUser) -> Result<(), AuthError> {
    if session.user.is_anonymous
        || session.session.actor_user_id.is_some()
        || !matches!(
            session.session.assurance,
            Assurance::Passkey | Assurance::PasswordAndPasskey | Assurance::Recovery
        )
    {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn recovery_code() -> String {
    let raw: String = random_token().chars().take(10).collect();
    format!("{}-{}", &raw[..5], &raw[5..])
}

fn normalize_recovery_code(code: &str) -> String {
    code.trim()
        .chars()
        .filter(|character| *character != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

fn recovery_limit_key(user_id: uuid::Uuid) -> String {
    format!("recovery:{user_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, AuthStore, MemoryStore, NewPasswordUser, StoredPasskey};
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    async fn recovery_codes_are_one_time_and_replace_the_pending_session() {
        let store = Arc::new(MemoryStore::default());
        let service = AuthService::new(store.clone(), AuthConfig::new([81_u8; 32]).unwrap());
        let user = service
            .provision_password_user(NewPasswordUser {
                username: "luna".into(),
                name: "Luna".into(),
                email: None,
                password: "correct-password".into(),
                role: "owner".into(),
            })
            .await
            .unwrap();
        let now = Utc::now();
        store
            .save_passkey(StoredPasskey {
                id: Uuid::new_v4(),
                user_id: user.id,
                name: Some("Passkey".into()),
                credential_id: "credential".into(),
                credential: json!({}),
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        let pending = service
            .sign_in_username("luna", "correct-password".into(), None, None)
            .await
            .unwrap();
        let strong = service
            .create_session(user, Assurance::PasswordAndPasskey, None, None, None, None)
            .await
            .unwrap();
        let codes = service
            .generate_recovery_codes(&strong.session, "correct-password".into())
            .await
            .unwrap();

        let recovered = service
            .verify_recovery_code(&pending.session, &codes[0].to_lowercase(), None, None)
            .await
            .unwrap();
        assert_eq!(recovered.session.session.assurance, Assurance::Recovery);
        assert!(service.session(&pending.token).await.unwrap().is_none());
        assert_eq!(
            service
                .recovery_code_status(&recovered.session)
                .await
                .unwrap()
                .remaining,
            RECOVERY_CODE_COUNT - 1
        );
    }
}
