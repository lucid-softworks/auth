use super::{AuthService, SignInResult, random_token};
use crate::{
    Assurance, AuthError, PasskeyDeleteOutcome, SessionWithUser, StoredPasskey, VerificationValue,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

const REGISTRATION_PURPOSE: &str = "passkey-registration";
const AUTHENTICATION_PURPOSE: &str = "passkey-authentication";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum PasskeyCeremony {
    Registration {
        user_id: Uuid,
        state: PasskeyRegistration,
    },
    Authentication {
        passkeys: Vec<StoredPasskey>,
        state: PasskeyAuthentication,
        prior_user_id: Option<Uuid>,
    },
}

#[derive(Debug, Clone)]
pub struct PasskeyRegistrationResult {
    pub passkey: StoredPasskey,
    pub replacement_session: Option<SignInResult>,
}

impl AuthService {
    pub async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError> {
        self.store.list_passkeys(user_id).await
    }

    pub async fn rename_passkey(
        &self,
        actor: &SessionWithUser,
        passkey_id: Uuid,
        name: &str,
    ) -> Result<StoredPasskey, AuthError> {
        require_account_session(actor)?;
        let name: String = name.trim().chars().take(80).collect();
        if name.is_empty() {
            return Err(AuthError::InvalidRequest(
                "passkey name must not be empty".into(),
            ));
        }
        let passkey = self
            .store
            .update_passkey_name(actor.user.id, passkey_id, name.clone())
            .await?
            .ok_or(AuthError::PasskeyNotFound)?;
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "passkey.renamed",
            Some(passkey_id.to_string()),
            json!({ "name": name }),
        )
        .await?;
        Ok(passkey)
    }

    pub async fn delete_passkey(
        &self,
        actor: &SessionWithUser,
        passkey_id: Uuid,
    ) -> Result<(), AuthError> {
        self.require_recent_strong_account(actor)?;
        let minimum_remaining = usize::from(self.requires_mfa(&actor.user));
        let remaining = match self
            .store
            .delete_passkey(actor.user.id, passkey_id, minimum_remaining)
            .await?
        {
            PasskeyDeleteOutcome::Deleted { remaining } => remaining,
            PasskeyDeleteOutcome::NotFound => return Err(AuthError::PasskeyNotFound),
            PasskeyDeleteOutcome::MinimumRequired => return Err(AuthError::LastPasskey),
        };
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "passkey.deleted",
            Some(passkey_id.to_string()),
            json!({ "remaining": remaining }),
        )
        .await
    }

    pub async fn start_passkey_registration(
        &self,
        actor: &SessionWithUser,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        require_account_session(actor)?;
        let webauthn = self.webauthn()?;
        let stored = self.store.list_passkeys(actor.user.id).await?;
        if !stored.is_empty() {
            self.require_recent_strong_account(actor)?;
        }
        let passkeys = deserialize_passkeys(&stored)?;
        let exclude = (!passkeys.is_empty()).then(|| {
            passkeys
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect()
        });
        let username = actor.user.username.as_deref().unwrap_or(&actor.user.email);
        let (options, state) = webauthn
            .start_passkey_registration(actor.user.id, username, &actor.user.name, exclude)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let token = random_token();
        self.store_passkey_ceremony(
            REGISTRATION_PURPOSE,
            &token,
            PasskeyCeremony::Registration {
                user_id: actor.user.id,
                state,
            },
        )
        .await?;
        Ok((token, options))
    }

    pub async fn finish_passkey_registration(
        &self,
        token: &str,
        actor: &SessionWithUser,
        response: RegisterPublicKeyCredential,
        name: Option<String>,
    ) -> Result<PasskeyRegistrationResult, AuthError> {
        let PasskeyCeremony::Registration { user_id, state, .. } = self
            .consume_passkey_ceremony(REGISTRATION_PURPOSE, token)
            .await?
        else {
            return Err(AuthError::PasskeyChallengeExpired);
        };
        if user_id != actor.user.id
            || actor.user.is_anonymous
            || actor.session.actor_user_id.is_some()
        {
            return Err(AuthError::InvalidSession);
        }
        if !self.store.list_passkeys(user_id).await?.is_empty() {
            self.require_recent_strong_account(actor)?;
        }
        let passkey = self
            .webauthn()?
            .finish_passkey_registration(&response, &state)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let now = Utc::now();
        let stored = self
            .store
            .save_passkey(StoredPasskey {
                id: Uuid::new_v4(),
                user_id,
                name: name.map(|value| value.trim().chars().take(80).collect()),
                credential_id: credential_id(&passkey)?,
                credential: serde_json::to_value(passkey)
                    .map_err(|error| AuthError::Storage(error.to_string()))?,
                created_at: now,
                updated_at: now,
            })
            .await?;
        let replacement_session = if matches!(
            actor.session.assurance,
            Assurance::Password | Assurance::PasswordPendingPasskey
        ) {
            let session = self
                .create_session(
                    actor.user.clone(),
                    Assurance::PasswordAndPasskey,
                    None,
                    None,
                    actor.session.ip_address.clone(),
                    actor.session.user_agent.clone(),
                )
                .await?;
            self.store.delete_session_by_id(actor.session.id).await?;
            Some(session)
        } else {
            None
        };
        self.audit(
            actor.user.id,
            Some(actor.user.id),
            "passkey.enrolled",
            Some(stored.id.to_string()),
            json!({}),
        )
        .await?;
        Ok(PasskeyRegistrationResult {
            passkey: stored,
            replacement_session,
        })
    }

    pub async fn start_passkey_authentication(
        &self,
        current_session: Option<&SessionWithUser>,
    ) -> Result<(String, RequestChallengeResponse), AuthError> {
        let stored = match current_session {
            Some(session) => self.store.list_passkeys(session.user.id).await?,
            None => self.store.list_all_passkeys().await?,
        };
        if stored.is_empty() {
            return Err(AuthError::PasskeyVerificationFailed);
        }
        let passkeys = deserialize_passkeys(&stored)?;
        let (options, state) = self
            .webauthn()?
            .start_passkey_authentication(&passkeys)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let token = random_token();
        self.store_passkey_ceremony(
            AUTHENTICATION_PURPOSE,
            &token,
            PasskeyCeremony::Authentication {
                passkeys: stored,
                state,
                prior_user_id: current_session.map(|session| session.user.id),
            },
        )
        .await?;
        Ok((token, options))
    }

    pub async fn finish_passkey_authentication(
        &self,
        token: &str,
        response: PublicKeyCredential,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let PasskeyCeremony::Authentication {
            passkeys,
            state,
            prior_user_id,
            ..
        } = self
            .consume_passkey_ceremony(AUTHENTICATION_PURPOSE, token)
            .await?
        else {
            return Err(AuthError::PasskeyChallengeExpired);
        };
        let result = self
            .webauthn()?
            .finish_passkey_authentication(&response, &state)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let id = serde_json::to_value(&response)
            .ok()
            .and_then(|value| {
                value
                    .get("id")
                    .and_then(|id| id.as_str())
                    .map(str::to_owned)
            })
            .ok_or(AuthError::PasskeyVerificationFailed)?;
        let mut stored = passkeys
            .into_iter()
            .find(|passkey| passkey.credential_id == id)
            .ok_or(AuthError::PasskeyVerificationFailed)?;
        if prior_user_id.is_some_and(|user_id| user_id != stored.user_id) {
            return Err(AuthError::InvalidSession);
        }
        let mut passkey: Passkey = serde_json::from_value(stored.credential.clone())
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        passkey.update_credential(&result);
        stored.credential =
            serde_json::to_value(passkey).map_err(|error| AuthError::Storage(error.to_string()))?;
        stored.updated_at = Utc::now();
        self.store.update_passkey(stored.clone()).await?;
        let user = self
            .store
            .find_user_by_id(stored.user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        let assurance = if prior_user_id.is_some() {
            Assurance::PasswordAndPasskey
        } else {
            Assurance::Passkey
        };
        self.create_session(user, assurance, None, None, ip_address, user_agent)
            .await
    }

    fn webauthn(&self) -> Result<Webauthn, AuthError> {
        let config = self
            .config
            .passkeys
            .as_ref()
            .ok_or(AuthError::PasskeyDisabled)?;
        let origin = Url::parse(&config.rp_origin)
            .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))?;
        WebauthnBuilder::new(&config.rp_id, &origin)
            .and_then(|builder| builder.rp_name(&config.rp_name).build())
            .map_err(|_| AuthError::InvalidConfiguration("invalid passkey relying party".into()))
    }

    fn require_recent_strong_account(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        require_account_session(session)?;
        if !session.session.assurance.is_strong()
            || session.session.created_at + self.config.step_up_ttl <= Utc::now()
        {
            return Err(AuthError::StepUpRequired);
        }
        Ok(())
    }

    async fn store_passkey_ceremony(
        &self,
        purpose: &str,
        token: &str,
        ceremony: PasskeyCeremony,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        self.store.delete_expired_verifications(now).await?;
        self.store
            .create_verification(VerificationValue {
                purpose: purpose.into(),
                identifier: token.into(),
                payload: serde_json::to_value(ceremony)
                    .map_err(|error| AuthError::Storage(error.to_string()))?,
                expires_at: now + Duration::minutes(5),
                created_at: now,
            })
            .await
    }

    async fn consume_passkey_ceremony(
        &self,
        purpose: &str,
        token: &str,
    ) -> Result<PasskeyCeremony, AuthError> {
        let value = self
            .store
            .consume_verification(purpose, token, Utc::now())
            .await?
            .ok_or(AuthError::PasskeyChallengeExpired)?;
        serde_json::from_value(value.payload).map_err(|_| AuthError::PasskeyChallengeExpired)
    }
}

fn require_account_session(session: &SessionWithUser) -> Result<(), AuthError> {
    if session.user.is_anonymous || session.session.actor_user_id.is_some() {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn deserialize_passkeys(stored: &[StoredPasskey]) -> Result<Vec<Passkey>, AuthError> {
    stored
        .iter()
        .map(|passkey| {
            serde_json::from_value(passkey.credential.clone())
                .map_err(|error| AuthError::Storage(error.to_string()))
        })
        .collect()
}

fn credential_id(passkey: &Passkey) -> Result<String, AuthError> {
    serde_json::to_value(passkey.cred_id())
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| AuthError::Storage("passkey credential ID was not serializable".into()))
}

#[cfg(test)]
#[path = "passkey_tests.rs"]
mod tests;
