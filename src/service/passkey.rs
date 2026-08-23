use super::{AuthService, SignInResult, random_token};
use crate::{
    AuthError, AuthenticationMethod, PasskeyAuthenticationVerified, PasskeyConfig,
    PasskeyDeleteOutcome, SessionWithUser, StoredPasskey,
};
use chrono::Utc;
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};
use webauthn_rs_core::proto::{
    AuthenticationResult, Credential, RequestAuthenticationExtensions, UserVerificationPolicy,
};

mod ceremony;
mod metadata;
mod registration;
mod webauthn;

use ceremony::{AUTHENTICATION_PURPOSE, PasskeyCeremony, REGISTRATION_PURPOSE};
use metadata::registration_metadata;
pub use registration::{
    PasskeyRegistrationRequest, PasskeyRegistrationResult, PasskeyRegistrationVerification,
};

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
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(AuthError::InvalidRequest(
                "passkey name must not be empty".into(),
            ));
        }
        let passkey = self
            .store
            .find_passkey_by_id(passkey_id)
            .await?
            .ok_or(AuthError::PasskeyNotFound)?;
        if passkey.user_id != actor.user.id {
            return Err(AuthError::PasskeyRegistrationForbidden);
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
        .await;
        Ok(passkey)
    }

    pub async fn delete_passkey(
        &self,
        actor: &SessionWithUser,
        passkey_id: Uuid,
    ) -> Result<(), AuthError> {
        require_account_session(actor)?;
        let passkey = self
            .store
            .find_passkey_by_id(passkey_id)
            .await?
            .ok_or(AuthError::PasskeyNotFound)?;
        if passkey.user_id != actor.user.id {
            return Err(AuthError::Unauthorized);
        }
        let remaining = match self
            .store
            .delete_passkey(actor.user.id, passkey_id, 0)
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
        .await;
        Ok(())
    }

    pub async fn start_passkey_authentication(
        &self,
        config: &PasskeyConfig,
        current_session: Option<&SessionWithUser>,
    ) -> Result<(String, RequestChallengeResponse), AuthError> {
        let stored = match current_session {
            Some(session) => self.store.list_passkeys(session.user.id).await?,
            None => Vec::new(),
        };
        let extensions = authentication_extensions(config).await?;
        let builder = webauthn::challenge(self, config)?
            .new_challenge_authenticate_builder(
                deserialize_credentials(&stored)?,
                Some(UserVerificationPolicy::Preferred),
            )
            .map(|builder| builder.extensions(extensions))
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let (options, state) = webauthn::challenge(self, config)?
            .generate_challenge_authenticate(builder)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let token = random_token();
        self.store_passkey_ceremony(
            AUTHENTICATION_PURPOSE,
            &token,
            PasskeyCeremony::Authentication {
                passkeys: stored,
                state,
            },
        )
        .await?;
        Ok((token, options))
    }

    pub async fn finish_passkey_authentication(
        &self,
        config: &PasskeyConfig,
        request_origin: Option<&str>,
        token: &str,
        response: PublicKeyCredential,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        let PasskeyCeremony::Authentication {
            passkeys,
            mut state,
        } = self
            .consume_passkey_ceremony(AUTHENTICATION_PURPOSE, token)
            .await?
        else {
            return Err(AuthError::PasskeyChallengeExpired);
        };
        let id = credential_response_id(&response)?;
        let mut stored = match passkeys
            .into_iter()
            .find(|passkey| passkey.credential_id == id)
        {
            Some(passkey) => passkey,
            None => self
                .store
                .find_passkey_by_credential_id(&id)
                .await?
                .ok_or(AuthError::PasskeyAuthenticationNotFound)?,
        };
        let credential = deserialize_credential(&stored)?;
        state.set_allowed_credentials(vec![credential.clone()]);
        let result = webauthn::verification(self, config, request_origin)?
            .authenticate_credential(&response, &state)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        self.run_authentication_callback(config, &stored, &response, &result)
            .await?;
        stored = self
            .persist_authentication_result(stored, credential, &result)
            .await?;
        let user = self
            .store
            .find_user_by_id(stored.user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        self.create_session(
            user,
            AuthenticationMethod::Passkey,
            None,
            ip_address,
            user_agent,
        )
        .await
    }

    async fn run_authentication_callback(
        &self,
        config: &PasskeyConfig,
        stored: &StoredPasskey,
        response: &PublicKeyCredential,
        result: &AuthenticationResult,
    ) -> Result<(), AuthError> {
        let Some(callback) = &config.authentication.after_verification else {
            return Ok(());
        };
        callback
            .after_verification(PasskeyAuthenticationVerified {
                passkey_id: stored.id,
                user_id: stored.user_id,
                response: serde_json::to_value(response)
                    .map_err(|error| AuthError::Storage(error.to_string()))?,
                counter: result.counter(),
                backed_up: result.backup_state(),
            })
            .await
    }

    async fn persist_authentication_result(
        &self,
        mut stored: StoredPasskey,
        mut credential: Credential,
        result: &AuthenticationResult,
    ) -> Result<StoredPasskey, AuthError> {
        let expected_counter = stored.counter;
        credential.counter = credential.counter.max(result.counter());
        credential.backup_state = result.backup_state();
        credential.backup_eligible |= result.backup_eligible();
        stored.counter = result.counter();
        stored.backed_up = result.backup_state();
        stored.device_type = if result.backup_eligible() {
            "multiDevice".into()
        } else {
            "singleDevice".into()
        };
        stored.credential = serde_json::to_value(credential)
            .map_err(|error| AuthError::Storage(error.to_string()))?;
        stored.updated_at = Utc::now();
        if !self
            .store
            .update_passkey_after_authentication(stored.clone(), expected_counter)
            .await?
        {
            return Err(AuthError::PasskeyVerificationFailed);
        }
        Ok(stored)
    }
}

fn require_account_session(session: &SessionWithUser) -> Result<(), AuthError> {
    if session.user.is_anonymous || session.session.actor_user_id.is_some() {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn deserialize_credentials(stored: &[StoredPasskey]) -> Result<Vec<Credential>, AuthError> {
    stored.iter().map(deserialize_credential).collect()
}

fn deserialize_credential(stored: &StoredPasskey) -> Result<Credential, AuthError> {
    let value = if stored.credential.get("cred_id").is_some() {
        stored.credential.clone()
    } else {
        stored
            .credential
            .get("cred")
            .cloned()
            .unwrap_or_else(|| stored.credential.clone())
    };
    serde_json::from_value(value).map_err(|error| AuthError::Storage(error.to_string()))
}

fn credential_response_id(response: &PublicKeyCredential) -> Result<String, AuthError> {
    serde_json::to_value(response)
        .ok()
        .and_then(|value| {
            value
                .get("id")
                .and_then(|id| id.as_str())
                .map(str::to_owned)
        })
        .ok_or(AuthError::PasskeyVerificationFailed)
}

async fn authentication_extensions(
    config: &PasskeyConfig,
) -> Result<Option<RequestAuthenticationExtensions>, AuthError> {
    let value = match &config.authentication.extensions {
        Some(extensions) => extensions.resolve(None).await?,
        None => None,
    };
    value.map(serde_json::from_value).transpose().map_err(|_| {
        AuthError::InvalidConfiguration("invalid passkey authentication extensions".into())
    })
}

#[cfg(test)]
#[path = "passkey_tests.rs"]
mod tests;
