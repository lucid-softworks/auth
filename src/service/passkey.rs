use super::{AuthService, SignInResult, random_token};
use crate::{Assurance, AuthError, AuthUser, SessionWithUser, StoredPasskey};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Webauthn,
    WebauthnBuilder,
};

#[derive(Debug, Clone)]
pub(super) enum PasskeyCeremony {
    Registration {
        user_id: Uuid,
        state: PasskeyRegistration,
        expires_at: DateTime<Utc>,
    },
    Authentication {
        passkeys: Vec<StoredPasskey>,
        state: PasskeyAuthentication,
        prior_user_id: Option<Uuid>,
        expires_at: DateTime<Utc>,
    },
}

impl AuthService {
    pub async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError> {
        self.store.list_passkeys(user_id).await
    }

    pub async fn start_passkey_registration(
        &self,
        user: &AuthUser,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let webauthn = self.webauthn()?;
        let stored = self.store.list_passkeys(user.id).await?;
        let passkeys = deserialize_passkeys(&stored)?;
        let exclude = (!passkeys.is_empty()).then(|| {
            passkeys
                .iter()
                .map(|passkey| passkey.cred_id().clone())
                .collect()
        });
        let username = user.username.as_deref().unwrap_or(&user.email);
        let (options, state) = webauthn
            .start_passkey_registration(user.id, username, &user.name, exclude)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let token = random_token();
        self.passkey_ceremonies.lock().await.insert(
            token.clone(),
            PasskeyCeremony::Registration {
                user_id: user.id,
                state,
                expires_at: Utc::now() + Duration::minutes(5),
            },
        );
        Ok((token, options))
    }

    pub async fn finish_passkey_registration(
        &self,
        token: &str,
        current_user_id: Uuid,
        response: RegisterPublicKeyCredential,
        name: Option<String>,
    ) -> Result<StoredPasskey, AuthError> {
        let PasskeyCeremony::Registration { user_id, state, .. } =
            self.consume_passkey_ceremony(token).await?
        else {
            return Err(AuthError::PasskeyChallengeExpired);
        };
        if user_id != current_user_id {
            return Err(AuthError::InvalidSession);
        }
        let passkey = self
            .webauthn()?
            .finish_passkey_registration(&response, &state)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let now = Utc::now();
        self.store
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
            .await
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
        self.passkey_ceremonies.lock().await.insert(
            token.clone(),
            PasskeyCeremony::Authentication {
                passkeys: stored,
                state,
                prior_user_id: current_session.map(|session| session.user.id),
                expires_at: Utc::now() + Duration::minutes(5),
            },
        );
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
        } = self.consume_passkey_ceremony(token).await?
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

    async fn consume_passkey_ceremony(&self, token: &str) -> Result<PasskeyCeremony, AuthError> {
        let now = Utc::now();
        let mut ceremonies = self.passkey_ceremonies.lock().await;
        ceremonies.retain(|_, ceremony| match ceremony {
            PasskeyCeremony::Registration { expires_at, .. }
            | PasskeyCeremony::Authentication { expires_at, .. } => *expires_at > now,
        });
        ceremonies
            .remove(token)
            .ok_or(AuthError::PasskeyChallengeExpired)
    }
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
