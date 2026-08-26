use super::{PasskeyCeremony, deserialize_credentials, metadata, registration_metadata, webauthn};
use crate::service::{AuthService, SignInResult, random_token};
use crate::{
    AuthError, AuthenticationMethod, PasskeyConfig, PasskeyRegistrationUser,
    PasskeyRegistrationVerified, SessionWithUser, StoredPasskey,
};
use chrono::{Duration, Utc};
use uuid::Uuid;
use webauthn_rs::prelude::{
    AuthenticatorAttachment, CreationChallengeResponse, RegisterPublicKeyCredential,
};
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, COSEAlgorithm, Credential, RequestRegistrationExtensions,
    UserVerificationPolicy,
};

#[derive(Debug, Clone)]
pub struct PasskeyRegistrationResult {
    pub passkey: StoredPasskey,
    pub replacement_session: Option<SignInResult>,
}

pub struct PasskeyRegistrationRequest {
    pub name: Option<String>,
    pub context: Option<String>,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
}

pub struct PasskeyRegistrationVerification {
    pub request_origin: Option<String>,
    pub token: String,
    pub response: RegisterPublicKeyCredential,
    pub name: Option<String>,
    pub create_session: bool,
}

struct CallbackInput<'a> {
    actor: Option<&'a SessionWithUser>,
    user: PasskeyRegistrationUser,
    context: Option<String>,
    response: &'a RegisterPublicKeyCredential,
    metadata: &'a metadata::RegistrationMetadata,
    client_name: Option<String>,
}

impl AuthService {
    pub async fn start_passkey_registration(
        &self,
        config: &PasskeyConfig,
        actor: Option<&SessionWithUser>,
        request: PasskeyRegistrationRequest,
    ) -> Result<(String, CreationChallengeResponse), AuthError> {
        let user = self
            .resolve_passkey_registration_user(config, actor, request.context.as_deref())
            .await?;
        let webauthn = webauthn::challenge(self, config)?;
        let credentials = deserialize_credentials(&self.store.list_passkeys(user.id).await?)?;
        let exclude = (!credentials.is_empty()).then(|| {
            credentials
                .iter()
                .map(|credential| credential.cred_id.clone())
                .collect()
        });
        let selection = &config.authenticator_selection;
        let extensions = registration_extensions(config, request.context.as_deref()).await?;
        let builder = webauthn
            .new_challenge_register_builder(
                &webauthn::random_user_handle(),
                request.name.as_deref().unwrap_or(&user.name),
                user.display_name.as_deref().unwrap_or(&user.name),
            )
            .map(|builder| {
                builder
                    .attestation(AttestationConveyancePreference::None)
                    .credential_algorithms(COSEAlgorithm::secure_algs())
                    .require_resident_key(selection.require_resident_key.unwrap_or(false))
                    .authenticator_attachment(
                        request
                            .authenticator_attachment
                            .or(selection.authenticator_attachment),
                    )
                    .user_verification_policy(
                        selection
                            .user_verification
                            .unwrap_or(UserVerificationPolicy::Preferred),
                    )
                    .reject_synchronised_authenticators(false)
                    .exclude_credentials(exclude)
                    .extensions(extensions)
            })
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        let (mut options, state) = webauthn
            .generate_challenge_register(builder)
            .map_err(|_| AuthError::PasskeyVerificationFailed)?;
        if let Some(options_selection) = &mut options.public_key.authenticator_selection {
            options_selection.resident_key = selection.resident_key.or(Some(
                webauthn_rs_core::proto::ResidentKeyRequirement::Preferred,
            ));
        }
        let token = random_token();
        self.store_passkey_ceremony(
            &token,
            PasskeyCeremony::Registration {
                user_id: user.id,
                user_name: user.name,
                user_display_name: user.display_name,
                state,
                context: request.context,
            },
        )
        .await?;
        Ok((token, options))
    }

    pub async fn finish_passkey_registration(
        &self,
        config: &PasskeyConfig,
        actor: Option<&SessionWithUser>,
        verification: PasskeyRegistrationVerification,
    ) -> Result<PasskeyRegistrationResult, AuthError> {
        self.validate_passkey_registration_freshness(config, actor)?;
        let PasskeyCeremony::Registration {
            user_id,
            user_name,
            user_display_name,
            state,
            context,
        } = self.consume_passkey_ceremony(&verification.token).await?
        else {
            return Err(AuthError::PasskeyChallengeExpired);
        };
        self.validate_passkey_registration_owner(actor, user_id)?;
        let metadata = registration_metadata(&verification.response)
            .map_err(|_| AuthError::PasskeyRegistrationFailed)?;
        let credential =
            webauthn::verification(self, config, verification.request_origin.as_deref())?
                .register_credential(&verification.response, &state, None)
                .map_err(|_| AuthError::PasskeyRegistrationFailed)?;
        let (user_id, name) = self
            .apply_registration_callback(
                config,
                CallbackInput {
                    actor,
                    user: PasskeyRegistrationUser {
                        id: user_id,
                        name: user_name,
                        display_name: user_display_name,
                    },
                    context,
                    response: &verification.response,
                    metadata: &metadata,
                    client_name: verification.name,
                },
            )
            .await?;
        let stored = self
            .persist_passkey_registration(user_id, name, credential, metadata)
            .await?;
        let replacement_session = self
            .create_passkey_registration_session(verification.create_session, actor, user_id)
            .await?;
        self.activity(crate::AuthActivity::PasskeyEnrolled {
            actor_user_id: actor.map(|actor| actor.user.id),
            user_id,
            passkey_id: stored.id,
        })
        .await;
        Ok(PasskeyRegistrationResult {
            passkey: stored,
            replacement_session,
        })
    }

    async fn persist_passkey_registration(
        &self,
        user_id: Uuid,
        name: Option<String>,
        credential: Credential,
        metadata: metadata::RegistrationMetadata,
    ) -> Result<StoredPasskey, AuthError> {
        let now = Utc::now();
        self.store
            .save_passkey(StoredPasskey {
                id: Uuid::new_v4(),
                user_id,
                name,
                credential_id: credential_id(&credential)?,
                public_key: metadata.public_key,
                counter: metadata.counter,
                device_type: metadata.device_type,
                backed_up: metadata.backed_up,
                transports: metadata.transports,
                aaguid: metadata.aaguid,
                created_at: now,
            })
            .await
    }

    async fn create_passkey_registration_session(
        &self,
        create_session: bool,
        actor: Option<&SessionWithUser>,
        user_id: Uuid,
    ) -> Result<Option<SignInResult>, AuthError> {
        if !create_session {
            return Ok(None);
        }
        let user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .ok_or(AuthError::PasskeyResolvedUserInvalid)?;
        self.create_session(
            user,
            AuthenticationMethod::Passkey,
            None,
            actor.and_then(|actor| actor.session.ip_address.clone()),
            actor.and_then(|actor| actor.session.user_agent.clone()),
        )
        .await
        .map(Some)
    }

    async fn resolve_passkey_registration_user(
        &self,
        config: &PasskeyConfig,
        actor: Option<&SessionWithUser>,
        context: Option<&str>,
    ) -> Result<PasskeyRegistrationUser, AuthError> {
        if config.registration.require_session {
            let actor = actor.ok_or(AuthError::PasskeySessionRequired)?;
            self.require_fresh_account_session(actor)?;
            return Ok(session_registration_user(actor));
        }
        if let Some(actor) = actor {
            require_account_session(actor)?;
            return Ok(session_registration_user(actor));
        }
        let resolver = config
            .registration
            .resolve_user
            .as_ref()
            .ok_or(AuthError::PasskeyResolverRequired)?;
        let user = resolver.resolve(context).await?;
        if user.name.is_empty() {
            return Err(AuthError::PasskeyResolvedUserInvalid);
        }
        Ok(user)
    }

    async fn apply_registration_callback(
        &self,
        config: &PasskeyConfig,
        input: CallbackInput<'_>,
    ) -> Result<(Uuid, Option<String>), AuthError> {
        let mut user_id = input.user.id;
        let mut name = normalized_name(input.client_name);
        if let Some(callback) = &config.registration.after_verification {
            let result = callback
                .after_verification(PasskeyRegistrationVerified {
                    user: input.user,
                    context: input.context,
                    response: serde_json::to_value(input.response)
                        .map_err(|error| AuthError::Storage(error.to_string()))?,
                    public_key: input.metadata.public_key.clone(),
                    counter: input.metadata.counter,
                    device_type: input.metadata.device_type.clone(),
                    backed_up: input.metadata.backed_up,
                    transports: input.metadata.transports.clone(),
                    aaguid: input.metadata.aaguid.clone(),
                })
                .await?;
            if let Some(resolved_user_id) = result.user_id {
                if input
                    .actor
                    .is_some_and(|actor| actor.user.id != resolved_user_id)
                {
                    return Err(AuthError::PasskeyRegistrationForbidden);
                }
                user_id = resolved_user_id;
            }
            if name.is_none() {
                name = normalized_name(result.name);
            }
        }
        Ok((user_id, name))
    }

    fn validate_passkey_registration_freshness(
        &self,
        config: &PasskeyConfig,
        actor: Option<&SessionWithUser>,
    ) -> Result<(), AuthError> {
        if config.registration.require_session {
            self.require_fresh_account_session(actor.ok_or(AuthError::PasskeySessionRequired)?)?;
        }
        Ok(())
    }

    fn validate_passkey_registration_owner(
        &self,
        actor: Option<&SessionWithUser>,
        user_id: Uuid,
    ) -> Result<(), AuthError> {
        if actor.is_some_and(|actor| {
            actor.user.id != user_id
                || actor.user.is_anonymous
                || actor.session.actor_user_id.is_some()
        }) {
            return Err(AuthError::PasskeyRegistrationForbidden);
        }
        Ok(())
    }

    fn require_fresh_account_session(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        require_account_session(session)?;
        if self.config.session_fresh_age != Duration::zero()
            && session.session.created_at + self.config.session_fresh_age <= Utc::now()
        {
            return Err(AuthError::SessionNotFresh);
        }
        Ok(())
    }
}

fn session_registration_user(actor: &SessionWithUser) -> PasskeyRegistrationUser {
    PasskeyRegistrationUser {
        id: actor.user.id,
        name: actor.user.email.clone(),
        display_name: Some(actor.user.email.clone()),
    }
}

fn require_account_session(session: &SessionWithUser) -> Result<(), AuthError> {
    if session.user.is_anonymous || session.session.actor_user_id.is_some() {
        return Err(AuthError::Forbidden);
    }
    Ok(())
}

fn credential_id(credential: &Credential) -> Result<String, AuthError> {
    serde_json::to_value(&credential.cred_id)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| AuthError::Storage("passkey credential ID was not serializable".into()))
}

fn normalized_name(name: Option<String>) -> Option<String> {
    name.map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

async fn registration_extensions(
    config: &PasskeyConfig,
    context: Option<&str>,
) -> Result<Option<RequestRegistrationExtensions>, AuthError> {
    let value = match &config.registration.extensions {
        Some(extensions) => extensions.resolve(context).await?,
        None => None,
    };
    value.map(serde_json::from_value).transpose().map_err(|_| {
        AuthError::InvalidConfiguration("invalid passkey registration extensions".into())
    })
}
