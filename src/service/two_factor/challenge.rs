use super::{
    AuthService, ChallengePayload, SignInResult, TwoFactorError, TwoFactorSignInOutcome,
    TwoFactorVerification, VerificationContext,
};
use crate::{AuthError, VerificationValue};
use chrono::Utc;
use serde_json::json;

const CHALLENGE_PURPOSE: &str = "two-factor-challenge";
const ATTEMPTS_PURPOSE: &str = "two-factor-attempts";
const TRUST_PURPOSE: &str = "two-factor-trust-device";

impl AuthService {
    pub(crate) async fn begin_two_factor_sign_in(
        &self,
        result: SignInResult,
        remember_me: Option<bool>,
        trust_cookie: Option<&str>,
    ) -> Result<TwoFactorSignInOutcome, AuthError> {
        let Some(plugin) = self.plugins.find::<crate::TwoFactorPlugin>() else {
            return Ok(continue_sign_in(result, None));
        };
        let Some(record) = plugin
            .store
            .find_two_factor(result.session.user.id)
            .await?
            .filter(|record| record.enabled)
        else {
            return Ok(continue_sign_in(result, None));
        };
        if self
            .validate_trust_device(result.session.user.id, trust_cookie)
            .await?
        {
            let rotated = self.create_trust_device(result.session.user.id).await?;
            return Ok(continue_sign_in(result, Some(rotated)));
        }
        let identifier = self
            .create_two_factor_challenge(&result, remember_me, plugin.config.challenge_ttl)
            .await?;
        Ok(TwoFactorSignInOutcome::Challenge {
            identifier,
            methods: available_methods(plugin, &record),
            max_age_seconds: plugin.config.challenge_ttl.num_seconds(),
        })
    }

    async fn create_two_factor_challenge(
        &self,
        result: &SignInResult,
        remember_me: Option<bool>,
        ttl: chrono::Duration,
    ) -> Result<String, AuthError> {
        let identifier = super::super::random_token();
        let now = Utc::now();
        let expires_at = now + ttl;
        let payload = ChallengePayload {
            user_id: result.session.user.id,
            session_expires_at: result.session.session.expires_at,
            remember_me,
            ip_address: result.session.session.ip_address.clone(),
            user_agent: result.session.session.user_agent.clone(),
        };
        self.create_verification_record(VerificationValue {
            purpose: CHALLENGE_PURPOSE.into(),
            identifier: identifier.clone(),
            payload: serde_json::to_value(payload)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            additional_fields: serde_json::Map::new(),
            expires_at,
            created_at: now,
        })
        .await?;
        self.create_verification_record(VerificationValue {
            purpose: ATTEMPTS_PURPOSE.into(),
            identifier: identifier.clone(),
            payload: json!({ "attempts": 0 }),
            additional_fields: serde_json::Map::new(),
            expires_at,
            created_at: now,
        })
        .await?;
        if let Err(error) = self.sign_out(&result.token).await {
            let _ = self
                .consume_verification_record(CHALLENGE_PURPOSE, &identifier, Utc::now())
                .await;
            let _ = self
                .consume_verification_record(ATTEMPTS_PURPOSE, &identifier, Utc::now())
                .await;
            return Err(error);
        }
        Ok(identifier)
    }

    pub(super) async fn verification_context(
        &self,
        active: Option<(crate::SessionWithUser, String)>,
        challenge_identifier: Option<String>,
    ) -> Result<VerificationContext, AuthError> {
        if let Some((session, token)) = active {
            return Ok(VerificationContext {
                user: session.user.clone(),
                active: Some((session, token)),
                challenge: None,
            });
        }
        let identifier = challenge_identifier.ok_or(TwoFactorError::InvalidCookie)?;
        let value = self
            .find_verification_value(CHALLENGE_PURPOSE, &identifier)
            .await?
            .filter(|value| value.expires_at > Utc::now())
            .ok_or(TwoFactorError::InvalidCookie)?;
        let payload: ChallengePayload =
            serde_json::from_value(value.payload).map_err(|_| TwoFactorError::InvalidCookie)?;
        let user = self
            .store
            .find_user_by_id(payload.user_id)
            .await?
            .ok_or(TwoFactorError::InvalidCookie)?;
        Ok(VerificationContext {
            user,
            active: None,
            challenge: Some((identifier, payload)),
        })
    }

    pub(super) async fn complete_two_factor(
        &self,
        context: VerificationContext,
        trust_device: bool,
    ) -> Result<TwoFactorVerification, AuthError> {
        self.reset_two_factor_failures(context.user.id).await?;
        let (result, remember_me) = match context.challenge {
            Some((identifier, payload)) => {
                let consumed = self
                    .consume_verification_record(CHALLENGE_PURPOSE, &identifier, Utc::now())
                    .await?
                    .ok_or(TwoFactorError::InvalidCookie)?;
                let consumed_payload: ChallengePayload =
                    serde_json::from_value(consumed.payload)
                        .map_err(|_| TwoFactorError::InvalidCookie)?;
                if consumed_payload.user_id != context.user.id {
                    return Err(TwoFactorError::InvalidCookie.into());
                }
                let _ = self
                    .consume_verification_record(ATTEMPTS_PURPOSE, &identifier, Utc::now())
                    .await;
                let result = if payload.remember_me == Some(false) {
                    self.create_session_expiring_at(
                        context.user.clone(),
                        crate::AuthenticationMethod::TwoFactor,
                        None,
                        payload.session_expires_at,
                        payload.ip_address,
                        payload.user_agent,
                    )
                    .await?
                } else {
                    self.create_session_until(
                        context.user.clone(),
                        crate::AuthenticationMethod::TwoFactor,
                        None,
                        Some(payload.session_expires_at),
                        payload.ip_address,
                        payload.user_agent,
                    )
                    .await?
                };
                (result, payload.remember_me)
            }
            None => {
                let (session, token) = context.active.ok_or(TwoFactorError::InvalidCookie)?;
                (SignInResult { token, session }, Some(true))
            }
        };
        let trust_cookie = if trust_device {
            Some(self.create_trust_device(context.user.id).await?)
        } else {
            None
        };
        Ok(TwoFactorVerification {
            result,
            remember_me,
            trust_cookie,
        })
    }

    pub(super) async fn rotate_active_session(
        &self,
        session: &crate::SessionWithUser,
        token: &str,
    ) -> Result<SignInResult, AuthError> {
        let replacement = self
            .create_session_until(
                session.user.clone(),
                session.session.authentication_method,
                session.session.actor_user_id,
                Some(session.session.expires_at),
                session.session.ip_address.clone(),
                session.session.user_agent.clone(),
            )
            .await?;
        self.sign_out(token).await?;
        Ok(replacement)
    }

    pub(super) async fn check_challenge_attempts(
        &self,
        context: &VerificationContext,
        allowed: u32,
    ) -> Result<(), AuthError> {
        let Some((identifier, _)) = &context.challenge else {
            return Ok(());
        };
        let attempts = self
            .find_verification_value(ATTEMPTS_PURPOSE, identifier)
            .await?
            .and_then(|value| value.payload["attempts"].as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(TwoFactorError::InvalidCookie)?;
        if attempts >= allowed {
            let _ = self
                .consume_verification_record(CHALLENGE_PURPOSE, identifier, Utc::now())
                .await;
            let _ = self
                .consume_verification_record(ATTEMPTS_PURPOSE, identifier, Utc::now())
                .await;
            return Err(TwoFactorError::TooManyAttempts.into());
        }
        Ok(())
    }

    pub(super) async fn record_challenge_failure(
        &self,
        context: &VerificationContext,
    ) -> Result<(), AuthError> {
        let Some((identifier, payload)) = &context.challenge else {
            return Ok(());
        };
        let value = self
            .consume_verification_record(ATTEMPTS_PURPOSE, identifier, Utc::now())
            .await?
            .ok_or(TwoFactorError::InvalidCookie)?;
        let attempts = value.payload["attempts"].as_u64().unwrap_or(5) + 1;
        self.create_verification_record(VerificationValue {
            purpose: ATTEMPTS_PURPOSE.into(),
            identifier: identifier.clone(),
            payload: json!({ "attempts": attempts }),
            additional_fields: serde_json::Map::new(),
            expires_at: value.expires_at,
            created_at: value.created_at,
        })
        .await?;
        self.record_two_factor_failure(payload.user_id).await
    }

    async fn validate_trust_device(
        &self,
        user_id: uuid::Uuid,
        cookie: Option<&str>,
    ) -> Result<bool, AuthError> {
        let Some((token, identifier)) = cookie.and_then(|value| value.split_once('!')) else {
            return Ok(false);
        };
        if token != self.sign(format!("{user_id}!{identifier}").as_bytes()) {
            return Ok(false);
        }
        let Some(value) = self
            .consume_verification_record(TRUST_PURPOSE, identifier, Utc::now())
            .await?
        else {
            return Ok(false);
        };
        Ok(value.payload["userId"].as_str() == Some(&user_id.to_string()))
    }

    pub(super) async fn revoke_trust_device(&self, cookie: Option<&str>) -> Result<(), AuthError> {
        let Some((_, identifier)) = cookie.and_then(|value| value.split_once('!')) else {
            return Ok(());
        };
        let _ = self
            .consume_verification_record(TRUST_PURPOSE, identifier, Utc::now())
            .await?;
        Ok(())
    }

    pub(super) async fn create_trust_device(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<String, AuthError> {
        let plugin = self.two_factor_plugin()?;
        let identifier = format!("trust-device-{}", super::super::random_token());
        let now = Utc::now();
        self.create_verification_record(VerificationValue {
            purpose: TRUST_PURPOSE.into(),
            identifier: identifier.clone(),
            payload: json!({ "userId": user_id }),
            additional_fields: serde_json::Map::new(),
            expires_at: now + plugin.config.trust_device_ttl,
            created_at: now,
        })
        .await?;
        let token = self.sign(format!("{user_id}!{identifier}").as_bytes());
        Ok(format!("{token}!{identifier}"))
    }
}

fn continue_sign_in(
    result: SignInResult,
    rotated_trust_cookie: Option<String>,
) -> TwoFactorSignInOutcome {
    TwoFactorSignInOutcome::Continue {
        result: Box::new(result),
        rotated_trust_cookie,
    }
}

fn available_methods(
    plugin: &crate::TwoFactorPlugin,
    record: &crate::TwoFactorRecord,
) -> Vec<String> {
    let mut methods = Vec::new();
    if !plugin.config.totp.disabled && record.encrypted_secret.is_some() && record.verified {
        methods.push("totp".into());
    }
    if plugin.config.otp.is_some() {
        methods.push("otp".into());
    }
    methods
}
