use super::AuthService;
use crate::{AuthError, StoredPasskey, VerificationValue};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs_core::proto::{AuthenticationState, RegistrationState};

pub(super) const REGISTRATION_PURPOSE: &str = "passkey-registration";
pub(super) const AUTHENTICATION_PURPOSE: &str = "passkey-authentication";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) enum PasskeyCeremony {
    Registration {
        user_id: Uuid,
        user_name: String,
        user_display_name: Option<String>,
        state: RegistrationState,
        context: Option<String>,
    },
    Authentication {
        passkeys: Vec<StoredPasskey>,
        state: AuthenticationState,
    },
}

impl AuthService {
    pub(super) async fn store_passkey_ceremony(
        &self,
        purpose: &str,
        token: &str,
        ceremony: PasskeyCeremony,
    ) -> Result<(), AuthError> {
        let now = Utc::now();
        self.store.delete_expired_verifications(now).await?;
        self.create_verification_record(VerificationValue {
            purpose: purpose.into(),
            identifier: token.into(),
            payload: serde_json::to_value(ceremony)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            additional_fields: serde_json::Map::new(),
            expires_at: now + Duration::minutes(5),
            created_at: now,
        })
        .await
    }

    pub(super) async fn consume_passkey_ceremony(
        &self,
        purpose: &str,
        token: &str,
    ) -> Result<PasskeyCeremony, AuthError> {
        let value = self
            .consume_verification_record(purpose, token, Utc::now())
            .await?
            .ok_or(AuthError::PasskeyChallengeExpired)?;
        serde_json::from_value(value.payload).map_err(|_| AuthError::PasskeyChallengeExpired)
    }
}
