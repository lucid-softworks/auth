use super::AuthService;
use crate::{
    AuthError, AuthenticationMethod, SiweCacao, SiweError, SiweVerificationRequest,
    SiweVerificationResult, VerificationValue,
    siwe::message::{
        SiweTimeGate, is_valid_siwe_nonce, normalize_siwe_domain, parse_siwe_message,
        siwe_time_gate, to_checksum_address,
    },
};
use chrono::{Duration, Utc};

const VERIFICATION_PURPOSE: &str = "";
const NONCE_IDENTIFIER_PREFIX: &str = "siwe:";

impl AuthService {
    pub async fn create_siwe_nonce(&self) -> Result<String, AuthError> {
        let nonce = self
            .siwe_plugin()?
            .config
            .get_nonce
            .generate()
            .await
            .map_err(|error| SiweError::NonceCallback(error.to_string()))?;
        if !is_valid_siwe_nonce(&nonce) {
            return Err(SiweError::InvalidGeneratedNonce.into());
        }
        let now = Utc::now();
        let identifier = format!("{NONCE_IDENTIFIER_PREFIX}{nonce}");
        self.replace_verification_with_create_hooks(VerificationValue {
            purpose: VERIFICATION_PURPOSE.into(),
            identifier,
            payload: serde_json::json!(nonce),
            additional_fields: serde_json::Map::new(),
            expires_at: now + Duration::seconds(900),
            created_at: now,
        })
        .await?;
        Ok(nonce)
    }

    pub async fn verify_siwe_message(
        &self,
        message: String,
        signature: String,
        email: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        request_base_origin: Option<String>,
    ) -> Result<SiweVerificationResult, AuthError> {
        let plugin = self.siwe_plugin()?;
        if !plugin.config.anonymous && email.is_none() {
            return Err(SiweError::EmailRequired.into());
        }
        let (address, chain_id) = self.verify_siwe_request(message, signature).await?;
        let user = self
            .resolve_siwe_user(
                &address,
                chain_id,
                email.as_deref(),
                request_base_origin.as_deref(),
            )
            .await
            .map_err(|error| match error {
                AuthError::Siwe(_) => error,
                _ => AuthError::Siwe(SiweError::Unexpected(error.to_string())),
            })?;
        let session = self
            .create_session(
                user.clone(),
                AuthenticationMethod::Extension,
                None,
                ip_address,
                user_agent,
            )
            .await
            .map_err(|error| AuthError::Siwe(SiweError::Unexpected(error.to_string())))?;
        Ok(SiweVerificationResult {
            token: session.token,
            user_id: user.id,
            wallet_address: address,
            chain_id,
        })
    }

    async fn verify_siwe_request(
        &self,
        message: String,
        signature: String,
    ) -> Result<(String, f64), AuthError> {
        let plugin = self.siwe_plugin()?;
        let parsed = parse_siwe_message(&message);
        let nonce = parsed
            .nonce
            .as_deref()
            .filter(|nonce| is_valid_siwe_nonce(nonce))
            .ok_or(SiweError::MessageMismatch)?
            .to_owned();
        if self
            .consume_verification_value(
                VERIFICATION_PURPOSE,
                &format!("{NONCE_IDENTIFIER_PREFIX}{nonce}"),
                Utc::now(),
            )
            .await
            .map_err(|error| AuthError::Siwe(SiweError::Unexpected(error.to_string())))?
            .is_none()
        {
            return Err(SiweError::InvalidOrExpiredNonce.into());
        }
        let address = parsed
            .address
            .as_deref()
            .and_then(to_checksum_address)
            .ok_or(SiweError::MessageMismatch)?;
        let chain_id = parsed
            .chain_id
            .filter(|chain_id| *chain_id > 0.0)
            .ok_or(SiweError::MessageMismatch)?;
        let domain_matches = parsed.domain.as_deref().is_some_and(|domain| {
            normalize_siwe_domain(domain) == normalize_siwe_domain(&plugin.config.domain)
        });
        if !domain_matches {
            return Err(SiweError::MessageMismatch.into());
        }
        match siwe_time_gate(&parsed, Utc::now().timestamp_millis()) {
            SiweTimeGate::Expired => return Err(SiweError::MessageExpired.into()),
            SiweTimeGate::NotYetValid => return Err(SiweError::MessageNotYetValid.into()),
            SiweTimeGate::Valid => {}
        }
        let verified = plugin
            .config
            .verify_message
            .verify(SiweVerificationRequest {
                message,
                signature: signature.clone(),
                address: address.clone(),
                chain_id,
                cacao: SiweCacao {
                    header_type: "caip122".into(),
                    domain: plugin.config.domain.clone(),
                    audience: plugin.config.domain.clone(),
                    nonce,
                    issuer: plugin.config.domain.clone(),
                    version: "1".into(),
                    signature_type: "eip191".into(),
                    signature,
                },
            })
            .await
            .map_err(|error| AuthError::Siwe(SiweError::Unexpected(error.to_string())))?;
        if !verified {
            return Err(SiweError::InvalidSignature.into());
        }
        Ok((address, chain_id))
    }
}
