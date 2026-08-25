mod audience;
mod claims;
mod jwks;
mod replay;
mod signature;
pub(super) mod thumbprint;

use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use serde_json::Value;

pub(crate) use audience::AgentAudience;
pub(crate) use claims::{
    AgentBoundRequest, AgentJwtClaims, AgentJwtHeader, AgentJwtKind, decode_agent_jwt,
};
#[cfg(feature = "axum")]
pub(crate) use replay::SecondaryAgentJwtReplayStore;
pub(crate) use replay::{AgentJwtReplayStore, MemoryAgentJwtReplayStore};
#[cfg(feature = "axum")]
pub(crate) use thumbprint::jwk_thumbprint;

const REPLAY_CLOCK_SKEW: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub(crate) struct AgentJwtKeySource<'a> {
    pub inline_public_jwk: Option<&'a Value>,
    pub jwks_url: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub(crate) struct AgentJwtVerifyOptions<'a> {
    pub kind: AgentJwtKind,
    pub allowed_key_algorithms: &'a [String],
    pub max_age: Duration,
    pub audience: AgentAudience<'a>,
    pub require_audience: bool,
    pub expected_issuer: Option<&'a str>,
    pub request: Option<AgentBoundRequest<'a>>,
    pub replay_partition: Option<&'a str>,
    pub skip_replay_check: bool,
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VerifiedAgentJwt {
    pub header: AgentJwtHeader,
    pub claims: AgentJwtClaims,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AgentJwtError {
    #[error("JWT is malformed")]
    Malformed,
    #[error("JWT has an unexpected typ header")]
    UnexpectedType,
    #[error("JWT is missing required claim `{0}`")]
    MissingClaim(&'static str),
    #[error("JWT claim `{0}` is invalid")]
    InvalidClaim(&'static str),
    #[error("JWT audience is invalid")]
    InvalidAudience,
    #[error("JWT is expired")]
    Expired,
    #[error("JWT is older than the configured maximum age")]
    TooOld,
    #[error("JWT was issued in the future")]
    IssuedInFuture,
    #[error("public key algorithm is not allowed")]
    UnsupportedAlgorithm,
    #[error("public key is invalid")]
    InvalidPublicKey,
    #[error("JWT signature is invalid")]
    InvalidSignature,
    #[error("JWT has already been used")]
    Replay,
    #[error("request binding does not match the JWT")]
    RequestBindingMismatch,
    #[error("JWKS URL is not allowed")]
    UnsafeJwksUrl,
    #[error("JWKS could not be fetched: {0}")]
    JwksFetch(String),
    #[error("JWT replay store failed: {0}")]
    ReplayStore(String),
}

pub(crate) struct AgentJwtVerifier {
    jwks: jwks::AgentJwksCache,
    replay: Arc<dyn AgentJwtReplayStore>,
}

impl AgentJwtVerifier {
    #[cfg(test)]
    pub(crate) fn new(replay: Arc<dyn AgentJwtReplayStore>) -> Result<Self, AgentJwtError> {
        Self::with_jwks_storage(replay, None)
    }

    pub(crate) fn with_jwks_storage(
        replay: Arc<dyn AgentJwtReplayStore>,
        storage: Option<Arc<dyn crate::SecondaryStorage>>,
    ) -> Result<Self, AgentJwtError> {
        Ok(Self {
            jwks: jwks::AgentJwksCache::new(Duration::from_secs(300), storage)?,
            replay,
        })
    }

    pub(crate) async fn verify(
        &self,
        token: &str,
        key_source: AgentJwtKeySource<'_>,
        options: AgentJwtVerifyOptions<'_>,
    ) -> Result<VerifiedAgentJwt, AgentJwtError> {
        let decoded = decode_agent_jwt(token)?;
        claims::validate_unverified(&decoded, &options)?;
        let key = self.resolve_key(&decoded.header, key_source).await?;
        signature::verify(token, &key, options.allowed_key_algorithms)?;
        claims::validate_times(&decoded.claims, options.max_age, options.now)?;
        if let Some(request) = options.request.as_ref() {
            claims::validate_request_binding(&decoded.claims, request)?;
        }
        self.reserve_replay(&decoded.claims, &options).await?;
        Ok(decoded)
    }

    async fn resolve_key(
        &self,
        header: &AgentJwtHeader,
        source: AgentJwtKeySource<'_>,
    ) -> Result<Value, AgentJwtError> {
        if let (Some(url), Some(kid)) = (source.jwks_url, header.kid.as_deref())
            && let Ok(Some(key)) = self.jwks.get_key_by_kid(url, kid).await
        {
            return Ok(key);
        }
        source
            .inline_public_jwk
            .cloned()
            .ok_or(AgentJwtError::InvalidPublicKey)
    }

    async fn reserve_replay(
        &self,
        claims: &AgentJwtClaims,
        options: &AgentJwtVerifyOptions<'_>,
    ) -> Result<(), AgentJwtError> {
        if options.skip_replay_check {
            return Ok(());
        }
        let Some(partition) = options.replay_partition else {
            return Ok(());
        };
        let jti = claims
            .jti
            .as_deref()
            .ok_or(AgentJwtError::MissingClaim("jti"))?;
        let expires_at = options.now
            + chrono::Duration::from_std(options.max_age + REPLAY_CLOCK_SKEW)
                .map_err(|error| AgentJwtError::ReplayStore(error.to_string()))?;
        let reserved = self
            .replay
            .reserve(format!("{partition}:{jti}"), expires_at, options.now)
            .await
            .map_err(AgentJwtError::ReplayStore)?;
        if reserved {
            Ok(())
        } else {
            Err(AgentJwtError::Replay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use josekit::{
        jwk::{Ed25519, Jwk},
        jws::{self, EdDSA, JwsHeader},
    };
    use serde_json::json;

    fn token(key: &Jwk, claims: Value) -> String {
        let mut header = JwsHeader::new();
        header.set_algorithm("EdDSA");
        header.set_token_type("agent+jwt");
        jws::serialize_compact(
            &serde_json::to_vec(&claims).unwrap(),
            &header,
            &EdDSA.signer_from_jwk(key).unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn verifies_agent_claims_and_reserves_identity_partitioned_jti() {
        let private = Jwk::generate_ed_key(Ed25519).unwrap();
        let public = serde_json::to_value(private.to_public_key().unwrap()).unwrap();
        let now = Utc::now();
        let jwt = token(
            &private,
            json!({
                "sub": "agent-id",
                "aud": "https://auth.example.test/api/auth",
                "jti": "one-use",
                "iat": now.timestamp(),
                "exp": now.timestamp() + 60,
                "capabilities": ["mail.send"]
            }),
        );
        let verifier =
            AgentJwtVerifier::new(Arc::new(MemoryAgentJwtReplayStore::default())).unwrap();
        let allowed_algorithms = vec!["Ed25519".into()];
        let verify = || {
            verifier.verify(
                &jwt,
                AgentJwtKeySource {
                    inline_public_jwk: Some(&public),
                    jwks_url: None,
                },
                AgentJwtVerifyOptions {
                    kind: AgentJwtKind::Agent,
                    allowed_key_algorithms: &allowed_algorithms,
                    max_age: Duration::from_secs(60),
                    audience: AgentAudience::new(
                        "https://auth.example.test/api/auth",
                        None,
                        None,
                        false,
                        None,
                    ),
                    require_audience: true,
                    expected_issuer: None,
                    request: None,
                    replay_partition: Some("agent-id"),
                    skip_replay_check: false,
                    now,
                },
            )
        };

        assert_eq!(
            verify().await.unwrap().claims.capabilities,
            vec!["mail.send"]
        );
        assert!(matches!(verify().await, Err(AgentJwtError::Replay)));
    }

    #[tokio::test]
    async fn verifies_host_type_issuer_and_inline_key_without_replay_by_default() {
        let private = Jwk::generate_ed_key(Ed25519).unwrap();
        let public = serde_json::to_value(private.to_public_key().unwrap()).unwrap();
        let now = Utc::now();
        let mut header = JwsHeader::new();
        header.set_algorithm("EdDSA");
        header.set_token_type("host+jwt");
        header.set_key_id("host-key");
        let jwt = jws::serialize_compact(
            &serde_json::to_vec(&json!({
                "iss": "host-thumbprint",
                "aud": "https://auth.example.test/api/auth",
                "iat": now.timestamp()
            }))
            .unwrap(),
            &header,
            &EdDSA.signer_from_jwk(&private).unwrap(),
        )
        .unwrap();
        let verifier =
            AgentJwtVerifier::new(Arc::new(MemoryAgentJwtReplayStore::default())).unwrap();
        let verified = verifier
            .verify(
                &jwt,
                AgentJwtKeySource {
                    inline_public_jwk: Some(&public),
                    jwks_url: Some("https://localhost/jwks.json"),
                },
                AgentJwtVerifyOptions {
                    kind: AgentJwtKind::Host,
                    allowed_key_algorithms: &["Ed25519".into()],
                    max_age: Duration::from_secs(60),
                    audience: AgentAudience::new(
                        "https://auth.example.test/api/auth",
                        None,
                        None,
                        false,
                        None,
                    ),
                    require_audience: true,
                    expected_issuer: Some("host-thumbprint"),
                    request: None,
                    replay_partition: None,
                    skip_replay_check: false,
                    now,
                },
            )
            .await
            .unwrap();
        assert_eq!(verified.claims.issuer.as_deref(), Some("host-thumbprint"));
    }
}
