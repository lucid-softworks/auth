use crate::AuthError;
#[cfg(feature = "axum")]
use crate::{OAuthClientAssertion, OAuthClientAssertionContext};
use async_trait::async_trait;
#[cfg(feature = "axum")]
use josekit::{
    jwk::Jwk,
    jws::{
        self, ES256, ES384, ES512, EdDSA, JwsHeader, JwsSigner, PS256, PS384, PS512, RS256,
        RS384, RS512,
    },
};
use serde_json::Value;
#[cfg(feature = "axum")]
use serde_json::json;

#[cfg(feature = "axum")]
const ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
    "EdDSA",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SsoPrivateKey {
    pub private_key_jwk: Option<Value>,
    pub private_key_pem: Option<String>,
    pub kid: Option<String>,
    pub algorithm: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoPrivateKeyRequest {
    pub provider_id: String,
    pub key_id: Option<String>,
    pub issuer: String,
}

#[async_trait]
pub trait SsoPrivateKeyResolver: Send + Sync {
    async fn resolve(
        &self,
        request: SsoPrivateKeyRequest,
    ) -> Result<Option<SsoPrivateKey>, AuthError>;
}

#[cfg(feature = "axum")]
pub(super) struct SsoClientAssertion {
    jwk: Option<Jwk>,
    pem: Option<String>,
    kid: Option<String>,
    algorithm: String,
}

#[cfg(feature = "axum")]
impl SsoClientAssertion {
    pub(super) fn new(
        material: SsoPrivateKey,
        configured_kid: Option<&str>,
        configured_algorithm: Option<&str>,
    ) -> Result<Self, AuthError> {
        let jwk = material
            .private_key_jwk
            .map(|value| serde_json::from_value::<Jwk>(value).map_err(configuration))
            .transpose()?;
        if jwk.is_none() && material.private_key_pem.is_none() {
            return Err(configuration("private key material is missing"));
        }
        let algorithm = configured_algorithm
            .map(str::to_owned)
            .or(material.algorithm)
            .or_else(|| jwk.as_ref().and_then(Jwk::algorithm).map(str::to_owned))
            .unwrap_or_else(|| "RS256".into());
        if !ALGORITHMS.contains(&algorithm.as_str()) {
            return Err(configuration("unsupported private_key_jwt algorithm"));
        }
        Ok(Self {
            jwk,
            pem: material.private_key_pem,
            kid: configured_kid.map(str::to_owned).or(material.kid),
            algorithm,
        })
    }

    fn signer(&self) -> Result<Box<dyn JwsSigner>, AuthError> {
        macro_rules! select {
            ($algorithm:expr) => {{
                if let Some(jwk) = &self.jwk {
                    Box::new($algorithm.signer_from_jwk(jwk).map_err(configuration)?)
                } else {
                    Box::new(
                        $algorithm
                            .signer_from_pem(self.pem.as_deref().unwrap_or_default())
                            .map_err(configuration)?,
                    )
                }
            }};
        }
        Ok(match self.algorithm.as_str() {
            "RS256" => select!(RS256),
            "RS384" => select!(RS384),
            "RS512" => select!(RS512),
            "PS256" => select!(PS256),
            "PS384" => select!(PS384),
            "PS512" => select!(PS512),
            "ES256" => select!(ES256),
            "ES384" => select!(ES384),
            "ES512" => select!(ES512),
            "EdDSA" => select!(EdDSA),
            _ => return Err(configuration("unsupported private_key_jwt algorithm")),
        })
    }
}

#[cfg(feature = "axum")]
#[async_trait]
impl OAuthClientAssertion for SsoClientAssertion {
    async fn client_assertion(
        &self,
        context: OAuthClientAssertionContext,
    ) -> Result<String, AuthError> {
        let now = chrono::Utc::now().timestamp();
        let claims = json!({
            "iss": context.client_id,
            "sub": context.client_id,
            "aud": context.token_endpoint,
            "iat": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string()
        });
        let mut header = JwsHeader::new();
        header.set_algorithm(&self.algorithm);
        if let Some(kid) = &self.kid {
            header.set_key_id(kid);
        }
        jws::serialize_compact(
            &serde_json::to_vec(&claims).map_err(configuration)?,
            &header,
            self.signer()?.as_ref(),
        )
        .map_err(configuration)
    }
}

#[cfg(feature = "axum")]
fn configuration(error: impl std::fmt::Display) -> AuthError {
    AuthError::InvalidConfiguration(format!("invalid SSO private key: {error}"))
}
