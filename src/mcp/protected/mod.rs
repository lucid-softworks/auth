mod challenge;
mod dpop;
mod introspection;
mod jwt;
mod replay;
mod resource;
mod scope;

use std::{
    collections::BTreeSet,
    fmt,
    sync::{Arc, LazyLock},
};

use serde_json::{Map, Value};

pub use challenge::McpAuthorizationChallenge;
pub use replay::{McpDpopReplayReservation, McpDpopReplayStore, ProcessMcpDpopReplayStore};

const DEFAULT_DPOP_PROOF_MAX_AGE_SECONDS: f64 = 300.0;

/// Request information used to validate a protected MCP HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpProtectedRequest {
    pub authorization_header: Option<String>,
    pub dpop_proof_jwt: Option<String>,
    pub method: String,
    pub url: String,
}

/// Remote RFC 7662 verification for opaque or authoritatively rechecked tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRemoteVerifyOptions {
    pub introspect_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub force: bool,
    pub allow_missing_audience: bool,
}

/// JOSE constraints in addition to the authoritative issuer and audience.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct McpJwtVerifyOptions {
    pub algorithms: Option<Vec<String>>,
    pub token_type: Option<String>,
    pub required_claims: Vec<String>,
    pub subject: Option<String>,
    pub clock_tolerance_seconds: f64,
    pub max_token_age_seconds: Option<f64>,
    pub current_date: Option<chrono::DateTime<chrono::Utc>>,
}

/// DPoP proof constraints and replay protection.
#[derive(Clone)]
pub struct McpDpopOptions {
    pub proof_max_age_seconds: f64,
    pub signing_algorithms: Option<Vec<String>>,
    pub replay_store: Option<Arc<dyn McpDpopReplayStore>>,
}

impl Default for McpDpopOptions {
    fn default() -> Self {
        Self {
            proof_max_age_seconds: DEFAULT_DPOP_PROOF_MAX_AGE_SECONDS,
            signing_algorithms: None,
            replay_store: None,
        }
    }
}

impl fmt::Debug for McpDpopOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDpopOptions")
            .field("proof_max_age_seconds", &self.proof_max_age_seconds)
            .field("signing_algorithms", &self.signing_algorithms)
            .field(
                "replay_store",
                &self.replay_store.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

pub type McpScopeMatcher = Arc<dyn Fn(&str, &BTreeSet<String>) -> bool + Send + Sync + 'static>;

/// Options for the framework-neutral MCP protected-request wrapper.
#[derive(Clone)]
pub struct McpProtectedRequestHandlerOptions {
    pub issuer: String,
    pub audience: String,
    pub jwt_verify_options: McpJwtVerifyOptions,
    pub jwks_url: Option<String>,
    pub remote_verify: Option<McpRemoteVerifyOptions>,
    pub required_scopes: Option<Vec<String>>,
    pub challenge_scopes: Option<Vec<String>>,
    pub is_scope_satisfied: Option<McpScopeMatcher>,
    pub dpop: McpDpopOptions,
}

impl fmt::Debug for McpProtectedRequestHandlerOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpProtectedRequestHandlerOptions")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("jwt_verify_options", &self.jwt_verify_options)
            .field("jwks_url", &self.jwks_url)
            .field("remote_verify", &self.remote_verify)
            .field("required_scopes", &self.required_scopes)
            .field("challenge_scopes", &self.challenge_scopes)
            .field(
                "is_scope_satisfied",
                &self.is_scope_satisfied.as_ref().map(|_| "custom"),
            )
            .field("dpop", &self.dpop)
            .finish()
    }
}

/// Options whose omitted values are resolved from an [`crate::AuthService`].
#[derive(Clone, Default)]
pub struct RequireMcpAuthOptions {
    pub resource: Option<String>,
    pub issuer: Option<String>,
    pub jwks_url: Option<String>,
    pub required_scopes: Option<Vec<String>>,
    pub challenge_scopes: Option<Vec<String>>,
    pub is_scope_satisfied: Option<McpScopeMatcher>,
    pub dpop: McpDpopOptions,
}

/// Result of checking a protected request.
#[derive(Debug, Clone, PartialEq)]
pub enum McpProtectedRequestOutcome {
    Authorized(Map<String, Value>),
    Challenge(McpAuthorizationChallenge),
}

/// Configuration or infrastructure failure that must propagate to the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpProtectedRequestError {
    #[error("{0}")]
    InvalidConfiguration(String),
    #[error("{0}")]
    Infrastructure(String),
}

#[derive(Clone)]
pub struct McpProtectedRequestHandler {
    options: Arc<McpProtectedRequestHandlerOptions>,
    http: reqwest::Client,
    process_replay: Arc<ProcessMcpDpopReplayStore>,
}

impl fmt::Debug for McpProtectedRequestHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpProtectedRequestHandler")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

/// Creates Better Auth's generic MCP protected-request verifier.
pub fn create_mcp_protected_request_handler(
    options: McpProtectedRequestHandlerOptions,
) -> Result<McpProtectedRequestHandler, McpProtectedRequestError> {
    resource::validate_mcp_resource(&options.audience)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| McpProtectedRequestError::Infrastructure(error.to_string()))?;
    Ok(McpProtectedRequestHandler {
        options: Arc::new(options),
        http,
        process_replay: PROCESS_DPOP_REPLAY.clone(),
    })
}

static PROCESS_DPOP_REPLAY: LazyLock<Arc<ProcessMcpDpopReplayStore>> =
    LazyLock::new(|| Arc::new(ProcessMcpDpopReplayStore::default()));

/// Resolves Better Auth's MCP wrapper defaults from an auth service.
pub fn require_mcp_auth(
    service: Arc<crate::AuthService>,
    mut options: RequireMcpAuthOptions,
) -> Result<McpProtectedRequestHandler, McpProtectedRequestError> {
    if let Some(resource) = options.resource.as_deref() {
        resource::validate_mcp_resource(resource)?;
    }
    let base_url = service.mcp_resolved_base_url().ok_or_else(|| {
        McpProtectedRequestError::InvalidConfiguration(
            "requireMcpAuth requires a resolvable base URL. For dynamic base URLs use `createMcpProtectedRequestHandler` with explicit verification options.".into(),
        )
    })?;
    let issuer = options.issuer.take().unwrap_or_else(|| base_url.clone());
    let audience = options.resource.take().unwrap_or_else(|| base_url.clone());
    let jwks_url = options
        .jwks_url
        .take()
        .unwrap_or_else(|| format!("{base_url}/jwks"));
    if options.dpop.replay_store.is_none() {
        options.dpop.replay_store = Some(Arc::new(replay::DurableMcpDpopReplayStore::new(service)));
    }
    create_mcp_protected_request_handler(McpProtectedRequestHandlerOptions {
        issuer,
        audience,
        jwt_verify_options: McpJwtVerifyOptions::default(),
        jwks_url: Some(jwks_url),
        remote_verify: None,
        required_scopes: options.required_scopes,
        challenge_scopes: options.challenge_scopes,
        is_scope_satisfied: options.is_scope_satisfied,
        dpop: options.dpop,
    })
}

impl McpProtectedRequestHandler {
    pub fn options(&self) -> &McpProtectedRequestHandlerOptions {
        &self.options
    }

    pub async fn verify(
        &self,
        request: &McpProtectedRequest,
    ) -> Result<McpProtectedRequestOutcome, McpProtectedRequestError> {
        scope::validate_required_scopes(self.options.required_scopes.as_deref())?;
        match self.verify_claims(request).await {
            Ok(claims) => Ok(McpProtectedRequestOutcome::Authorized(claims)),
            Err(VerificationFailure::Challenge(error)) => challenge::from_oauth_error(
                &error,
                &self.options.audience,
                self.options
                    .challenge_scopes
                    .as_deref()
                    .or(self.options.required_scopes.as_deref()),
                self.options.dpop.signing_algorithms.as_deref(),
            )
            .map(McpProtectedRequestOutcome::Challenge),
            Err(VerificationFailure::Infrastructure(message)) => {
                Err(McpProtectedRequestError::Infrastructure(message))
            }
        }
    }

    /// Converts a handler-owned insufficient-scope failure into the same MCP challenge.
    pub fn insufficient_scope_challenge(
        &self,
        required_scopes: Vec<String>,
        description: Option<String>,
    ) -> Result<McpAuthorizationChallenge, McpProtectedRequestError> {
        scope::validate_nonempty_scopes(&required_scopes)?;
        let description = description.unwrap_or_else(|| {
            format!(
                "access token is missing required scope: {}",
                required_scopes.join(" ")
            )
        });
        challenge::from_oauth_error(
            &crate::OAuthProviderError::InsufficientScope {
                description,
                required_scopes,
            },
            &self.options.audience,
            self.options.challenge_scopes.as_deref(),
            self.options.dpop.signing_algorithms.as_deref(),
        )
    }

    async fn verify_claims(
        &self,
        request: &McpProtectedRequest,
    ) -> Result<Map<String, Value>, VerificationFailure> {
        let authorization = dpop::parse_authorization(request.authorization_header.as_deref())?;
        let payload =
            jwt::verify_access_token(&self.http, &authorization.token, &self.options).await?;
        scope::enforce_scopes(
            &payload,
            self.options.required_scopes.as_deref(),
            self.options.is_scope_satisfied.as_ref(),
        )?;
        let replay = self
            .options
            .dpop
            .replay_store
            .as_deref()
            .unwrap_or(self.process_replay.as_ref());
        dpop::enforce_binding(
            &payload,
            &authorization,
            request,
            &self.options.dpop,
            replay,
        )
        .await?;
        Ok(payload)
    }
}

#[derive(Debug)]
enum VerificationFailure {
    Challenge(crate::OAuthProviderError),
    Infrastructure(String),
}

impl From<crate::AuthError> for VerificationFailure {
    fn from(error: crate::AuthError) -> Self {
        Self::Infrastructure(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> McpProtectedRequestHandlerOptions {
        McpProtectedRequestHandlerOptions {
            issuer: "https://auth.example.test".into(),
            audience: "https://api.example.test/mcp".into(),
            jwt_verify_options: McpJwtVerifyOptions::default(),
            jwks_url: None,
            remote_verify: None,
            required_scopes: None,
            challenge_scopes: None,
            is_scope_satisfied: None,
            dpop: McpDpopOptions::default(),
        }
    }

    #[test]
    fn generic_handlers_share_the_process_replay_store() {
        let first = create_mcp_protected_request_handler(options()).unwrap();
        let second = create_mcp_protected_request_handler(options()).unwrap();
        assert!(Arc::ptr_eq(&first.process_replay, &second.process_replay));
    }

    #[test]
    fn required_scope_validation_is_deferred_until_request_verification() {
        let mut options = options();
        options.required_scopes = Some(vec!["bad scope".into()]);
        assert!(create_mcp_protected_request_handler(options).is_ok());
    }
}
