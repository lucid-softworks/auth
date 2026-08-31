use crate::{AuthError, DatabaseTransaction};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct SsoProviderUserProfile {
    pub email: String,
    pub email_verified: bool,
    pub name: String,
    pub image: Option<String>,
    pub additional_fields: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SsoUserResolutionInput {
    Oidc {
        provider_id: String,
        account_issuer: String,
        account_id: String,
        provider_user: SsoProviderUserProfile,
        provider_claims: Map<String, Value>,
        verified_id_token_claims: Map<String, Value>,
        provider_reference: super::SsoProviderReference,
    },
    Saml {
        provider_id: String,
        account_issuer: String,
        account_id: String,
        provider_user: SsoProviderUserProfile,
        provider_attributes: Map<String, Value>,
        provider_reference: super::SsoProviderReference,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsoUserResolution {
    Continue,
    Link {
        user_id: String,
        profile: SsoUserProfilePolicy,
    },
    Reject {
        code: String,
        message: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsoUserProfilePolicy {
    Preserve,
    Update,
}

#[derive(Clone)]
pub struct SsoUserResolutionContext {
    pub database: Arc<dyn DatabaseTransaction>,
}

impl std::fmt::Debug for SsoUserResolutionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsoUserResolutionContext")
            .finish_non_exhaustive()
    }
}

#[async_trait]
pub trait SsoUserResolver: Send + Sync {
    async fn resolve(
        &self,
        input: SsoUserResolutionInput,
        context: SsoUserResolutionContext,
    ) -> Result<SsoUserResolution, AuthError>;
}
