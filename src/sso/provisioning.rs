use crate::{AuthError, AuthUser, OAuthTokens, OAuthUserInfo};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct SsoProvisioningInput {
    pub user: AuthUser,
    pub user_info: OAuthUserInfo,
    pub tokens: Option<OAuthTokens>,
    pub provider: super::SsoProvider,
}

#[async_trait]
pub trait SsoUserProvisioner: Send + Sync {
    async fn provision(&self, input: SsoProvisioningInput) -> Result<(), AuthError>;
}
