use super::{SiweIdentityWrite, SiweIdentityWriteOutcome, SiweSchema, WalletAddressOwner};
use crate::{AuthError, AuthUser, DatabaseAccountCreate, DatabaseCreate, WalletAddress};
use async_trait::async_trait;

#[async_trait]
pub trait SiweStore: Send + Sync {
    async fn find_wallet_owner(
        &self,
        schema: &SiweSchema,
        address: &str,
        chain_id: Option<f64>,
    ) -> Result<Option<WalletAddressOwner>, AuthError>;

    async fn create_wallet_identity(
        &self,
        schema: &SiweSchema,
        user: DatabaseCreate<AuthUser>,
        wallet: WalletAddress,
        account: &dyn DatabaseAccountCreate,
    ) -> Result<SiweIdentityWriteOutcome, AuthError>;

    async fn write_wallet_identity(
        &self,
        schema: &SiweSchema,
        write: SiweIdentityWrite,
    ) -> Result<SiweIdentityWriteOutcome, AuthError>;
}
