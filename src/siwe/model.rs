use crate::{AuthUser, DatabaseCreate, OAuthAccount};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq)]
pub struct WalletAddress {
    pub id: String,
    pub user_id: String,
    pub address: String,
    pub chain_id: f64,
    pub is_primary: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WalletAddressOwner {
    pub wallet: WalletAddress,
    pub user: AuthUser,
}

#[derive(Debug, Clone)]
pub enum SiweIdentityWrite {
    AddChain {
        expected_user_id: String,
        wallet: DatabaseCreate<WalletAddress>,
        account: DatabaseCreate<OAuthAccount>,
    },
}

#[derive(Debug, Clone)]
pub enum SiweIdentityWriteOutcome {
    Created {
        user: AuthUser,
        wallet: WalletAddress,
        account: OAuthAccount,
    },
    AddedChain {
        user: AuthUser,
        wallet: WalletAddress,
        account: OAuthAccount,
    },
    Existing(WalletAddressOwner),
    EmailTaken,
}
