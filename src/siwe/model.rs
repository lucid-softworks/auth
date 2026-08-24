use crate::{AuthUser, OAuthAccount};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct WalletAddress {
    pub id: Uuid,
    pub user_id: Uuid,
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
    Create {
        user: Box<AuthUser>,
        wallet: WalletAddress,
        account: Box<OAuthAccount>,
    },
    AddChain {
        expected_user_id: Uuid,
        wallet: WalletAddress,
        account: Box<OAuthAccount>,
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
