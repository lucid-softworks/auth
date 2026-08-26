use super::MemoryStore;
use crate::{
    AuthError, AuthUser, DatabaseAccountCreate, DatabaseCreate, SiweIdentityWrite,
    SiweIdentityWriteOutcome, SiweSchema, SiweStore, WalletAddress, WalletAddressOwner,
};
use async_trait::async_trait;

mod create;

#[async_trait]
impl SiweStore for MemoryStore {
    async fn find_wallet_owner(
        &self,
        _schema: &SiweSchema,
        address: &str,
        chain_id: Option<f64>,
    ) -> Result<Option<WalletAddressOwner>, AuthError> {
        let state = self.state.read().await;
        find_owner(&state, address, chain_id)
    }

    async fn create_wallet_identity(
        &self,
        _schema: &SiweSchema,
        user: DatabaseCreate<AuthUser>,
        wallet: WalletAddress,
        account: &dyn DatabaseAccountCreate,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        create::write(self, user, wallet, account).await
    }

    async fn write_wallet_identity(
        &self,
        _schema: &SiweSchema,
        write: SiweIdentityWrite,
    ) -> Result<SiweIdentityWriteOutcome, AuthError> {
        let _identity_guard = self.siwe_identity_write.lock().await;
        let mut state = self.state.write().await;
        let (mut wallet, account) = match &write {
            SiweIdentityWrite::AddChain {
                wallet, account, ..
            } => (wallet.clone(), account.clone()),
        };
        if let Some(owner) = find_owner(&state, &wallet.address, Some(wallet.chain_id))? {
            return Ok(SiweIdentityWriteOutcome::Existing(owner));
        }
        let address_owner = find_owner(&state, &wallet.address, None)?;
        match write {
            SiweIdentityWrite::AddChain {
                expected_user_id, ..
            } => {
                let Some(owner) = address_owner else {
                    return Err(AuthError::Storage(
                        "SIWE address owner disappeared during chain linking".into(),
                    ));
                };
                if owner.user.id != expected_user_id {
                    return Ok(SiweIdentityWriteOutcome::Existing(owner));
                }
                wallet.user_id = owner.user.id.clone();
                wallet.is_primary = false;
                let (mut account, account_id) = account.into_parts(self)?;
                account.id = self.create_id("account", account_id, state.oauth_accounts.len())?;
                account.user_id = owner.user.id.clone();
                ensure_wallet_account_available(&state, &wallet, &account)?;
                insert_wallet_account(&mut state, &wallet, &account);
                Ok(SiweIdentityWriteOutcome::AddedChain {
                    user: owner.user,
                    wallet,
                    account,
                })
            }
        }
    }
}

fn find_owner(
    state: &super::MemoryState,
    address: &str,
    chain_id: Option<f64>,
) -> Result<Option<WalletAddressOwner>, AuthError> {
    let address = address.to_lowercase();
    let wallet = match chain_id {
        Some(chain_id) => state.wallet_addresses.get(&(address, chain_id.to_bits())),
        None => state
            .wallet_addresses
            .iter()
            .find(|((candidate, _), _)| candidate == &address)
            .map(|(_, wallet)| wallet),
    };
    let Some(wallet) = wallet else {
        return Ok(None);
    };
    let user = state
        .users
        .get(&wallet.user_id)
        .ok_or_else(|| AuthError::Storage("SIWE wallet owner is missing".into()))?;
    Ok(Some(WalletAddressOwner {
        wallet: wallet.clone(),
        user: user.clone(),
    }))
}

fn insert_wallet_account(
    state: &mut super::MemoryState,
    wallet: &WalletAddress,
    account: &crate::OAuthAccount,
) {
    let wallet_key = (wallet.address.to_lowercase(), wallet.chain_id.to_bits());
    let account_key = (account.issuer.clone(), account.account_id.clone());
    state.wallet_addresses.insert(wallet_key, wallet.clone());
    state.oauth_accounts.insert(account_key, account.clone());
}

fn ensure_wallet_account_available(
    state: &super::MemoryState,
    wallet: &WalletAddress,
    account: &crate::OAuthAccount,
) -> Result<(), AuthError> {
    let wallet_key = (wallet.address.to_lowercase(), wallet.chain_id.to_bits());
    let account_key = (account.issuer.clone(), account.account_id.clone());
    if state.wallet_addresses.contains_key(&wallet_key)
        || state.oauth_accounts.contains_key(&account_key)
    {
        return Err(AuthError::UserAlreadyExists);
    }
    Ok(())
}
