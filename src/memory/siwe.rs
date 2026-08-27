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
        wallet: DatabaseCreate<WalletAddress>,
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
        let (mut wallet, mut account) = match &write {
            SiweIdentityWrite::AddChain {
                wallet, account, ..
            } => (wallet.clone(), account.clone()),
        };
        if let Some(owner) =
            find_owner(&state, &wallet.record.address, Some(wallet.record.chain_id))?
        {
            return Ok(SiweIdentityWriteOutcome::Existing(owner));
        }
        let address_owner = find_owner(&state, &wallet.record.address, None)?;
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
                wallet.record.user_id = owner.user.id.clone();
                wallet.record.is_primary = false;
                account.record.user_id = owner.user.id.clone();
                ensure_wallet_account_available(&state, &wallet.record, &account.record)?;
                let wallet = materialize_wallet(self, &state, wallet)?;
                let (mut account, account_id) = account.into_parts(self)?;
                account.id = self.create_id("account", account_id, state.oauth_accounts.len())?;
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

pub(super) fn materialize_wallet(
    store: &MemoryStore,
    state: &super::MemoryState,
    wallet: DatabaseCreate<WalletAddress>,
) -> Result<WalletAddress, AuthError> {
    let (mut wallet, id) = wallet.into_parts(store)?;
    wallet.id = store.create_id("walletAddress", id, state.wallet_addresses.len())?;
    if state
        .wallet_addresses
        .values()
        .any(|existing| existing.id == wallet.id)
    {
        return Err(AuthError::Storage(
            "SIWE wallet address id already exists".into(),
        ));
    }
    Ok(wallet)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DatabaseIdGeneration, DatabaseIdGenerationRequest, DatabaseIdGenerationResult,
        DatabaseIdGenerator, DatabaseIdInput, DatabaseIdPlan,
    };
    use chrono::Utc;
    use std::sync::Arc;

    #[derive(Debug)]
    struct Empty;

    impl DatabaseIdGenerator for Empty {
        fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            DatabaseIdGenerationResult::Id(String::new())
        }
    }

    #[derive(Debug)]
    struct Defer;

    impl DatabaseIdGenerator for Defer {
        fn generate(&self, _: DatabaseIdGenerationRequest<'_>) -> DatabaseIdGenerationResult {
            DatabaseIdGenerationResult::Defer
        }
    }

    fn wallet(strategy: DatabaseIdGeneration) -> DatabaseCreate<WalletAddress> {
        DatabaseCreate::new(
            WalletAddress {
                id: String::new(),
                user_id: "user".into(),
                address: "0xwallet".into(),
                chain_id: 1.0,
                is_primary: true,
                created_at: Utc::now(),
            },
            DatabaseIdPlan::new(strategy, "walletAddress", DatabaseIdInput::Absent, false),
        )
    }

    #[tokio::test]
    async fn memory_rejects_every_ordinary_deferred_wallet_id() {
        for strategy in [
            DatabaseIdGeneration::Database,
            DatabaseIdGeneration::Callback(Arc::new(Defer)),
            DatabaseIdGeneration::Callback(Arc::new(Empty)),
        ] {
            let store = MemoryStore::default();
            let state = store.state.read().await;
            let error = materialize_wallet(&store, &state, wallet(strategy)).unwrap_err();
            assert!(
                matches!(error, AuthError::Storage(message) if message.contains("model 'walletAddress'"))
            );
        }
    }
}
