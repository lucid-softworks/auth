use super::{ensure_wallet_account_available, find_owner, insert_wallet_account};
use crate::{
    AuthError, AuthUser, DatabaseAccountCreate, DatabaseCreate, SiweIdentityWriteOutcome,
    WalletAddress, WalletAddressOwner,
};

enum IdentityTarget {
    Existing(WalletAddressOwner),
    EmailTaken,
    Link(AuthUser),
    Create(AuthUser),
}

pub(super) async fn write(
    store: &super::super::MemoryStore,
    user: DatabaseCreate<AuthUser>,
    wallet: WalletAddress,
    account: &dyn DatabaseAccountCreate,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let _identity_guard = store.siwe_identity_write.lock().await;
    let target = prepare_target(store, user, &wallet).await?;
    let owner = match &target {
        IdentityTarget::Existing(owner) => {
            return Ok(SiweIdentityWriteOutcome::Existing(owner.clone()));
        }
        IdentityTarget::EmailTaken => return Ok(SiweIdentityWriteOutcome::EmailTaken),
        IdentityTarget::Link(user) | IdentityTarget::Create(user) => user,
    };
    let account = account.prepare(owner).await?;
    persist(store, target, wallet, account).await
}

async fn prepare_target(
    store: &super::super::MemoryStore,
    user: DatabaseCreate<AuthUser>,
    wallet: &WalletAddress,
) -> Result<IdentityTarget, AuthError> {
    let state = store.state.read().await;
    if let Some(owner) = find_owner(&state, &wallet.address, Some(wallet.chain_id))? {
        return Ok(IdentityTarget::Existing(owner));
    }
    if let Some(owner) = find_owner(&state, &wallet.address, None)? {
        return Ok(IdentityTarget::Link(owner.user));
    }
    let DatabaseCreate {
        record: mut user,
        id,
    } = user;
    user.email = user.email.to_lowercase();
    user.id = store.create_id("user", id.prepare(store)?, state.users.len())?;
    if state.emails.contains_key(&user.email)
        || user
            .username
            .as_ref()
            .is_some_and(|username| state.usernames.contains_key(username))
    {
        return Ok(IdentityTarget::EmailTaken);
    }
    super::super::user::ensure_phone_number_available(&state, &user, None)?;
    Ok(IdentityTarget::Create(user))
}

async fn persist(
    store: &super::super::MemoryStore,
    target: IdentityTarget,
    wallet: WalletAddress,
    account: DatabaseCreate<crate::OAuthAccount>,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let mut state = store.state.write().await;
    if let Some(owner) = find_owner(&state, &wallet.address, Some(wallet.chain_id))? {
        return Ok(SiweIdentityWriteOutcome::Existing(owner));
    }
    let (mut account, account_id) = account.into_parts(store)?;
    account.id = store.create_id("account", account_id, state.oauth_accounts.len())?;
    match target {
        IdentityTarget::Existing(_) => unreachable!("existing identities return before prepare"),
        IdentityTarget::EmailTaken => unreachable!("email conflicts return before prepare"),
        IdentityTarget::Link(user) => persist_link(&mut state, user, wallet, account),
        IdentityTarget::Create(user) => persist_create(&mut state, user, wallet, account),
    }
}

fn persist_link(
    state: &mut super::super::MemoryState,
    user: AuthUser,
    mut wallet: WalletAddress,
    mut account: crate::OAuthAccount,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let Some(current) = find_owner(state, &wallet.address, None)? else {
        return Err(AuthError::Storage(
            "SIWE address owner disappeared during chain linking".into(),
        ));
    };
    if current.user.id != user.id {
        return Ok(SiweIdentityWriteOutcome::Existing(current));
    }
    wallet.user_id = user.id.clone();
    wallet.is_primary = false;
    account.user_id = user.id.clone();
    ensure_wallet_account_available(state, &wallet, &account)?;
    insert_wallet_account(state, &wallet, &account);
    Ok(SiweIdentityWriteOutcome::AddedChain {
        user,
        wallet,
        account,
    })
}

fn persist_create(
    state: &mut super::super::MemoryState,
    user: AuthUser,
    mut wallet: WalletAddress,
    mut account: crate::OAuthAccount,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    if state.emails.contains_key(&user.email)
        || user
            .username
            .as_ref()
            .is_some_and(|username| state.usernames.contains_key(username))
    {
        return Ok(SiweIdentityWriteOutcome::EmailTaken);
    }
    super::super::user::ensure_phone_number_available(state, &user, None)?;
    wallet.user_id = user.id.clone();
    wallet.is_primary = true;
    account.user_id = user.id.clone();
    ensure_wallet_account_available(state, &wallet, &account)?;
    if let Some(username) = &user.username {
        state.usernames.insert(username.clone(), user.id.clone());
    }
    state.emails.insert(user.email.clone(), user.id.clone());
    super::super::phone_number::index_phone_number(state, &user)?;
    state.users.insert(user.id.clone(), user.clone());
    insert_wallet_account(state, &wallet, &account);
    Ok(SiweIdentityWriteOutcome::Created {
        user,
        wallet,
        account,
    })
}
