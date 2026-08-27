use super::{
    ensure_wallet_account_available, find_owner, insert_wallet_account, materialize_wallet,
};
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
    wallet: DatabaseCreate<WalletAddress>,
    account: &dyn DatabaseAccountCreate,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let _identity_guard = store.siwe_identity_write.lock().await;
    let target = prepare_target(store, user, &wallet.record).await?;
    match &target {
        IdentityTarget::Existing(owner) => {
            return Ok(SiweIdentityWriteOutcome::Existing(owner.clone()));
        }
        IdentityTarget::EmailTaken => return Ok(SiweIdentityWriteOutcome::EmailTaken),
        IdentityTarget::Link(_) | IdentityTarget::Create(_) => {}
    }
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
    if state.emails.contains_key(&user.email)
        || user
            .username
            .as_ref()
            .is_some_and(|username| state.usernames.contains_key(username))
    {
        return Ok(IdentityTarget::EmailTaken);
    }
    super::super::user::ensure_phone_number_available(&state, &user, None)?;
    user.id = store.create_id("user", id.prepare(store)?, state.users.len())?;
    Ok(IdentityTarget::Create(user))
}

async fn persist(
    store: &super::super::MemoryStore,
    target: IdentityTarget,
    wallet: DatabaseCreate<WalletAddress>,
    account: &dyn DatabaseAccountCreate,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let owner = match &target {
        IdentityTarget::Link(user) | IdentityTarget::Create(user) => user,
        IdentityTarget::Existing(_) | IdentityTarget::EmailTaken => {
            unreachable!("conflicts return before persistence")
        }
    };
    let account = account.prepare(owner).await?;
    let mut state = store.state.write().await;
    if let Some(owner) = find_owner(&state, &wallet.record.address, Some(wallet.record.chain_id))? {
        return Ok(SiweIdentityWriteOutcome::Existing(owner));
    }
    match target {
        IdentityTarget::Existing(_) => unreachable!("existing identities return before prepare"),
        IdentityTarget::EmailTaken => unreachable!("email conflicts return before prepare"),
        IdentityTarget::Link(user) => persist_link(store, &mut state, user, wallet, account),
        IdentityTarget::Create(user) => persist_create(store, &mut state, user, wallet, account),
    }
}

fn persist_link(
    store: &super::super::MemoryStore,
    state: &mut super::super::MemoryState,
    user: AuthUser,
    mut wallet: DatabaseCreate<WalletAddress>,
    mut account: DatabaseCreate<crate::OAuthAccount>,
) -> Result<SiweIdentityWriteOutcome, AuthError> {
    let Some(current) = find_owner(state, &wallet.record.address, None)? else {
        return Err(AuthError::Storage(
            "SIWE address owner disappeared during chain linking".into(),
        ));
    };
    if current.user.id != user.id {
        return Ok(SiweIdentityWriteOutcome::Existing(current));
    }
    wallet.record.user_id = user.id.clone();
    wallet.record.is_primary = false;
    account.record.user_id = user.id.clone();
    ensure_wallet_account_available(state, &wallet.record, &account.record)?;
    let wallet = materialize_wallet(store, state, wallet)?;
    let (mut account, account_id) = account.into_parts(store)?;
    account.id = store.create_id("account", account_id, state.oauth_accounts.len())?;
    insert_wallet_account(state, &wallet, &account);
    Ok(SiweIdentityWriteOutcome::AddedChain {
        user,
        wallet,
        account,
    })
}

fn persist_create(
    store: &super::super::MemoryStore,
    state: &mut super::super::MemoryState,
    user: AuthUser,
    mut wallet: DatabaseCreate<WalletAddress>,
    mut account: DatabaseCreate<crate::OAuthAccount>,
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
    wallet.record.user_id = user.id.clone();
    wallet.record.is_primary = true;
    account.record.user_id = user.id.clone();
    ensure_wallet_account_available(state, &wallet.record, &account.record)?;
    let wallet = materialize_wallet(store, state, wallet)?;
    let (mut account, account_id) = account.into_parts(store)?;
    account.id = store.create_id("account", account_id, state.oauth_accounts.len())?;
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
