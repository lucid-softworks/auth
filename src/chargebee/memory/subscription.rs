use super::{MemoryChargebeeState, MemoryChargebeeStore, item};
use crate::chargebee::{ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionPatch};
use uuid::Uuid;

pub(super) async fn create(
    store: &MemoryChargebeeStore,
    subscription: ChargebeeSubscription,
) -> Result<ChargebeeSubscription, ChargebeeStoreError> {
    let mut state = store.state.write().await;
    if state.subscriptions.contains_key(&subscription.id) {
        return Err(ChargebeeStoreError::DuplicateId);
    }
    ensure_provider_id_available(
        &state,
        subscription.chargebee_subscription_id.as_deref(),
        None,
    )?;
    state.subscription_order.push(subscription.id);
    state
        .subscriptions
        .insert(subscription.id, subscription.clone());
    Ok(subscription)
}

pub(super) async fn find(
    store: &MemoryChargebeeStore,
    id: Uuid,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    Ok(store.state.read().await.subscriptions.get(&id).cloned())
}

pub(super) async fn find_by_chargebee_id(
    store: &MemoryChargebeeStore,
    chargebee_id: &str,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    let state = store.state.read().await;
    Ok(in_order(&state)
        .find(|subscription| {
            subscription.chargebee_subscription_id.as_deref() == Some(chargebee_id)
        })
        .cloned())
}

pub(super) async fn list_by_reference(
    store: &MemoryChargebeeStore,
    reference_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    let state = store.state.read().await;
    Ok(in_order(&state)
        .filter(|subscription| subscription.reference_id == reference_id)
        .cloned()
        .collect())
}

pub(super) async fn list_by_customer(
    store: &MemoryChargebeeStore,
    customer_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    let state = store.state.read().await;
    Ok(in_order(&state)
        .filter(|subscription| subscription.chargebee_customer_id.as_deref() == Some(customer_id))
        .cloned()
        .collect())
}

pub(super) async fn update(
    store: &MemoryChargebeeStore,
    id: Uuid,
    patch: ChargebeeSubscriptionPatch,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    let mut state = store.state.write().await;
    let proposed_provider_id = match &patch.chargebee_subscription_id {
        Some(value) => value.as_deref(),
        None => state
            .subscriptions
            .get(&id)
            .and_then(|subscription| subscription.chargebee_subscription_id.as_deref()),
    };
    ensure_provider_id_available(&state, proposed_provider_id, Some(id))?;
    let Some(subscription) = state.subscriptions.get_mut(&id) else {
        return Ok(None);
    };
    patch.apply(subscription);
    Ok(Some(subscription.clone()))
}

pub(super) async fn delete(
    store: &MemoryChargebeeStore,
    id: Uuid,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    let mut state = store.state.write().await;
    Ok(delete_locked(&mut state, id))
}

pub(super) async fn delete_by_reference(
    store: &MemoryChargebeeStore,
    reference_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    delete_matching(store, |subscription| {
        subscription.reference_id == reference_id
    })
    .await
}

pub(super) async fn delete_by_customer(
    store: &MemoryChargebeeStore,
    customer_id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    delete_matching(store, |subscription| {
        subscription.chargebee_customer_id.as_deref() == Some(customer_id)
    })
    .await
}

async fn delete_matching(
    store: &MemoryChargebeeStore,
    predicate: impl Fn(&ChargebeeSubscription) -> bool,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    let mut state = store.state.write().await;
    let ids = state
        .subscription_order
        .iter()
        .copied()
        .filter(|id| state.subscriptions.get(id).is_some_and(&predicate))
        .collect::<Vec<_>>();
    Ok(ids
        .into_iter()
        .filter_map(|id| delete_locked(&mut state, id))
        .collect())
}

fn delete_locked(state: &mut MemoryChargebeeState, id: Uuid) -> Option<ChargebeeSubscription> {
    let removed = state.subscriptions.remove(&id)?;
    state.subscription_order.retain(|stored| *stored != id);
    item::delete_locked(state, id);
    Some(removed)
}

fn ensure_provider_id_available(
    state: &MemoryChargebeeState,
    provider_id: Option<&str>,
    except: Option<Uuid>,
) -> Result<(), ChargebeeStoreError> {
    if provider_id.is_some_and(|provider_id| {
        state.subscriptions.iter().any(|(id, subscription)| {
            Some(*id) != except
                && subscription.chargebee_subscription_id.as_deref() == Some(provider_id)
        })
    }) {
        Err(ChargebeeStoreError::DuplicateSubscriptionId)
    } else {
        Ok(())
    }
}

fn in_order(state: &MemoryChargebeeState) -> impl Iterator<Item = &ChargebeeSubscription> {
    state
        .subscription_order
        .iter()
        .filter_map(|id| state.subscriptions.get(id))
}
