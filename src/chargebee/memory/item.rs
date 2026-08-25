use super::{MemoryChargebeeState, MemoryChargebeeStore};
use crate::chargebee::{ChargebeeStoreError, ChargebeeSubscriptionItem};
use uuid::Uuid;

pub(super) async fn create(
    store: &MemoryChargebeeStore,
    item: ChargebeeSubscriptionItem,
) -> Result<ChargebeeSubscriptionItem, ChargebeeStoreError> {
    let mut state = store.state.write().await;
    if !state.subscriptions.contains_key(&item.subscription_id) {
        return Err(ChargebeeStoreError::MissingSubscription);
    }
    if state.items.contains_key(&item.id) {
        return Err(ChargebeeStoreError::DuplicateId);
    }
    state.item_order.push(item.id);
    state.items.insert(item.id, item.clone());
    Ok(item)
}

pub(super) async fn list(
    store: &MemoryChargebeeStore,
    subscription_id: Uuid,
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    let state = store.state.read().await;
    Ok(items_for(&state, subscription_id))
}

pub(super) async fn delete(
    store: &MemoryChargebeeStore,
    subscription_id: Uuid,
) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError> {
    let mut state = store.state.write().await;
    Ok(delete_locked(&mut state, subscription_id))
}

pub(super) fn delete_locked(
    state: &mut MemoryChargebeeState,
    subscription_id: Uuid,
) -> Vec<ChargebeeSubscriptionItem> {
    let ids = state
        .item_order
        .iter()
        .copied()
        .filter(|id| {
            state
                .items
                .get(id)
                .is_some_and(|item| item.subscription_id == subscription_id)
        })
        .collect::<Vec<_>>();
    state.item_order.retain(|id| !ids.contains(id));
    ids.into_iter()
        .filter_map(|id| state.items.remove(&id))
        .collect()
}

fn items_for(
    state: &MemoryChargebeeState,
    subscription_id: Uuid,
) -> Vec<ChargebeeSubscriptionItem> {
    state
        .item_order
        .iter()
        .filter_map(|id| state.items.get(id))
        .filter(|item| item.subscription_id == subscription_id)
        .cloned()
        .collect()
}
