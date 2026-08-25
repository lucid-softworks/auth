use super::{
    CreemStore, CreemStoreError, CreemStoredUser, CreemSubscription, CreemSubscriptionPatch,
};
use crate::{AuthStore, UserProfileUpdate};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Default)]
struct MemoryCreemState {
    subscriptions: BTreeMap<Uuid, CreemSubscription>,
    insertion_order: Vec<Uuid>,
}

/// In-memory Creem data attached to the same user store as [`crate::AuthService`].
pub struct MemoryCreemStore {
    auth_store: Arc<dyn AuthStore>,
    state: RwLock<MemoryCreemState>,
}

impl MemoryCreemStore {
    pub fn new(auth_store: Arc<dyn AuthStore>) -> Self {
        Self {
            auth_store,
            state: RwLock::new(MemoryCreemState::default()),
        }
    }
}

#[async_trait]
impl CreemStore for MemoryCreemStore {
    async fn find_user(
        &self,
        reference_id: &str,
    ) -> Result<Option<CreemStoredUser>, CreemStoreError> {
        let Some(user_id) = native_user_id(reference_id) else {
            return Ok(None);
        };
        self.auth_store
            .find_user_by_id(user_id)
            .await
            .map_err(auth_error)
            .map(|user| {
                user.map(|user| CreemStoredUser {
                    reference_id: reference_id.to_owned(),
                    creem_customer_id: user.additional_fields.get("creemCustomerId").cloned(),
                    had_trial: user.additional_fields.get("hadTrial").cloned(),
                })
            })
    }

    async fn set_user_customer_id(
        &self,
        reference_id: &str,
        customer_id: &str,
    ) -> Result<(), CreemStoreError> {
        update_user_field(
            self.auth_store.as_ref(),
            reference_id,
            "creemCustomerId",
            Value::String(customer_id.to_owned()),
        )
        .await
    }

    async fn set_user_had_trial(
        &self,
        reference_id: &str,
        had_trial: bool,
    ) -> Result<(), CreemStoreError> {
        update_user_field(
            self.auth_store.as_ref(),
            reference_id,
            "hadTrial",
            Value::Bool(had_trial),
        )
        .await
    }

    async fn create_subscription(
        &self,
        subscription: CreemSubscription,
    ) -> Result<CreemSubscription, CreemStoreError> {
        let mut state = self.state.write().await;
        if state.subscriptions.contains_key(&subscription.id) {
            return Err(CreemStoreError::DuplicateId);
        }
        state.insertion_order.push(subscription.id);
        state
            .subscriptions
            .insert(subscription.id, subscription.clone());
        Ok(subscription)
    }

    async fn find_subscription_by_creem_id(
        &self,
        creem_subscription_id: &str,
    ) -> Result<Option<CreemSubscription>, CreemStoreError> {
        let state = self.state.read().await;
        Ok(state.insertion_order.iter().find_map(|id| {
            state.subscriptions.get(id).and_then(|subscription| {
                (subscription.creem_subscription_id.as_deref() == Some(creem_subscription_id))
                    .then(|| subscription.clone())
            })
        }))
    }

    async fn list_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
        let state = self.state.read().await;
        Ok(in_order(&state)
            .filter(|subscription| subscription.reference_id == reference_id)
            .cloned()
            .collect())
    }

    async fn list_subscriptions_by_customer(
        &self,
        creem_customer_id: &str,
    ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
        let state = self.state.read().await;
        Ok(in_order(&state)
            .filter(|subscription| {
                subscription.creem_customer_id.as_deref() == Some(creem_customer_id)
            })
            .cloned()
            .collect())
    }

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: CreemSubscriptionPatch,
    ) -> Result<Option<CreemSubscription>, CreemStoreError> {
        let mut state = self.state.write().await;
        let Some(subscription) = state.subscriptions.get_mut(&id) else {
            return Ok(None);
        };
        patch.apply(subscription);
        Ok(Some(subscription.clone()))
    }
}

fn in_order(state: &MemoryCreemState) -> impl Iterator<Item = &CreemSubscription> {
    state
        .insertion_order
        .iter()
        .filter_map(|id| state.subscriptions.get(id))
}

fn native_user_id(reference_id: &str) -> Option<Uuid> {
    Uuid::parse_str(reference_id).ok()
}

async fn update_user_field(
    auth_store: &dyn AuthStore,
    reference_id: &str,
    field: &str,
    value: Value,
) -> Result<(), CreemStoreError> {
    let Some(user_id) = native_user_id(reference_id) else {
        return Ok(());
    };
    let additional_fields = Map::from_iter([(field.to_owned(), value)]);
    auth_store
        .update_user_profile(
            user_id,
            UserProfileUpdate {
                additional_fields,
                ..UserProfileUpdate::default()
            },
        )
        .await
        .map(|_| ())
        .map_err(auth_error)
}

fn auth_error(error: crate::AuthError) -> CreemStoreError {
    CreemStoreError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthUser, MemoryStore};
    use chrono::Utc;

    #[tokio::test]
    async fn user_fields_update_the_real_auth_store() {
        let auth_store = Arc::new(MemoryStore::default());
        let user = user();
        auth_store
            .create_user_without_account(user.clone())
            .await
            .unwrap();
        let store = MemoryCreemStore::new(auth_store.clone());

        store
            .set_user_customer_id(&user.id.to_string(), "cust_1")
            .await
            .unwrap();
        store
            .set_user_had_trial(&user.id.to_string(), true)
            .await
            .unwrap();

        let creem_user = store
            .find_user(&user.id.to_string())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(creem_user.creem_customer_id, Some(Value::from("cust_1")));
        assert_eq!(creem_user.had_trial, Some(Value::Bool(true)));
        let persisted = auth_store.find_user_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(
            persisted.additional_fields.get("creemCustomerId"),
            Some(&Value::from("cust_1"))
        );
        assert_eq!(
            persisted.additional_fields.get("hadTrial"),
            Some(&Value::Bool(true))
        );
    }

    #[tokio::test]
    async fn subscriptions_keep_insertion_order_and_duplicate_provider_ids() {
        let auth_store = Arc::new(MemoryStore::default());
        let store = MemoryCreemStore::new(auth_store);
        let first = subscription("owner", "customer", "duplicate");
        let second = subscription("owner", "customer", "duplicate");
        store.create_subscription(first.clone()).await.unwrap();
        store.create_subscription(second.clone()).await.unwrap();

        assert_eq!(
            store
                .find_subscription_by_creem_id("duplicate")
                .await
                .unwrap()
                .map(|subscription| subscription.id),
            Some(first.id)
        );
        assert_eq!(
            store
                .list_subscriptions_by_reference("owner")
                .await
                .unwrap()
                .into_iter()
                .map(|subscription| subscription.id)
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );
        assert_eq!(
            store
                .list_subscriptions_by_customer("customer")
                .await
                .unwrap()
                .into_iter()
                .map(|subscription| subscription.id)
                .collect::<Vec<_>>(),
            vec![first.id, second.id]
        );

        assert!(matches!(
            store.create_subscription(first).await,
            Err(CreemStoreError::DuplicateId)
        ));
        assert_eq!(
            store
                .list_subscriptions_by_reference("owner")
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn an_invalid_external_reference_does_not_constrain_subscription_rows() {
        let auth_store = Arc::new(MemoryStore::default());
        let store = MemoryCreemStore::new(auth_store);
        let row = subscription("not-a-uuid", "customer", "subscription");
        store.create_subscription(row.clone()).await.unwrap();

        assert!(store.find_user("not-a-uuid").await.unwrap().is_none());
        assert_eq!(
            store
                .list_subscriptions_by_reference("not-a-uuid")
                .await
                .unwrap(),
            vec![row]
        );
    }

    fn user() -> AuthUser {
        let now = Utc::now();
        AuthUser {
            id: Uuid::new_v4(),
            username: None,
            display_username: None,
            name: "Creem user".into(),
            email: "creem@example.com".into(),
            email_verified: true,
            image: None,
            additional_fields: Map::new(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn subscription(reference_id: &str, customer_id: &str, provider_id: &str) -> CreemSubscription {
        CreemSubscription {
            id: Uuid::new_v4(),
            product_id: "product".into(),
            reference_id: reference_id.into(),
            creem_customer_id: Some(customer_id.into()),
            creem_subscription_id: Some(provider_id.into()),
            creem_order_id: None,
            status: CreemSubscription::DEFAULT_STATUS.into(),
            period_start: None,
            period_end: None,
            cancel_at_period_end: false,
        }
    }
}
