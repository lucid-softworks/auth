mod checkout;
mod subscription;
mod value;

use crate::creem::{CreemStore, CreemWebhookPersistence};
use async_trait::async_trait;
use serde_json::{Map, Value};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct CreemStoreWebhookPersistence {
    store: Arc<dyn CreemStore>,
}

impl CreemStoreWebhookPersistence {
    pub(crate) fn new(store: Arc<dyn CreemStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl CreemWebhookPersistence for CreemStoreWebhookPersistence {
    async fn persist_checkout(
        &self,
        checkout: &Map<String, Value>,
    ) -> Result<(), crate::creem::CreemPersistenceError> {
        checkout::persist(self.store.as_ref(), checkout).await
    }

    async fn persist_subscription(
        &self,
        event_type: &str,
        subscription: &Map<String, Value>,
    ) -> Result<(), crate::creem::CreemPersistenceError> {
        subscription::persist(self.store.as_ref(), event_type, subscription).await
    }

    async fn mark_trial(
        &self,
        subscription: &Map<String, Value>,
    ) -> Result<(), crate::creem::CreemPersistenceError> {
        subscription::mark_trial(self.store.as_ref(), subscription).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creem::{
        CreemStoreError, CreemStoredUser, CreemSubscription, CreemSubscriptionPatch,
    };
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use serde_json::json;
    use std::collections::BTreeMap;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    #[derive(Default)]
    struct StoreState {
        users: BTreeMap<String, CreemStoredUser>,
        subscriptions: Vec<CreemSubscription>,
        fail_customer_link: bool,
    }

    #[derive(Default)]
    struct TestStore {
        state: Mutex<StoreState>,
    }

    impl TestStore {
        async fn add_user(
            &self,
            reference_id: &str,
            customer: Option<Value>,
            trial: Option<Value>,
        ) {
            self.state.lock().await.users.insert(
                reference_id.into(),
                CreemStoredUser {
                    reference_id: reference_id.into(),
                    creem_customer_id: customer,
                    had_trial: trial,
                },
            );
        }

        async fn subscriptions(&self) -> Vec<CreemSubscription> {
            self.state.lock().await.subscriptions.clone()
        }
    }

    #[async_trait]
    impl CreemStore for TestStore {
        async fn find_user(
            &self,
            reference_id: &str,
        ) -> Result<Option<CreemStoredUser>, CreemStoreError> {
            Ok(self.state.lock().await.users.get(reference_id).cloned())
        }

        async fn set_user_customer_id(
            &self,
            reference_id: &str,
            customer_id: &str,
        ) -> Result<(), CreemStoreError> {
            let mut state = self.state.lock().await;
            if state.fail_customer_link {
                return Err(CreemStoreError::Unavailable("link".into()));
            }
            if let Some(user) = state.users.get_mut(reference_id) {
                user.creem_customer_id = Some(Value::String(customer_id.into()));
            }
            Ok(())
        }

        async fn set_user_had_trial(
            &self,
            reference_id: &str,
            had_trial: bool,
        ) -> Result<(), CreemStoreError> {
            if let Some(user) = self.state.lock().await.users.get_mut(reference_id) {
                user.had_trial = Some(Value::Bool(had_trial));
            }
            Ok(())
        }

        async fn create_subscription(
            &self,
            subscription: CreemSubscription,
        ) -> Result<CreemSubscription, CreemStoreError> {
            self.state
                .lock()
                .await
                .subscriptions
                .push(subscription.clone());
            Ok(subscription)
        }

        async fn find_subscription_by_creem_id(
            &self,
            creem_subscription_id: &str,
        ) -> Result<Option<CreemSubscription>, CreemStoreError> {
            Ok(self
                .state
                .lock()
                .await
                .subscriptions
                .iter()
                .find(|subscription| {
                    subscription.creem_subscription_id.as_deref() == Some(creem_subscription_id)
                })
                .cloned())
        }

        async fn list_subscriptions_by_reference(
            &self,
            reference_id: &str,
        ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
            Ok(self
                .state
                .lock()
                .await
                .subscriptions
                .iter()
                .filter(|subscription| subscription.reference_id == reference_id)
                .cloned()
                .collect())
        }

        async fn list_subscriptions_by_customer(
            &self,
            customer_id: &str,
        ) -> Result<Vec<CreemSubscription>, CreemStoreError> {
            Ok(self
                .state
                .lock()
                .await
                .subscriptions
                .iter()
                .filter(|subscription| {
                    subscription.creem_customer_id.as_deref() == Some(customer_id)
                })
                .cloned()
                .collect())
        }

        async fn update_subscription(
            &self,
            id: Uuid,
            patch: CreemSubscriptionPatch,
        ) -> Result<Option<CreemSubscription>, CreemStoreError> {
            let mut state = self.state.lock().await;
            let Some(subscription) = state
                .subscriptions
                .iter_mut()
                .find(|subscription| subscription.id == id)
            else {
                return Ok(None);
            };
            patch.apply(subscription);
            Ok(Some(subscription.clone()))
        }
    }

    #[tokio::test]
    async fn missing_checkout_product_keeps_the_earlier_customer_link_only() {
        let store = Arc::new(TestStore::default());
        store.add_user("user_1", None, None).await;
        let bridge = CreemStoreWebhookPersistence::new(store.clone());
        let checkout = object(json!({
            "customer": {"id": "customer_1"},
            "metadata": {"referenceId": "user_1"},
            "subscription": {"id": "subscription_1", "status": "active"},
            "order": {"id": "order_1"}
        }));

        assert!(bridge.persist_checkout(&checkout).await.is_err());
        assert_eq!(
            store
                .find_user("user_1")
                .await
                .unwrap()
                .unwrap()
                .creem_customer_id,
            Some(Value::String("customer_1".into()))
        );
        assert!(store.subscriptions().await.is_empty());
    }

    #[tokio::test]
    async fn a_failed_customer_link_does_not_prevent_checkout_subscription_creation() {
        let store = Arc::new(TestStore::default());
        store.add_user("user_1", None, None).await;
        store.state.lock().await.fail_customer_link = true;
        let bridge = CreemStoreWebhookPersistence::new(store.clone());

        bridge.persist_checkout(&checkout_payload()).await.unwrap();
        let subscriptions = store.subscriptions().await;
        assert_eq!(subscriptions.len(), 1);
        assert_eq!(subscriptions[0].product_id, "product_1");
        assert_eq!(
            subscriptions[0].creem_subscription_id.as_deref(),
            Some("subscription_1")
        );
    }

    #[tokio::test]
    async fn subscription_events_preserve_owned_fields_and_absent_periods() {
        let store = Arc::new(TestStore::default());
        let old_end = timestamp("2026-09-01T00:00:00Z");
        let mut existing = CreemSubscription::new("product_1", "original_owner");
        existing.creem_customer_id = Some("customer_1".into());
        existing.creem_order_id = Some("order_1".into());
        existing.period_end = Some(old_end);
        existing.cancel_at_period_end = true;
        store.create_subscription(existing.clone()).await.unwrap();
        let bridge = CreemStoreWebhookPersistence::new(store.clone());
        let event = object(json!({
            "id": "subscription_1",
            "status": "provider_status",
            "customer": {"id": "customer_1"},
            "product": {"id": "product_1"},
            "metadata": {"referenceId": "event_owner"},
            "current_period_start_date": "2026-08-01T00:00:00Z"
        }));

        bridge
            .persist_subscription("subscription.paid", &event)
            .await
            .unwrap();
        let updated = store.subscriptions().await.remove(0);
        assert_eq!(updated.status, "provider_status");
        assert_eq!(updated.reference_id, "original_owner");
        assert_eq!(updated.creem_order_id.as_deref(), Some("order_1"));
        assert_eq!(updated.period_end, Some(old_end));
        assert!(updated.cancel_at_period_end);
        assert_eq!(
            updated.period_start,
            Some(timestamp("2026-08-01T00:00:00Z"))
        );
    }

    #[tokio::test]
    async fn trial_marking_remains_independent_after_subscription_update_failure() {
        let store = Arc::new(TestStore::default());
        store
            .add_user("user_1", None, Some(Value::Bool(false)))
            .await;
        let bridge = CreemStoreWebhookPersistence::new(store.clone());
        let event = object(json!({
            "id": "subscription_1",
            "product": {"id": "product_1"},
            "metadata": {"referenceId": "user_1"}
        }));

        assert!(
            bridge
                .persist_subscription("subscription.trialing", &event)
                .await
                .is_err()
        );
        bridge.mark_trial(&event).await.unwrap();
        assert_eq!(
            store.find_user("user_1").await.unwrap().unwrap().had_trial,
            Some(Value::Bool(true))
        );
    }

    fn checkout_payload() -> Map<String, Value> {
        object(json!({
            "customer": {"id": "customer_1"},
            "metadata": {"referenceId": "user_1"},
            "subscription": {
                "id": "subscription_1",
                "status": "active",
                "current_period_start_date": "2026-08-01T00:00:00Z"
            },
            "order": {"id": "order_1"},
            "product": {"id": "product_1"}
        }))
    }

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    fn timestamp(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }
}
