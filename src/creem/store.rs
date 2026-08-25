use super::CreemSubscription;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum CreemStoreError {
    #[error("Creem subscription id already exists")]
    DuplicateId,
    #[error("Creem subscription store is unavailable: {0}")]
    Unavailable(String),
}

/// The plugin-owned user fields read by Creem persistence workflows.
///
/// Values remain JSON so the caller can reproduce JavaScript truthiness. In
/// particular, checkout tests `hadTrial === true`, while webhook writes test
/// the same stored value for falseyness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreemStoredUser {
    pub reference_id: String,
    pub creem_customer_id: Option<Value>,
    pub had_trial: Option<Value>,
}

/// A granular Better Auth adapter-style subscription mutation.
///
/// Nested options preserve the distinction between an omitted property and a
/// property explicitly cleared by a store caller. Checkout completion uses the
/// full patch shape when updating an existing row; later subscription events
/// leave product, reference, and order fields omitted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreemSubscriptionPatch {
    pub product_id: Option<String>,
    pub reference_id: Option<String>,
    pub status: Option<String>,
    pub creem_customer_id: Option<Option<String>>,
    pub creem_subscription_id: Option<Option<String>>,
    pub creem_order_id: Option<Option<String>>,
    pub period_start: Option<Option<DateTime<Utc>>>,
    pub period_end: Option<Option<DateTime<Utc>>>,
}

impl CreemSubscriptionPatch {
    pub fn apply(self, subscription: &mut CreemSubscription) {
        if let Some(product_id) = self.product_id {
            subscription.product_id = product_id;
        }
        if let Some(reference_id) = self.reference_id {
            subscription.reference_id = reference_id;
        }
        if let Some(status) = self.status {
            subscription.status = status;
        }
        apply_nullable(self.creem_customer_id, &mut subscription.creem_customer_id);
        apply_nullable(
            self.creem_subscription_id,
            &mut subscription.creem_subscription_id,
        );
        apply_nullable(self.creem_order_id, &mut subscription.creem_order_id);
        apply_nullable(self.period_start, &mut subscription.period_start);
        apply_nullable(self.period_end, &mut subscription.period_end);
    }
}

fn apply_nullable<T>(patch: Option<Option<T>>, target: &mut Option<T>) {
    if let Some(value) = patch {
        *target = value;
    }
}

/// Persistence operations used by the native Creem plugin.
///
/// The interface intentionally has no transaction or provider-id upsert. The
/// pinned webhook performs separate reads and writes, catches each helper's
/// failures, and can therefore leave partial progress or duplicate rows.
#[async_trait]
pub trait CreemStore: Send + Sync {
    async fn find_user(
        &self,
        reference_id: &str,
    ) -> Result<Option<CreemStoredUser>, CreemStoreError>;

    async fn set_user_customer_id(
        &self,
        reference_id: &str,
        customer_id: &str,
    ) -> Result<(), CreemStoreError>;

    async fn set_user_had_trial(
        &self,
        reference_id: &str,
        had_trial: bool,
    ) -> Result<(), CreemStoreError>;

    async fn create_subscription(
        &self,
        subscription: CreemSubscription,
    ) -> Result<CreemSubscription, CreemStoreError>;

    /// Returns the first row in adapter order with the provider id.
    /// Provider ids are deliberately not unique.
    async fn find_subscription_by_creem_id(
        &self,
        creem_subscription_id: &str,
    ) -> Result<Option<CreemSubscription>, CreemStoreError>;

    /// Returns all rows in the adapter's native order; no ordering contract is
    /// added by the plugin.
    async fn list_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<CreemSubscription>, CreemStoreError>;

    /// Returns all customer rows in the adapter's native order.
    async fn list_subscriptions_by_customer(
        &self,
        creem_customer_id: &str,
    ) -> Result<Vec<CreemSubscription>, CreemStoreError>;

    async fn update_subscription(
        &self,
        id: Uuid,
        patch: CreemSubscriptionPatch,
    ) -> Result<Option<CreemSubscription>, CreemStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_event_patch_preserves_checkout_owned_fields() {
        let now = Utc::now();
        let mut subscription = CreemSubscription {
            id: Uuid::new_v4(),
            product_id: "product".into(),
            reference_id: "owner".into(),
            creem_customer_id: Some("customer-old".into()),
            creem_subscription_id: Some("subscription-old".into()),
            creem_order_id: Some("order".into()),
            status: "pending".into(),
            period_start: Some(now),
            period_end: Some(now),
            cancel_at_period_end: true,
        };

        CreemSubscriptionPatch {
            status: Some("active".into()),
            creem_customer_id: Some(Some("customer-new".into())),
            creem_subscription_id: Some(None),
            period_start: None,
            period_end: Some(None),
            ..CreemSubscriptionPatch::default()
        }
        .apply(&mut subscription);

        assert_eq!(subscription.product_id, "product");
        assert_eq!(subscription.reference_id, "owner");
        assert_eq!(subscription.creem_order_id.as_deref(), Some("order"));
        assert!(subscription.cancel_at_period_end);
        assert_eq!(subscription.status, "active");
        assert_eq!(
            subscription.creem_customer_id.as_deref(),
            Some("customer-new")
        );
        assert!(subscription.creem_subscription_id.is_none());
        assert_eq!(subscription.period_start, Some(now));
        assert!(subscription.period_end.is_none());
    }

    #[test]
    fn checkout_patch_can_replace_every_upserted_field() {
        let mut subscription = CreemSubscription::new("old-product", "old-owner");
        CreemSubscriptionPatch {
            product_id: Some("new-product".into()),
            reference_id: Some("new-owner".into()),
            creem_order_id: Some(Some("new-order".into())),
            ..CreemSubscriptionPatch::default()
        }
        .apply(&mut subscription);
        assert_eq!(subscription.product_id, "new-product");
        assert_eq!(subscription.reference_id, "new-owner");
        assert_eq!(subscription.creem_order_id.as_deref(), Some("new-order"));
    }
}
