use super::{ChargebeeSubscription, ChargebeeSubscriptionItem, ChargebeeSubscriptionStatus};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChargebeeStoreError {
    #[error("Chargebee record id already exists")]
    DuplicateId,
    #[error("Chargebee customer id already exists")]
    DuplicateCustomerId,
    #[error("Chargebee subscription id already exists")]
    DuplicateSubscriptionId,
    #[error("Chargebee subscription item references a missing subscription")]
    MissingSubscription,
    #[error("Chargebee subscription store is unavailable: {0}")]
    Unavailable(String),
}

/// An adapter-style subscription mutation.
///
/// Nested options distinguish an omitted field from an explicit database
/// `null`, which webhook transitions and customer deletion both require.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ChargebeeSubscriptionPatch {
    pub reference_id: Option<String>,
    pub chargebee_customer_id: Option<Option<String>>,
    pub chargebee_subscription_id: Option<Option<String>>,
    pub status: Option<ChargebeeSubscriptionStatus>,
    pub period_start: Option<Option<DateTime<Utc>>>,
    pub period_end: Option<Option<DateTime<Utc>>>,
    pub trial_start: Option<Option<DateTime<Utc>>>,
    pub trial_end: Option<Option<DateTime<Utc>>>,
    pub canceled_at: Option<Option<DateTime<Utc>>>,
    pub seats: Option<Option<f64>>,
    pub metadata: Option<Option<String>>,
}

impl ChargebeeSubscriptionPatch {
    pub fn apply(self, subscription: &mut ChargebeeSubscription) {
        if let Some(value) = self.reference_id {
            subscription.reference_id = value;
        }
        apply_nullable(
            self.chargebee_customer_id,
            &mut subscription.chargebee_customer_id,
        );
        apply_nullable(
            self.chargebee_subscription_id,
            &mut subscription.chargebee_subscription_id,
        );
        if let Some(value) = self.status {
            subscription.status = value;
        }
        apply_nullable(self.period_start, &mut subscription.period_start);
        apply_nullable(self.period_end, &mut subscription.period_end);
        apply_nullable(self.trial_start, &mut subscription.trial_start);
        apply_nullable(self.trial_end, &mut subscription.trial_end);
        apply_nullable(self.canceled_at, &mut subscription.canceled_at);
        apply_nullable(self.seats, &mut subscription.seats);
        apply_nullable(self.metadata, &mut subscription.metadata);
    }
}

fn apply_nullable<T>(patch: Option<Option<T>>, target: &mut Option<T>) {
    if let Some(value) = patch {
        *target = value;
    }
}

/// Granular persistence operations used by the Chargebee 1.2.0 adapter.
///
/// The interface intentionally offers no transactions, bulk item creation, or
/// atomic item replacement. Upstream writes subscription items sequentially
/// and can expose partially completed work after a later failure.
#[async_trait]
pub trait ChargebeeStore: Send + Sync {
    async fn user_customer_id(&self, user_id: Uuid) -> Result<Option<String>, ChargebeeStoreError>;
    async fn set_user_customer_id(
        &self,
        user_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), ChargebeeStoreError>;
    async fn user_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, ChargebeeStoreError>;

    async fn organization_customer_id(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<String>, ChargebeeStoreError>;
    async fn set_organization_customer_id(
        &self,
        organization_id: Uuid,
        customer_id: Option<String>,
    ) -> Result<(), ChargebeeStoreError>;
    async fn organization_id_by_customer(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, ChargebeeStoreError>;

    async fn create_subscription(
        &self,
        subscription: ChargebeeSubscription,
    ) -> Result<ChargebeeSubscription, ChargebeeStoreError>;
    async fn find_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn find_subscription_by_chargebee_id(
        &self,
        chargebee_subscription_id: &str,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn list_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn list_subscriptions_by_customer(
        &self,
        chargebee_customer_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn update_subscription(
        &self,
        id: Uuid,
        patch: ChargebeeSubscriptionPatch,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn delete_subscription(
        &self,
        id: Uuid,
    ) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn delete_subscriptions_by_reference(
        &self,
        reference_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError>;
    async fn delete_subscriptions_by_customer(
        &self,
        chargebee_customer_id: &str,
    ) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError>;

    async fn create_subscription_item(
        &self,
        item: ChargebeeSubscriptionItem,
    ) -> Result<ChargebeeSubscriptionItem, ChargebeeStoreError>;
    async fn list_subscription_items(
        &self,
        subscription_id: Uuid,
    ) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError>;
    async fn delete_subscription_items(
        &self,
        subscription_id: Uuid,
    ) -> Result<Vec<ChargebeeSubscriptionItem>, ChargebeeStoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patches_preserve_omitted_values_and_clear_explicit_nulls() {
        let mut subscription = ChargebeeSubscription::future("owner");
        subscription.chargebee_customer_id = Some("customer".into());
        subscription.metadata = Some("metadata".into());
        ChargebeeSubscriptionPatch {
            chargebee_customer_id: Some(None),
            status: Some(ChargebeeSubscriptionStatus::Active),
            ..ChargebeeSubscriptionPatch::default()
        }
        .apply(&mut subscription);
        assert!(subscription.chargebee_customer_id.is_none());
        assert_eq!(subscription.metadata.as_deref(), Some("metadata"));
        assert_eq!(subscription.status, ChargebeeSubscriptionStatus::Active);
    }
}
