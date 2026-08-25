use crate::chargebee::{
    ChargebeeItemType, ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionItem,
    ChargebeeSubscriptionStatus,
};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct ChargebeeSubscriptionRow {
    pub id: Uuid,
    pub reference_id: String,
    pub chargebee_customer_id: Option<String>,
    pub chargebee_subscription_id: Option<String>,
    pub status: String,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub trial_start: Option<DateTime<Utc>>,
    pub trial_end: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub seats: Option<f64>,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<ChargebeeSubscriptionRow> for ChargebeeSubscription {
    type Error = ChargebeeStoreError;

    fn try_from(row: ChargebeeSubscriptionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            reference_id: row.reference_id,
            chargebee_customer_id: row.chargebee_customer_id,
            chargebee_subscription_id: row.chargebee_subscription_id,
            status: row
                .status
                .parse::<ChargebeeSubscriptionStatus>()
                .map_err(|error| ChargebeeStoreError::Unavailable(error.to_string()))?,
            period_start: row.period_start,
            period_end: row.period_end,
            trial_start: row.trial_start,
            trial_end: row.trial_end,
            canceled_at: row.canceled_at,
            seats: row.seats,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(FromRow)]
pub(super) struct ChargebeeSubscriptionItemRow {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub item_price_id: String,
    pub item_type: String,
    pub quantity: f64,
    pub unit_price: Option<f64>,
    pub amount: Option<f64>,
}

impl TryFrom<ChargebeeSubscriptionItemRow> for ChargebeeSubscriptionItem {
    type Error = ChargebeeStoreError;

    fn try_from(row: ChargebeeSubscriptionItemRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            subscription_id: row.subscription_id,
            item_price_id: row.item_price_id,
            item_type: row
                .item_type
                .parse::<ChargebeeItemType>()
                .map_err(|error| ChargebeeStoreError::Unavailable(error.to_string()))?,
            quantity: row.quantity,
            unit_price: row.unit_price,
            amount: row.amount,
        })
    }
}
