use crate::creem::CreemSubscription;
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct SubscriptionRow {
    id: Uuid,
    product_id: String,
    reference_id: String,
    creem_customer_id: Option<String>,
    creem_subscription_id: Option<String>,
    creem_order_id: Option<String>,
    status: String,
    period_start: Option<DateTime<Utc>>,
    period_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
}

impl From<SubscriptionRow> for CreemSubscription {
    fn from(row: SubscriptionRow) -> Self {
        Self {
            id: row.id,
            product_id: row.product_id,
            reference_id: row.reference_id,
            creem_customer_id: row.creem_customer_id,
            creem_subscription_id: row.creem_subscription_id,
            creem_order_id: row.creem_order_id,
            status: row.status,
            period_start: row.period_start,
            period_end: row.period_end,
            cancel_at_period_end: row.cancel_at_period_end,
        }
    }
}
