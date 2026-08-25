use crate::stripe::{BillingInterval, StripeStoreError, Subscription};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct SubscriptionRow {
    id: Uuid,
    plan: String,
    reference_id: String,
    stripe_customer_id: Option<String>,
    stripe_subscription_id: Option<String>,
    status: String,
    period_start: Option<DateTime<Utc>>,
    period_end: Option<DateTime<Utc>>,
    trial_start: Option<DateTime<Utc>>,
    trial_end: Option<DateTime<Utc>>,
    cancel_at_period_end: bool,
    cancel_at: Option<DateTime<Utc>>,
    canceled_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
    seats: Option<f64>,
    billing_interval: Option<String>,
    stripe_schedule_id: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<SubscriptionRow> for Subscription {
    type Error = StripeStoreError;

    fn try_from(row: SubscriptionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            plan: row.plan,
            reference_id: row.reference_id,
            stripe_customer_id: row.stripe_customer_id,
            stripe_subscription_id: row.stripe_subscription_id,
            status: row.status.parse().map_err(|error| {
                StripeStoreError::Unavailable(format!("invalid persisted Stripe status: {error}"))
            })?,
            period_start: row.period_start,
            period_end: row.period_end,
            trial_start: row.trial_start,
            trial_end: row.trial_end,
            cancel_at_period_end: row.cancel_at_period_end,
            cancel_at: row.cancel_at,
            canceled_at: row.canceled_at,
            ended_at: row.ended_at,
            seats: row.seats,
            billing_interval: row
                .billing_interval
                .map(|interval| parse_billing_interval(&interval))
                .transpose()?,
            stripe_schedule_id: row.stripe_schedule_id,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

fn parse_billing_interval(value: &str) -> Result<BillingInterval, StripeStoreError> {
    match value {
        "day" => Ok(BillingInterval::Day),
        "week" => Ok(BillingInterval::Week),
        "month" => Ok(BillingInterval::Month),
        "year" => Ok(BillingInterval::Year),
        _ => Err(StripeStoreError::Unavailable(format!(
            "invalid persisted Stripe billing interval `{value}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn billing_interval_accepts_only_stripe_values() {
        assert_eq!(parse_billing_interval("day").unwrap(), BillingInterval::Day);
        assert_eq!(
            parse_billing_interval("month").unwrap(),
            BillingInterval::Month
        );
        assert!(parse_billing_interval("monthly").is_err());
    }
}
