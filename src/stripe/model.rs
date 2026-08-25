use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, str::FromStr, sync::Arc};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProrationBehavior {
    #[default]
    CreateProrations,
    AlwaysInvoice,
    None,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CustomerType {
    #[default]
    User,
    Organization,
}

impl ProrationBehavior {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CreateProrations => "create_prorations",
            Self::AlwaysInvoice => "always_invoice",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StripePlan {
    pub name: String,
    pub price_id: Option<String>,
    pub lookup_key: Option<String>,
    pub annual_discount_price_id: Option<String>,
    pub annual_discount_lookup_key: Option<String>,
    pub limits: Option<BTreeMap<String, Value>>,
    pub group: Option<String>,
    pub seat_price_id: Option<String>,
    #[serde(default)]
    pub proration_behavior: ProrationBehavior,
    #[serde(default)]
    pub line_items: Vec<CheckoutLineItem>,
    pub free_trial: Option<FreeTrial>,
}

impl StripePlan {
    pub fn matches_name(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    pub fn persisted_name(&self) -> String {
        self.name.to_lowercase()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CheckoutLineItem {
    pub price: Option<Value>,
    pub quantity: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeTrial {
    pub days: u32,
    #[serde(skip)]
    pub callbacks: Option<Arc<dyn super::TrialCallbacks>>,
}

impl fmt::Debug for FreeTrial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreeTrial")
            .field("days", &self.days)
            .field("has_callbacks", &self.callbacks.is_some())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionStatus {
    Active,
    Canceled,
    #[default]
    Incomplete,
    IncompleteExpired,
    PastDue,
    Paused,
    Trialing,
    Unpaid,
}

impl SubscriptionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Canceled => "canceled",
            Self::Incomplete => "incomplete",
            Self::IncompleteExpired => "incomplete_expired",
            Self::PastDue => "past_due",
            Self::Paused => "paused",
            Self::Trialing => "trialing",
            Self::Unpaid => "unpaid",
        }
    }

    pub const fn is_active_or_trialing(self) -> bool {
        matches!(self, Self::Active | Self::Trialing)
    }
}

impl fmt::Display for SubscriptionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SubscriptionStatus {
    type Err = SubscriptionStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "canceled" => Ok(Self::Canceled),
            "incomplete" => Ok(Self::Incomplete),
            "incomplete_expired" => Ok(Self::IncompleteExpired),
            "past_due" => Ok(Self::PastDue),
            "paused" => Ok(Self::Paused),
            "trialing" => Ok(Self::Trialing),
            "unpaid" => Ok(Self::Unpaid),
            _ => Err(SubscriptionStatusParseError(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid Stripe subscription status `{0}`")]
pub struct SubscriptionStatusParseError(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BillingInterval {
    Day,
    Week,
    Month,
    Year,
}

impl BillingInterval {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub id: Uuid,
    pub plan: String,
    pub reference_id: String,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    #[serde(default)]
    pub status: SubscriptionStatus,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub trial_start: Option<DateTime<Utc>>,
    pub trial_end: Option<DateTime<Utc>>,
    #[serde(default)]
    pub cancel_at_period_end: bool,
    pub cancel_at: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub seats: Option<f64>,
    pub billing_interval: Option<BillingInterval>,
    pub stripe_schedule_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Subscription {
    pub const fn is_active_or_trialing(&self) -> bool {
        self.status.is_active_or_trialing()
    }

    pub const fn is_pending_cancel(&self) -> bool {
        self.cancel_at_period_end || self.cancel_at.is_some()
    }

    pub fn has_trial_history(&self) -> bool {
        self.status == SubscriptionStatus::Trialing
            || self.trial_start.is_some()
            || self.trial_end.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_lookup_is_case_insensitive_but_persistence_is_lowercase() {
        let plan = StripePlan {
            name: "Pro-Team".into(),
            price_id: None,
            lookup_key: None,
            annual_discount_price_id: None,
            annual_discount_lookup_key: None,
            limits: None,
            group: Some("unused-in-1.7.1".into()),
            seat_price_id: None,
            proration_behavior: ProrationBehavior::default(),
            line_items: vec![],
            free_trial: None,
        };
        assert!(plan.matches_name("PRO-team"));
        assert_eq!(plan.persisted_name(), "pro-team");
    }

    #[test]
    fn statuses_round_trip_exact_storage_values() {
        for status in [
            SubscriptionStatus::Active,
            SubscriptionStatus::Canceled,
            SubscriptionStatus::Incomplete,
            SubscriptionStatus::IncompleteExpired,
            SubscriptionStatus::PastDue,
            SubscriptionStatus::Paused,
            SubscriptionStatus::Trialing,
            SubscriptionStatus::Unpaid,
        ] {
            assert_eq!(status.as_str().parse(), Ok(status));
        }
    }
}
