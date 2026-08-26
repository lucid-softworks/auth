use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};
use uuid::Uuid;

/// Chargebee's known statuses plus raw values added by the provider runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ChargebeeSubscriptionStatus {
    #[default]
    Future,
    InTrial,
    Active,
    NonRenewing,
    Paused,
    Cancelled,
    Transferred,
    Other(String),
}

impl ChargebeeSubscriptionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Future => "future",
            Self::InTrial => "in_trial",
            Self::Active => "active",
            Self::NonRenewing => "non_renewing",
            Self::Paused => "paused",
            Self::Cancelled => "cancelled",
            Self::Transferred => "transferred",
            Self::Other(value) => value,
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::InTrial | Self::NonRenewing)
    }
}

impl Serialize for ChargebeeSubscriptionStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChargebeeSubscriptionStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(String::deserialize(deserializer)?
            .parse()
            .expect("Chargebee status parsing is infallible"))
    }
}

impl fmt::Display for ChargebeeSubscriptionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ChargebeeSubscriptionStatus {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "future" => Ok(Self::Future),
            "in_trial" => Ok(Self::InTrial),
            "active" => Ok(Self::Active),
            "non_renewing" => Ok(Self::NonRenewing),
            "paused" => Ok(Self::Paused),
            "cancelled" => Ok(Self::Cancelled),
            "transferred" => Ok(Self::Transferred),
            _ => Ok(Self::Other(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargebeeItemType {
    Plan,
    Addon,
    Charge,
    Other(String),
}

impl ChargebeeItemType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Plan => "plan",
            Self::Addon => "addon",
            Self::Charge => "charge",
            Self::Other(value) => value,
        }
    }
}

impl Serialize for ChargebeeItemType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ChargebeeItemType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(String::deserialize(deserializer)?
            .parse()
            .expect("Chargebee item-type parsing is infallible"))
    }
}

impl fmt::Display for ChargebeeItemType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ChargebeeItemType {
    type Err = std::convert::Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "plan" => Ok(Self::Plan),
            "addon" => Ok(Self::Addon),
            "charge" => Ok(Self::Charge),
            _ => Ok(Self::Other(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargebeeSubscription {
    pub id: Uuid,
    pub reference_id: String,
    pub chargebee_customer_id: Option<String>,
    pub chargebee_subscription_id: Option<String>,
    #[serde(default)]
    pub status: ChargebeeSubscriptionStatus,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,
    pub trial_start: Option<DateTime<Utc>>,
    pub trial_end: Option<DateTime<Utc>>,
    pub canceled_at: Option<DateTime<Utc>>,
    pub seats: Option<f64>,
    pub metadata: Option<String>,
}

impl ChargebeeSubscription {
    pub fn future(reference_id: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            reference_id: reference_id.into(),
            chargebee_customer_id: None,
            chargebee_subscription_id: None,
            status: ChargebeeSubscriptionStatus::Future,
            period_start: None,
            period_end: None,
            trial_start: None,
            trial_end: None,
            canceled_at: None,
            seats: None,
            metadata: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChargebeeSubscriptionItem {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub item_price_id: String,
    pub item_type: ChargebeeItemType,
    pub quantity: f64,
    pub unit_price: Option<f64>,
    pub amount: Option<f64>,
}

impl ChargebeeSubscriptionItem {
    pub fn new(
        subscription_id: Uuid,
        item_price_id: impl Into<String>,
        item_type: ChargebeeItemType,
        quantity: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            subscription_id,
            item_price_id: item_price_id.into(),
            item_type,
            quantity,
            unit_price: None,
            amount: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_vocabulary_and_active_subset_are_exact() {
        for (wire, status, active) in [
            ("future", ChargebeeSubscriptionStatus::Future, false),
            ("in_trial", ChargebeeSubscriptionStatus::InTrial, true),
            ("active", ChargebeeSubscriptionStatus::Active, true),
            (
                "non_renewing",
                ChargebeeSubscriptionStatus::NonRenewing,
                true,
            ),
            ("paused", ChargebeeSubscriptionStatus::Paused, false),
            ("cancelled", ChargebeeSubscriptionStatus::Cancelled, false),
            (
                "transferred",
                ChargebeeSubscriptionStatus::Transferred,
                false,
            ),
        ] {
            assert_eq!(
                wire.parse::<ChargebeeSubscriptionStatus>().unwrap(),
                status.clone()
            );
            assert_eq!(status.as_str(), wire);
            assert_eq!(status.is_active(), active);
        }
    }

    #[test]
    fn item_type_vocabulary_is_exact() {
        for (wire, item_type) in [
            ("plan", ChargebeeItemType::Plan),
            ("addon", ChargebeeItemType::Addon),
            ("charge", ChargebeeItemType::Charge),
        ] {
            assert_eq!(
                wire.parse::<ChargebeeItemType>().unwrap(),
                item_type.clone()
            );
            assert_eq!(item_type.as_str(), wire);
        }
    }

    #[test]
    fn provider_added_status_and_item_type_round_trip_as_raw_strings() {
        let status: ChargebeeSubscriptionStatus = "provider_added".parse().unwrap();
        let item_type: ChargebeeItemType = "metered".parse().unwrap();

        assert_eq!(
            status,
            ChargebeeSubscriptionStatus::Other("provider_added".into())
        );
        assert_eq!(item_type, ChargebeeItemType::Other("metered".into()));
        assert_eq!(serde_json::to_value(&status).unwrap(), "provider_added");
        assert_eq!(serde_json::to_value(&item_type).unwrap(), "metered");
        assert!(!status.is_active());
    }
}
