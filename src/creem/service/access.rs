use crate::creem::CreemSubscription;
#[cfg(feature = "axum")]
use crate::creem::{CreemStore, CreemStoreError};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreemAccessSubscription {
    pub id: String,
    pub status: String,
    pub product_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_end: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreemAccessDecision {
    pub has_access_granted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription: Option<CreemAccessSubscription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriptions: Option<Vec<CreemAccessSubscription>>,
}

#[cfg(feature = "axum")]
pub(crate) async fn check_access(
    store: &dyn CreemStore,
    reference_id: &str,
    now: DateTime<Utc>,
) -> Result<CreemAccessDecision, CreemStoreError> {
    let subscriptions = store.list_subscriptions_by_reference(reference_id).await?;
    Ok(evaluate_access(&subscriptions, now))
}

pub(crate) fn evaluate_access(
    subscriptions: &[CreemSubscription],
    now: DateTime<Utc>,
) -> CreemAccessDecision {
    if subscriptions.is_empty() {
        return denied("No subscriptions found for this user", None);
    }
    for subscription in subscriptions {
        let status = subscription.status.to_lowercase();
        if ["active", "trialing", "paid"].contains(&status.as_str()) {
            return granted(subscription, None);
        }
        if ["canceled", "past_due", "unpaid"].contains(&status.as_str())
            && let Some(period_end) = subscription.period_end
            && period_end > now
        {
            let formatted = format_date(period_end);
            return granted(
                subscription,
                Some(format!(
                    "Subscription is {status} but access granted until {formatted}"
                )),
            );
        }
    }
    denied(
        "No active subscriptions found",
        Some(subscriptions.iter().map(compact).collect()),
    )
}

fn granted(subscription: &CreemSubscription, message: Option<String>) -> CreemAccessDecision {
    CreemAccessDecision {
        has_access_granted: true,
        message,
        subscription: Some(compact(subscription)),
        subscriptions: None,
    }
}

fn denied(
    message: impl Into<String>,
    subscriptions: Option<Vec<CreemAccessSubscription>>,
) -> CreemAccessDecision {
    CreemAccessDecision {
        has_access_granted: false,
        message: Some(message.into()),
        subscription: None,
        subscriptions,
    }
}

fn compact(subscription: &CreemSubscription) -> CreemAccessSubscription {
    CreemAccessSubscription {
        id: subscription.id.to_string(),
        status: subscription.status.clone(),
        product_id: subscription.product_id.clone(),
        period_end: subscription.period_end.map(format_date),
    }
}

fn format_date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;

    #[test]
    fn immediate_access_statuses_are_case_insensitive() {
        let now = Utc::now();
        for status in ["ACTIVE", "Trialing", "paid"] {
            let decision = evaluate_access(&[subscription(status, None)], now);
            assert!(decision.has_access_granted);
            assert!(decision.message.is_none());
        }
    }

    #[test]
    fn limited_statuses_grant_only_before_period_end() {
        let now = DateTime::parse_from_rfc3339("2026-08-25T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for status in ["canceled", "PAST_DUE", "Unpaid"] {
            let decision = evaluate_access(
                &[subscription(status, Some(now + TimeDelta::seconds(1)))],
                now,
            );
            assert!(decision.has_access_granted);
            assert_eq!(
                decision.message.as_deref(),
                Some(
                    format!(
                        "Subscription is {} but access granted until 2026-08-25T12:00:01.000Z",
                        status.to_lowercase()
                    )
                    .as_str()
                )
            );
        }
        assert!(!evaluate_access(&[subscription("unpaid", Some(now))], now).has_access_granted);
        assert!(!evaluate_access(&[subscription("unpaid", None)], now).has_access_granted);
    }

    #[test]
    fn denial_includes_every_compact_row_in_store_order() {
        let now = Utc::now();
        let rows = [subscription("pending", None), subscription("expired", None)];
        let decision = evaluate_access(&rows, now);
        assert!(!decision.has_access_granted);
        let compact = decision.subscriptions.unwrap();
        assert_eq!(compact.len(), 2);
        assert_eq!(compact[0].status, "pending");
        assert_eq!(compact[1].status, "expired");
    }

    fn subscription(status: &str, period_end: Option<DateTime<Utc>>) -> CreemSubscription {
        let mut subscription = CreemSubscription::new("product", "owner");
        subscription.status = status.into();
        subscription.period_end = period_end;
        subscription
    }
}
