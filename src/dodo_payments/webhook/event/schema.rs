use crate::dodo_payments::DodoWebhookEventType as Event;
use serde::de::DeserializeOwned;
use serde_json::Value;

mod commerce;
mod common;
mod lifecycle;
mod projection;
mod subscription;

pub(super) fn normalize(event: Event, data: &Value) -> Result<Value, ()> {
    match event {
        Event::PaymentSucceeded
        | Event::PaymentFailed
        | Event::PaymentProcessing
        | Event::PaymentCancelled => validated::<commerce::Payment>(data, commerce::payment),
        Event::RefundSucceeded | Event::RefundFailed => {
            validated::<commerce::Refund>(data, commerce::refund)
        }
        Event::DisputeOpened
        | Event::DisputeExpired
        | Event::DisputeAccepted
        | Event::DisputeCancelled
        | Event::DisputeChallenged
        | Event::DisputeWon
        | Event::DisputeLost => validated::<commerce::Dispute>(data, commerce::dispute),
        Event::SubscriptionActive
        | Event::SubscriptionOnHold
        | Event::SubscriptionRenewed
        | Event::SubscriptionPlanChanged
        | Event::SubscriptionCancelled
        | Event::SubscriptionFailed
        | Event::SubscriptionExpired
        | Event::SubscriptionUpdated
        | Event::SubscriptionPaused
        | Event::SubscriptionUnpaused
        | Event::SubscriptionUpdatePaymentMethod => {
            validated::<subscription::Subscription>(data, subscription::subscription)
        }
        Event::LicenseKeyCreated => validated::<commerce::LicenseKey>(data, commerce::license_key),
        Event::AbandonedCheckoutDetected | Event::AbandonedCheckoutRecovered => {
            validated::<lifecycle::AbandonedCheckout>(data, lifecycle::abandoned_checkout)
        }
        Event::DunningStarted | Event::DunningRecovered => {
            validated::<lifecycle::DunningAttempt>(data, lifecycle::dunning_attempt)
        }
        Event::CreditAdded
        | Event::CreditDeducted
        | Event::CreditExpired
        | Event::CreditRolledOver
        | Event::CreditRolloverForfeited
        | Event::CreditOverageCharged
        | Event::CreditOverageReset
        | Event::CreditManualAdjustment => {
            validated::<lifecycle::CreditLedgerEntry>(data, lifecycle::credit_ledger_entry)
        }
        Event::CreditBalanceLow => {
            validated::<lifecycle::CreditBalanceLow>(data, lifecycle::credit_balance_low)
        }
        Event::EntitlementGrantCreated
        | Event::EntitlementGrantDelivered
        | Event::EntitlementGrantFailed
        | Event::EntitlementGrantRevoked => {
            validated::<lifecycle::EntitlementGrant>(data, lifecycle::entitlement_grant)
        }
        Event::PayoutCreated
        | Event::PayoutOnHold
        | Event::PayoutInProgress
        | Event::PayoutFailed
        | Event::PayoutSuccess => validated::<commerce::Payout>(data, commerce::payout),
        Event::Unknown => Ok(data.clone()),
    }
}

fn validated<T: DeserializeOwned>(data: &Value, project: fn(&Value) -> Value) -> Result<Value, ()> {
    serde_json::from_value::<T>(data.clone()).map_err(|_| ())?;
    Ok(project(data))
}
