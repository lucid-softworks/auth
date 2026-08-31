use crate::stripe::model::CustomerType;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Better Auth 1.7.2's `/subscription/upgrade` request body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeSubscriptionInput {
    pub plan: String,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub annual: Option<bool>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub reference_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub subscription_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub customer_type: Option<CustomerType>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub metadata: Option<Map<String, Value>>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub seats: Option<f64>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub locale: Option<String>,
    #[serde(default = "root_path")]
    pub success_url: String,
    #[serde(default = "root_path")]
    pub cancel_url: String,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub return_url: Option<String>,
    #[serde(default)]
    pub schedule_at_period_end: bool,
    #[serde(default)]
    pub disable_redirect: bool,
}

impl UpgradeSubscriptionInput {
    pub fn effective_customer_type(&self) -> CustomerType {
        self.customer_type.unwrap_or_default()
    }
}

/// Better Auth 1.7.2's `/subscription/cancel` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelSubscriptionInput {
    #[serde(default, deserialize_with = "optional_non_null")]
    pub reference_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub subscription_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub customer_type: Option<CustomerType>,
    pub return_url: String,
    #[serde(default)]
    pub disable_redirect: bool,
}

impl CancelSubscriptionInput {
    pub fn effective_customer_type(&self) -> CustomerType {
        self.customer_type.unwrap_or_default()
    }
}

/// Better Auth 1.7.2's `/subscription/restore` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreSubscriptionInput {
    #[serde(default, deserialize_with = "optional_non_null")]
    pub reference_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub subscription_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub customer_type: Option<CustomerType>,
}

impl RestoreSubscriptionInput {
    pub fn effective_customer_type(&self) -> CustomerType {
        self.customer_type.unwrap_or_default()
    }
}

/// Better Auth 1.7.2's optional `/subscription/list` query.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListSubscriptionsQuery {
    #[serde(default, deserialize_with = "optional_non_null")]
    pub reference_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub customer_type: Option<CustomerType>,
}

impl ListSubscriptionsQuery {
    pub fn effective_customer_type(&self) -> CustomerType {
        self.customer_type.unwrap_or_default()
    }
}

/// Better Auth 1.7.2's `/subscription/billing-portal` request body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BillingPortalInput {
    #[serde(default, deserialize_with = "optional_non_null")]
    pub locale: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub reference_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub customer_type: Option<CustomerType>,
    #[serde(default = "root_path")]
    pub return_url: String,
    #[serde(default)]
    pub disable_redirect: bool,
}

impl BillingPortalInput {
    pub fn effective_customer_type(&self) -> CustomerType {
        self.customer_type.unwrap_or_default()
    }
}

/// Arbitrary query record accepted by `/subscription/success`.
///
/// Only the two exact Better Auth keys exposed by the accessors below affect
/// built-in behavior. Other keys remain available to compatibility tooling but
/// aliases such as `callbackUrl` intentionally do not become callbacks.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubscriptionSuccessQuery(BTreeMap<String, Value>);

impl SubscriptionSuccessQuery {
    pub fn values(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    pub fn callback_url(&self) -> Option<&str> {
        non_empty_string(self.0.get("callbackURL"))
    }

    pub fn checkout_session_id(&self) -> Option<&str> {
        non_empty_string(self.0.get("checkoutSessionId"))
    }

    pub fn effective_callback_url(&self) -> &str {
        self.callback_url().unwrap_or("/")
    }

    /// Resolves Stripe's literal placeholder after the caller has performed
    /// the upstream session check. `None` means the checkout id was absent.
    pub fn callback_with_checkout_session(&self) -> Option<String> {
        let checkout_session_id = self.checkout_session_id()?;
        Some(
            self.effective_callback_url()
                .replace("{CHECKOUT_SESSION_ID}", checkout_session_id),
        )
    }
}

fn non_empty_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn root_path() -> String {
    "/".into()
}

/// Zod's `.optional()` accepts an absent field but rejects explicit `null`.
/// Serde's normal `Option<T>` handling accepts both, so wire inputs use this
/// deserializer together with `#[serde(default)]` to preserve the distinction.
fn optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn upgrade_applies_only_the_zod_defaults() {
        let input: UpgradeSubscriptionInput =
            serde_json::from_value(json!({ "plan": "Pro" })).expect("minimal request should parse");

        assert_eq!(input.plan, "Pro");
        assert_eq!(input.success_url, "/");
        assert_eq!(input.cancel_url, "/");
        assert!(!input.schedule_at_period_end);
        assert!(!input.disable_redirect);
        assert_eq!(input.effective_customer_type(), CustomerType::User);
        assert_eq!(input.annual, None);
    }

    #[test]
    fn upgrade_preserves_arbitrary_metadata_and_fractional_seats() {
        let input: UpgradeSubscriptionInput = serde_json::from_value(json!({
            "plan": "pro",
            "customerType": "organization",
            "metadata": { "nested": [1, true], "nullable": null },
            "seats": 1.5,
            "locale": "ko",
            "successUrl": "/done",
            "cancelUrl": "/pricing",
            "returnUrl": "/account",
            "scheduleAtPeriodEnd": true,
            "disableRedirect": true
        }))
        .expect("complete request should parse");

        assert_eq!(input.effective_customer_type(), CustomerType::Organization);
        assert_eq!(input.seats, Some(1.5));
        assert_eq!(
            input.metadata.expect("metadata")["nested"],
            json!([1, true])
        );
        assert!(input.schedule_at_period_end);
        assert!(input.disable_redirect);
    }

    #[test]
    fn optional_fields_reject_explicit_null_like_zod() {
        let error = serde_json::from_value::<UpgradeSubscriptionInput>(json!({
            "plan": "pro",
            "annual": null
        }))
        .expect_err("explicit null is not optional undefined");

        assert!(error.to_string().contains("boolean"));
    }

    #[test]
    fn customer_type_rejects_unrecognized_values() {
        let result = serde_json::from_value::<RestoreSubscriptionInput>(json!({
            "customerType": "team"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn cancel_requires_return_url_and_defaults_redirect() {
        assert!(serde_json::from_value::<CancelSubscriptionInput>(json!({})).is_err());
        let input: CancelSubscriptionInput =
            serde_json::from_value(json!({ "returnUrl": "/account" }))
                .expect("return URL satisfies the schema");
        assert_eq!(input.return_url, "/account");
        assert!(!input.disable_redirect);
    }

    #[test]
    fn portal_defaults_match_the_pinned_schema() {
        let input: BillingPortalInput =
            serde_json::from_value(json!({})).expect("all fields have defaults or are optional");
        assert_eq!(input.return_url, "/");
        assert!(!input.disable_redirect);
        assert_eq!(input.effective_customer_type(), CustomerType::User);
    }

    #[test]
    fn success_uses_only_exact_case_sensitive_keys() {
        let query: SubscriptionSuccessQuery = serde_json::from_value(json!({
            "callbackUrl": "/wrong",
            "callback_url": "/also-wrong",
            "checkout_session_id": "cs_wrong",
            "arbitrary": [1, 2]
        }))
        .expect("the success query accepts an arbitrary record");

        assert_eq!(query.callback_url(), None);
        assert_eq!(query.checkout_session_id(), None);
        assert_eq!(query.effective_callback_url(), "/");
        assert!(query.values().contains_key("arbitrary"));
    }

    #[test]
    fn success_replaces_every_literal_checkout_placeholder() {
        let query: SubscriptionSuccessQuery = serde_json::from_value(json!({
            "callbackURL": "/done/{CHECKOUT_SESSION_ID}/{CHECKOUT_SESSION_ID}",
            "checkoutSessionId": "cs_123"
        }))
        .expect("valid success query");

        assert_eq!(
            query.callback_with_checkout_session().as_deref(),
            Some("/done/cs_123/cs_123")
        );
    }

    #[test]
    fn success_keeps_the_placeholder_until_checkout_id_exists() {
        let query: SubscriptionSuccessQuery = serde_json::from_value(json!({
            "callbackURL": "/done/{CHECKOUT_SESSION_ID}"
        }))
        .expect("valid success query");

        assert_eq!(
            query.effective_callback_url(),
            "/done/{CHECKOUT_SESSION_ID}"
        );
        assert_eq!(query.callback_with_checkout_session(), None);
    }
}
