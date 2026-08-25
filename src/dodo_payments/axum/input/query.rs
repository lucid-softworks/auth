use super::common::{DodoInputError, error};
use crate::dodo_payments::provider::{
    DodoPaymentListRequest, DodoPaymentStatus, DodoSubscriptionListRequest, DodoSubscriptionStatus,
};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DodoSubscriptionQuery {
    page: Option<f64>,
    limit: Option<f64>,
    status: Option<DodoSubscriptionStatus>,
}

impl DodoSubscriptionQuery {
    pub(crate) fn into_provider(self, customer_id: String) -> DodoSubscriptionListRequest {
        DodoSubscriptionListRequest {
            customer_id,
            page_number: upstream_page_number(self.page),
            page_size: self.limit,
            status: self.status,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DodoPaymentQuery {
    page: Option<f64>,
    limit: Option<f64>,
    status: Option<DodoPaymentStatus>,
}

impl DodoPaymentQuery {
    pub(crate) fn into_provider(self, customer_id: String) -> DodoPaymentListRequest {
        DodoPaymentListRequest {
            customer_id,
            page_number: upstream_page_number(self.page),
            page_size: self.limit,
            status: self.status,
        }
    }
}

pub(crate) fn parse_subscription_query(
    raw: Option<&str>,
) -> Result<DodoSubscriptionQuery, DodoInputError> {
    let query = query_map(raw)?;
    Ok(DodoSubscriptionQuery {
        page: query_number(&query, "page")?,
        limit: query_number(&query, "limit")?,
        status: query.get("status").map(subscription_status).transpose()?,
    })
}

pub(crate) fn parse_payment_query(raw: Option<&str>) -> Result<DodoPaymentQuery, DodoInputError> {
    let query = query_map(raw)?;
    Ok(DodoPaymentQuery {
        page: query_number(&query, "page")?,
        limit: query_number(&query, "limit")?,
        status: query.get("status").map(payment_status).transpose()?,
    })
}

pub(super) fn query_map(raw: Option<&str>) -> Result<Map<String, Value>, DodoInputError> {
    let pairs = serde_urlencoded::from_str::<Vec<(String, String)>>(raw.unwrap_or_default())
        .map_err(|_| error("[query] Invalid query parameters".into()))?;
    Ok(pairs
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect())
}

pub(super) fn query_number(
    query: &Map<String, Value>,
    key: &str,
) -> Result<Option<f64>, DodoInputError> {
    let Some(raw) = query.get(key).and_then(Value::as_str) else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    let parsed = if trimmed.is_empty() {
        Some(0.0)
    } else if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok().map(|value| value as f64)
    } else if let Some(binary) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        u64::from_str_radix(binary, 2)
            .ok()
            .map(|value| value as f64)
    } else if let Some(octal) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        u64::from_str_radix(octal, 8).ok().map(|value| value as f64)
    } else {
        trimmed.parse::<f64>().ok()
    };
    parsed
        .filter(|value| value.is_finite())
        .map(Some)
        .ok_or_else(|| error(format!("[query.{key}] Expected number, received nan")))
}

pub(super) fn query_string(query: &Map<String, Value>, key: &str) -> Option<String> {
    query.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn upstream_page_number(page: Option<f64>) -> Option<f64> {
    page.filter(|page| *page != 0.0).map(|page| page - 1.0)
}

fn subscription_status(value: &Value) -> Result<DodoSubscriptionStatus, DodoInputError> {
    match value.as_str() {
        Some("active") => Ok(DodoSubscriptionStatus::Active),
        Some("cancelled") => Ok(DodoSubscriptionStatus::Cancelled),
        Some("on_hold") => Ok(DodoSubscriptionStatus::OnHold),
        Some("pending") => Ok(DodoSubscriptionStatus::Pending),
        Some("failed") => Ok(DodoSubscriptionStatus::Failed),
        Some("expired") => Ok(DodoSubscriptionStatus::Expired),
        Some(received) => Err(enum_error(
            "'active' | 'cancelled' | 'on_hold' | 'pending' | 'failed' | 'expired'",
            received,
        )),
        None => unreachable!("query values are strings"),
    }
}

fn payment_status(value: &Value) -> Result<DodoPaymentStatus, DodoInputError> {
    match value.as_str() {
        Some("succeeded") => Ok(DodoPaymentStatus::Succeeded),
        Some("failed") => Ok(DodoPaymentStatus::Failed),
        Some("cancelled") => Ok(DodoPaymentStatus::Cancelled),
        Some("processing") => Ok(DodoPaymentStatus::Processing),
        Some("requires_customer_action") => Ok(DodoPaymentStatus::RequiresCustomerAction),
        Some("requires_merchant_action") => Ok(DodoPaymentStatus::RequiresMerchantAction),
        Some("requires_payment_method") => Ok(DodoPaymentStatus::RequiresPaymentMethod),
        Some("requires_confirmation") => Ok(DodoPaymentStatus::RequiresConfirmation),
        Some("requires_capture") => Ok(DodoPaymentStatus::RequiresCapture),
        Some("partially_captured") => Ok(DodoPaymentStatus::PartiallyCaptured),
        Some("partially_captured_and_capturable") => {
            Ok(DodoPaymentStatus::PartiallyCapturedAndCapturable)
        }
        Some(received) => Err(enum_error(
            "'succeeded' | 'failed' | 'cancelled' | 'processing' | 'requires_customer_action' | 'requires_merchant_action' | 'requires_payment_method' | 'requires_confirmation' | 'requires_capture' | 'partially_captured' | 'partially_captured_and_capturable'",
            received,
        )),
        None => unreachable!("query values are strings"),
    }
}

fn enum_error(expected: &str, received: &str) -> DodoInputError {
    error(format!(
        "[query.status] Invalid enum value. Expected {expected}, received '{received}'"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coerces_numbers_and_applies_truthy_page_math() {
        let request = parse_subscription_query(Some("page=0&limit=10&status=on_hold&ignored=yes"))
            .unwrap()
            .into_provider("customer_1".into());
        assert_eq!(request.page_number, None);
        assert_eq!(request.page_size, Some(10.0));
        assert_eq!(request.status, Some(DodoSubscriptionStatus::OnHold));

        let request = parse_payment_query(Some(
            "page=2&limit=0x10&status=partially_captured_and_capturable",
        ))
        .unwrap()
        .into_provider("customer_1".into());
        assert_eq!(request.page_number, Some(1.0));
        assert_eq!(request.page_size, Some(16.0));
        assert_eq!(
            request.status,
            Some(DodoPaymentStatus::PartiallyCapturedAndCapturable)
        );
        assert_eq!(
            query_number(&query_map(Some("page=0b10")).unwrap(), "page").unwrap(),
            Some(2.0)
        );
        assert!(parse_subscription_query(Some("page=NaN")).is_err());
    }

    #[test]
    fn enum_failures_match_pinned_zod_messages() {
        assert_eq!(
            parse_payment_query(Some("status=refunded"))
                .unwrap_err()
                .message(),
            "[query.status] Invalid enum value. Expected 'succeeded' | 'failed' | 'cancelled' | 'processing' | 'requires_customer_action' | 'requires_merchant_action' | 'requires_payment_method' | 'requires_confirmation' | 'requires_capture' | 'partially_captured' | 'partially_captured_and_capturable', received 'refunded'"
        );
        assert_eq!(
            parse_subscription_query(Some("status=paused"))
                .unwrap_err()
                .message(),
            "[query.status] Invalid enum value. Expected 'active' | 'cancelled' | 'on_hold' | 'pending' | 'failed' | 'expired', received 'paused'"
        );
    }
}
