use super::InputError;
use crate::polar::{
    PolarOrderQuery, PolarPageQuery, PolarProductBillingType, PolarSubscriptionQuery,
};

#[derive(Debug, Clone, PartialEq)]
pub(in crate::polar::axum) struct SubscriptionsInput {
    pub(in crate::polar::axum) reference_id: Option<String>,
    pub(in crate::polar::axum) query: PolarSubscriptionQuery,
}

impl SubscriptionsInput {
    pub fn parse(raw: Option<&str>) -> Result<Self, InputError> {
        let values = query_values(raw);
        Ok(Self {
            reference_id: query_string(&values, "referenceId"),
            query: PolarSubscriptionQuery {
                page: query_number(&values, "page")?,
                limit: query_number(&values, "limit")?,
                active: query_boolean(&values, "active"),
            },
        })
    }
}

pub(in crate::polar::axum) fn page_query(raw: Option<&str>) -> Result<PolarPageQuery, InputError> {
    let values = query_values(raw);
    Ok(PolarPageQuery {
        page: query_number(&values, "page")?,
        limit: query_number(&values, "limit")?,
    })
}

pub(in crate::polar::axum) fn order_query(
    raw: Option<&str>,
) -> Result<PolarOrderQuery, InputError> {
    let values = query_values(raw);
    let product_billing_type = match query_string(&values, "productBillingType").as_deref() {
        None => None,
        Some("recurring") => Some(PolarProductBillingType::Recurring),
        Some("one_time") => Some(PolarProductBillingType::OneTime),
        Some(_) => return Err(InputError::new("productBillingType is invalid")),
    };
    Ok(PolarOrderQuery {
        page: query_number(&values, "page")?,
        limit: query_number(&values, "limit")?,
        product_billing_type,
    })
}

fn query_values(raw: Option<&str>) -> Vec<(String, String)> {
    raw.and_then(|raw| serde_urlencoded::from_str(raw).ok())
        .unwrap_or_default()
}

fn query_string(values: &[(String, String)], key: &str) -> Option<String> {
    values
        .iter()
        .find(|(candidate, _)| candidate == key)
        .map(|(_, value)| value.clone())
}

fn query_number(values: &[(String, String)], key: &str) -> Result<Option<f64>, InputError> {
    query_string(values, key)
        .map(|value| js_number(&value, key))
        .transpose()
}

fn js_number(value: &str, field: &str) -> Result<f64, InputError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(0.0);
    }
    let parsed = if let Some(value) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        radix_number(value, 16)
    } else if let Some(value) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        radix_number(value, 2)
    } else if let Some(value) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        radix_number(value, 8)
    } else {
        trimmed
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
    };
    parsed.ok_or_else(|| InputError::new(format!("{field} must coerce to a number")))
}

fn radix_number(value: &str, radix: u32) -> Option<f64> {
    i64::from_str_radix(value, radix)
        .ok()
        .map(|value| value as f64)
}

fn query_boolean(values: &[(String, String)], key: &str) -> Option<bool> {
    query_string(values, key).map(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coercion_matches_javascript_number_and_boolean() {
        let input = SubscriptionsInput::parse(Some("page=1.5&limit=0x10&active=false")).unwrap();
        assert_eq!(input.query.page, Some(1.5));
        assert_eq!(input.query.limit, Some(16.0));
        assert_eq!(input.query.active, Some(true));
    }
}
