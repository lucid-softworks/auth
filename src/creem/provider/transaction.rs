use super::commerce::{EnvironmentMode, Nullable};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Deserialize, Serialize)]
enum TransactionType {
    #[serde(rename = "payment")]
    Payment,
    #[serde(rename = "invoice")]
    Invoice,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
enum TransactionStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "paid")]
    Paid,
    #[serde(rename = "refunded")]
    Refunded,
    #[serde(rename = "partialRefund")]
    PartialRefund,
    #[serde(rename = "chargedBack")]
    ChargedBack,
    #[serde(rename = "uncollectible")]
    Uncollectible,
    #[serde(rename = "declined")]
    Declined,
    #[serde(rename = "canceled")]
    Canceled,
    #[serde(rename = "void")]
    Void,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TransactionEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    amount: f64,
    #[serde(
        rename(deserialize = "amount_paid", serialize = "amountPaid"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    amount_paid: Nullable<f64>,
    #[serde(
        rename(deserialize = "discount_amount", serialize = "discountAmount"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    discount_amount: Nullable<f64>,
    currency: String,
    #[serde(rename = "type")]
    transaction_type: TransactionType,
    #[serde(
        rename(deserialize = "tax_country", serialize = "taxCountry"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    tax_country: Nullable<String>,
    #[serde(
        rename(deserialize = "tax_amount", serialize = "taxAmount"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    tax_amount: Nullable<f64>,
    status: TransactionStatus,
    #[serde(
        rename(deserialize = "refunded_amount", serialize = "refundedAmount"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    refunded_amount: Nullable<f64>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    order: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    subscription: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    customer: Nullable<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(
        rename(deserialize = "period_start", serialize = "periodStart"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    period_start: Option<f64>,
    #[serde(
        rename(deserialize = "period_end", serialize = "periodEnd"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    period_end: Option<f64>,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PaginationEntity {
    #[serde(rename(deserialize = "total_records", serialize = "totalRecords"))]
    total_records: f64,
    #[serde(rename(deserialize = "total_pages", serialize = "totalPages"))]
    total_pages: f64,
    #[serde(rename(deserialize = "current_page", serialize = "currentPage"))]
    current_page: f64,
    #[serde(rename(deserialize = "next_page", serialize = "nextPage"))]
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    next_page: Nullable<f64>,
    #[serde(rename(deserialize = "prev_page", serialize = "prevPage"))]
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    prev_page: Nullable<f64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct TransactionListEntity {
    items: Vec<TransactionEntity>,
    pagination: PaginationEntity,
}

pub(crate) fn normalize_transaction_page(
    value: Value,
    page: f64,
    limit: f64,
) -> Result<(Value, Option<f64>), ()> {
    let parsed: TransactionListEntity = serde_json::from_value(value).map_err(|_| ())?;
    if parsed.pagination.next_page.is_absent() || parsed.pagination.prev_page.is_absent() {
        return Err(());
    }
    let next_page = (parsed.pagination.total_pages > page
        && !parsed.items.is_empty()
        && parsed.items.len() as f64 >= limit)
        .then_some(page + 1.0);
    let result = serde_json::to_value(parsed).map_err(|_| ())?;
    let value = match next_page {
        Some(next) => json!({"result": result, "~next": {"page": next}}),
        None => json!({"result": result}),
    };
    Ok((value, next_page))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction() -> Value {
        json!({
            "id": "transaction_1",
            "mode": "test",
            "object": "transaction",
            "amount": 1000,
            "amount_paid": null,
            "currency": "USD",
            "type": "payment",
            "status": "paid",
            "created_at": 1720000000,
            "unknown": true
        })
    }

    #[test]
    fn normalizes_page_and_adds_enumerable_next_marker() {
        let (value, next) = normalize_transaction_page(
            json!({
                "items": [transaction()],
                "pagination": {
                    "total_records": 2,
                    "total_pages": 2,
                    "current_page": 1,
                    "next_page": 2,
                    "prev_page": null,
                    "unknown": true
                }
            }),
            1.0,
            1.0,
        )
        .unwrap();
        assert_eq!(next, Some(2.0));
        assert_eq!(value["~next"], json!({"page": 2.0}));
        assert_eq!(value["result"]["pagination"]["totalRecords"], 2.0);
        assert_eq!(value["result"]["items"][0]["createdAt"], 1720000000.0);
        assert_eq!(value["result"]["items"][0]["amountPaid"], Value::Null);
        assert!(value["result"]["items"][0].get("unknown").is_none());
    }

    #[test]
    fn requires_nullable_pagination_keys_and_full_pages() {
        let pagination = json!({
            "total_records": 2,
            "total_pages": 2,
            "current_page": 1,
            "next_page": 2,
            "prev_page": null
        });
        let (value, next) = normalize_transaction_page(
            json!({"items": [transaction()], "pagination": pagination}),
            1.0,
            10.0,
        )
        .unwrap();
        assert_eq!(next, None);
        assert!(value.get("~next").is_none());

        assert!(
            normalize_transaction_page(
                json!({
                    "items": [],
                    "pagination": {
                        "total_records": 0,
                        "total_pages": 1,
                        "current_page": 1,
                        "prev_page": null
                    }
                }),
                1.0,
                10.0
            )
            .is_err()
        );
    }
}
