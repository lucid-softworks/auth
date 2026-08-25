use super::*;
use serde_json::json;

#[test]
fn portal_validation_strips_unknown_fields() {
    assert_eq!(
        normalize_portal(json!({
            "customer_portal_link": "https://portal.test",
            "extra": true
        })),
        Ok((
            "https://portal.test".into(),
            json!({"customerPortalLink": "https://portal.test"})
        ))
    );
    assert!(normalize_portal(json!({})).is_err());
}

#[test]
fn sdk_dates_are_utc_millisecond_iso_strings() {
    let value = serde_json::from_value::<CustomerEntity>(json!({
        "id": "customer_1",
        "mode": "test",
        "object": "customer",
        "email": "user@example.com",
        "country": null,
        "created_at": "2026-01-01T01:00:00+01:00",
        "updated_at": "2026-01-01T00:00:00Z"
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_value(value).unwrap()["createdAt"],
        "2026-01-01T00:00:00.000Z"
    );
}

#[test]
fn required_nullable_fields_must_be_present() {
    let customer = serde_json::from_value::<CustomerOrId>(json!({
        "id": "customer_1",
        "mode": "test",
        "object": "customer",
        "email": "user@example.com",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    }))
    .unwrap();
    assert!(customer.validate().is_err());
}
