use super::common::*;
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DodoLegacyCheckoutInput {
    pub(crate) body: Map<String, Value>,
}

impl DodoLegacyCheckoutInput {
    pub(crate) fn slug(&self) -> Option<&str> {
        string(&self.body, "slug")
    }

    pub(crate) fn reference_id(&self) -> Option<&str> {
        string(&self.body, "referenceId")
    }

    pub(crate) fn into_body(self) -> Map<String, Value> {
        self.body
    }
}

pub(crate) fn parse_legacy_checkout(
    value: Value,
) -> Result<DodoLegacyCheckoutInput, DodoInputError> {
    let mut body = root_object(value)?;
    require_together(&body, &["billing", "customer"])?;
    optional_string(&body, "product_id", "body.product_id", false)?;
    optional_number(&body, "quantity", "body.quantity", NumberRule::Any, false)?;
    for key in [
        "discount_id",
        "currency",
        "discount_code",
        "slug",
        "referenceId",
    ] {
        optional_string(&body, key, &format!("body.{key}"), false)?;
    }
    normalize_discount_codes(&mut body, "discount_codes", "body.discount_codes", false)?;
    normalize_record(&mut body, "metadata", "body.metadata", false)?;
    normalize_billing(&mut body)?;
    normalize_customer(&mut body)?;
    normalize_cart(&mut body, "product_cart")?;
    normalize_cart(&mut body, "addons")?;
    Ok(DodoLegacyCheckoutInput { body })
}

fn normalize_billing(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let value = body.get_mut("billing").expect("required field checked");
    let map = object_mut_at(value, "body.billing")?;
    require_together(map, &["city", "country", "state", "street", "zipcode"])
        .map_err(|error| prefix_nested_error(error, "billing"))?;
    for key in ["city", "country", "state", "street", "zipcode"] {
        optional_string(map, key, &format!("body.billing.{key}"), false)?;
    }
    map.retain(|key, _| ["city", "country", "state", "street", "zipcode"].contains(&key.as_str()));
    Ok(())
}

fn normalize_customer(body: &mut Map<String, Value>) -> Result<(), DodoInputError> {
    let value = body.get_mut("customer").expect("required field checked");
    let map = object_mut_at(value, "body.customer")?;
    for key in ["customer_id", "email", "name"] {
        optional_string(map, key, &format!("body.customer.{key}"), false)?;
    }
    map.retain(|key, _| ["customer_id", "email", "name"].contains(&key.as_str()));
    Ok(())
}

fn normalize_cart(body: &mut Map<String, Value>, key: &str) -> Result<(), DodoInputError> {
    let Some(value) = body.get_mut(key) else {
        return Ok(());
    };
    let items = array_mut_at(value, &format!("body.{key}"))?;
    let id_key = if key == "addons" {
        "addon_id"
    } else {
        "product_id"
    };
    for (index, item) in items.iter_mut().enumerate() {
        let path = format!("body.{key}.{index}");
        let map = object_mut_at(item, &path)?;
        require_nested(map, id_key, &path)?;
        require_nested(map, "quantity", &path)?;
        optional_string(map, id_key, &format!("{path}.{id_key}"), false)?;
        optional_number(
            map,
            "quantity",
            &format!("{path}.quantity"),
            NumberRule::Any,
            false,
        )?;
        map.retain(|field, _| field == id_key || field == "quantity");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preserves_only_the_upstream_catchall_boundary() {
        let parsed = parse_legacy_checkout(json!({
            "product_id":"product_1","quantity":1.5,
            "billing":{"city":"C","country":"US","state":"S","street":"X","zipcode":"Z","unknown":true},
            "customer":{"customer_id":"customer_1","email":"user@example.com","name":"User","unknown":true},
            "product_cart":[{"product_id":"product_2","quantity":2,"unknown":true}],
            "addons":[{"addon_id":"addon_1","quantity":0.5,"unknown":true}],
            "metadata":{"text":"yes","number":2,"boolean":false},
            "discount_code":"ONE","discount_codes":["TWO"],"slug":"pro",
            "referenceId":"reference_1","future_top_level":{"retained":true}
        }))
        .unwrap();
        assert_eq!(parsed.slug(), Some("pro"));
        assert_eq!(parsed.reference_id(), Some("reference_1"));
        assert_eq!(parsed.body["future_top_level"], json!({"retained":true}));
        assert!(parsed.body["billing"].get("unknown").is_none());
        assert!(parsed.body["customer"].get("unknown").is_none());
        assert!(parsed.body["product_cart"][0].get("unknown").is_none());
        assert_eq!(parsed.into_body()["discount_codes"], json!(["TWO"]));
    }

    #[test]
    fn aggregates_required_fields_and_enforces_metadata_values() {
        assert_eq!(
            parse_legacy_checkout(json!({})).unwrap_err().message(),
            "[body.billing] Required; [body.customer] Required"
        );
        let invalid = json!({
            "billing":{"city":"C","country":"US","state":"S","street":"X","zipcode":"Z"},
            "customer":{},"metadata":{"nested":{"not":"allowed"}}
        });
        assert_eq!(
            parse_legacy_checkout(invalid).unwrap_err().message(),
            "[body.metadata.nested] Expected string, number, or boolean, received object"
        );
    }
}
