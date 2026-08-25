use crate::{
    SessionWithUser,
    dodo_payments::{DodoCheckoutOptions, DodoPaymentsClient},
};
use serde_json::{Map, Value, json};

#[derive(Debug, thiserror::Error)]
pub(crate) enum DodoCheckoutError {
    #[error("Product not found")]
    ProductNotFound,
    #[error("Neither product_cart nor slug was provided")]
    MissingCart,
    #[error("checkout product resolution failed: {0}")]
    ProductResolution(String),
    #[error("checkout provider request failed: {0}")]
    Provider(#[from] crate::dodo_payments::DodoPaymentsProviderError),
    #[error("checkout URL was missing")]
    MissingUrl,
    #[error("checkout URL was invalid")]
    InvalidUrl,
    #[error("checkout payload was invalid: {0}")]
    InvalidPayload(&'static str),
}

pub(crate) async fn resolve_product(
    options: &DodoCheckoutOptions,
    slug: Option<&str>,
) -> Result<Option<String>, DodoCheckoutError> {
    let Some(slug) = slug.filter(|slug| !slug.is_empty()) else {
        return Ok(None);
    };
    let products = match &options.products {
        Some(products) => products
            .resolve()
            .await
            .map_err(|error| DodoCheckoutError::ProductResolution(error.to_string()))?,
        None => Vec::new(),
    };
    products
        .into_iter()
        .find(|product| product.slug == slug)
        .map(|product| Some(product.product_id))
        .ok_or(DodoCheckoutError::ProductNotFound)
}

pub(crate) async fn create_checkout_session(
    client: &dyn DodoPaymentsClient,
    mut body: Map<String, Value>,
    resolved_product_id: Option<String>,
    reference_id: Option<String>,
    session: Option<&SessionWithUser>,
    configured_success_url: Option<String>,
) -> Result<String, DodoCheckoutError> {
    body.remove("slug");
    body.remove("referenceId");
    let product_cart = match resolved_product_id {
        Some(product_id) => vec![json!({"product_id": product_id, "quantity": 1})],
        None => body
            .get("product_cart")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };
    if product_cart.is_empty() {
        return Err(DodoCheckoutError::MissingCart);
    }
    body.insert("product_cart".into(), Value::Array(product_cart));
    if let Some(user) = session
        .map(|session| &session.user)
        .filter(|user| !user.email.is_empty())
    {
        body.insert(
            "customer".into(),
            json!({"email": user.email, "name": user.name}),
        );
    }
    merge_reference_metadata(&mut body, reference_id);
    match configured_success_url {
        Some(url) => {
            body.insert("return_url".into(), Value::String(url));
        }
        None => {
            body.remove("return_url");
        }
    }
    reject_combined_discounts(&body)?;
    let response = client.create_checkout_session(Value::Object(body)).await?;
    absolute_url(response.checkout_url)
}

pub(crate) async fn create_legacy_checkout(
    client: &dyn DodoPaymentsClient,
    mut body: Map<String, Value>,
    resolved_slug_product_id: Option<String>,
    reference_id: Option<String>,
    session: Option<&SessionWithUser>,
    configured_success_url: Option<String>,
) -> Result<String, DodoCheckoutError> {
    body.remove("slug");
    body.remove("referenceId");
    let product_id = resolved_slug_product_id.or_else(|| {
        body.get("product_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });

    let request_customer = body
        .get("customer")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut customer = Map::new();
    if let Some(user) = session.map(|session| &session.user) {
        customer.insert("email".into(), Value::String(user.email.clone()));
        customer.insert("name".into(), Value::String(user.name.clone()));
    }
    customer.extend(request_customer);
    body.insert("customer".into(), Value::Object(customer));
    match &product_id {
        Some(product_id) => {
            body.insert("product_id".into(), Value::String(product_id.clone()));
            body.insert(
                "product_cart".into(),
                json!([{"product_id": product_id, "quantity": 1}]),
            );
        }
        None => {
            body.remove("product_id");
            body.remove("product_cart");
        }
    }
    merge_reference_metadata(&mut body, reference_id);
    reject_combined_discounts(&body)?;

    let product_id = product_id.ok_or(DodoCheckoutError::InvalidPayload(
        "Missing required field: product_id or product_cart[0].product_id",
    ))?;
    let product = client.retrieve_product(&product_id).await?;
    let request = if product.is_recurring {
        subscription_request(&body, &product_id, configured_success_url)?
    } else {
        payment_request(&body, configured_success_url)?
    };
    let response = if product.is_recurring {
        client.create_subscription(request).await?
    } else {
        client.create_payment(request).await?
    };
    absolute_url(response.payment_link)
}

fn subscription_request(
    body: &Map<String, Value>,
    product_id: &str,
    configured_success_url: Option<String>,
) -> Result<Value, DodoCheckoutError> {
    let mut request = Map::from_iter([
        ("billing".into(), required(body, "billing")?.clone()),
        ("customer".into(), required(body, "customer")?.clone()),
        ("product_id".into(), Value::String(product_id.into())),
        (
            "quantity".into(),
            body.get("quantity")
                .filter(|value| js_truthy(value))
                .cloned()
                .unwrap_or(json!(1)),
        ),
    ]);
    copy_truthy(body, &mut request, "metadata");
    copy_discounts(body, &mut request);
    copy_truthy(body, &mut request, "addons");
    for field in [
        "allowed_payment_method_types",
        "billing_currency",
        "on_demand",
        "show_saved_payment_methods",
        "tax_id",
        "trial_period_days",
    ] {
        copy_truthy(body, &mut request, field);
    }
    request.insert("payment_link".into(), Value::Bool(true));
    copy_return_url(body, &mut request, configured_success_url);
    Ok(Value::Object(request))
}

fn payment_request(
    body: &Map<String, Value>,
    configured_success_url: Option<String>,
) -> Result<Value, DodoCheckoutError> {
    let mut request = Map::from_iter([
        ("billing".into(), required(body, "billing")?.clone()),
        ("customer".into(), required(body, "customer")?.clone()),
        (
            "product_cart".into(),
            required(body, "product_cart")?.clone(),
        ),
    ]);
    copy_truthy(body, &mut request, "metadata");
    request.insert("payment_link".into(), Value::Bool(true));
    for field in [
        "allowed_payment_method_types",
        "billing_currency",
        "show_saved_payment_methods",
        "tax_id",
    ] {
        copy_truthy(body, &mut request, field);
    }
    copy_discounts(body, &mut request);
    copy_return_url(body, &mut request, configured_success_url);
    Ok(Value::Object(request))
}

fn merge_reference_metadata(body: &mut Map<String, Value>, reference_id: Option<String>) {
    let Some(reference_id) = reference_id.filter(|reference_id| !reference_id.is_empty()) else {
        return;
    };
    let caller = body
        .get("metadata")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut metadata = Map::from_iter([("referenceId".into(), Value::String(reference_id))]);
    metadata.extend(caller);
    body.insert("metadata".into(), Value::Object(metadata));
}

fn reject_combined_discounts(body: &Map<String, Value>) -> Result<(), DodoCheckoutError> {
    let singular = body
        .get("discount_code")
        .and_then(Value::as_str)
        .is_some_and(|code| !code.is_empty());
    let stacked = body
        .get("discount_codes")
        .and_then(Value::as_array)
        .is_some_and(|codes| !codes.is_empty());
    if singular && stacked {
        return Err(DodoCheckoutError::InvalidPayload(
            "Cannot use both discount_code and discount_codes",
        ));
    }
    Ok(())
}

fn copy_discounts(body: &Map<String, Value>, target: &mut Map<String, Value>) {
    if body
        .get("discount_codes")
        .and_then(Value::as_array)
        .is_some_and(|codes| !codes.is_empty())
    {
        target.insert("discount_codes".into(), body["discount_codes"].clone());
    } else {
        copy_truthy(body, target, "discount_code");
    }
}

fn copy_return_url(
    body: &Map<String, Value>,
    target: &mut Map<String, Value>,
    configured: Option<String>,
) {
    if let Some(value) = body.get("return_url").filter(|value| js_truthy(value)) {
        target.insert("return_url".into(), value.clone());
    } else if let Some(value) = configured {
        target.insert("return_url".into(), Value::String(value));
    }
}

fn copy_truthy(body: &Map<String, Value>, target: &mut Map<String, Value>, field: &str) {
    if let Some(value) = body.get(field).filter(|value| js_truthy(value)) {
        target.insert(field.into(), value.clone());
    }
}

fn required<'a>(
    body: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, DodoCheckoutError> {
    body.get(field)
        .ok_or(DodoCheckoutError::InvalidPayload(field))
}

fn absolute_url(value: Option<String>) -> Result<String, DodoCheckoutError> {
    let value = value.ok_or(DodoCheckoutError::MissingUrl)?;
    url::Url::parse(&value)
        .map(|url| url.to_string())
        .map_err(|_| DodoCheckoutError::InvalidUrl)
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_metadata_is_written_first_and_caller_wins() {
        let mut body = Map::from_iter([(
            "metadata".into(),
            json!({"referenceId": "caller", "tier": 2}),
        )]);
        merge_reference_metadata(&mut body, Some("synthetic".into()));
        assert_eq!(body["metadata"]["referenceId"], "caller");
        assert_eq!(body["metadata"]["tier"], 2);
    }

    #[test]
    fn legacy_return_url_uses_body_truthiness_then_configuration() {
        let body = Map::from_iter([("return_url".into(), Value::String(String::new()))]);
        let mut request = Map::new();
        copy_return_url(&body, &mut request, Some("https://configured.test".into()));
        assert_eq!(request["return_url"], "https://configured.test");
    }
}
