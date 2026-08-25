use super::super::{PolarRouteState, input::CheckoutInput, support};
use crate::{AxumPluginRoute, polar::PolarCheckoutCreate};
use axum::{
    Extension, Json,
    extract::OriginalUri,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::{Map, Value, json};

pub(super) fn route(state: PolarRouteState) -> AxumPluginRoute {
    AxumPluginRoute::new("/checkout", post(handle).layer(Extension(state)))
}

async fn handle(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match CheckoutInput::parse(body) {
        Ok(input) => input,
        Err(error) => return support::bad_input(error),
    };
    let options = state
        .checkout
        .as_ref()
        .expect("checkout route requires checkout options");
    // The pinned adapter loads the optional session before invoking a dynamic
    // product resolver, but defers auth enforcement until after slug lookup.
    let session = support::optional_session(&service, &headers).await;
    let products = match selected_products(options, &input).await {
        Ok(products) => products,
        Err(response) => return *response,
    };
    if options.authenticated_users_only {
        let Some(session) = session.as_ref() else {
            return support::unauthorized("You must be logged in to checkout");
        };
        if session.user.is_anonymous {
            return support::unauthorized("Anonymous users are not allowed to checkout");
        }
    }

    let metadata = checkout_metadata(&input);
    let success_url = input
        .success_url
        .as_deref()
        .or(options.success_url.as_deref());
    let return_url = input
        .return_url
        .as_deref()
        .or(options.return_url.as_deref());
    let result = async {
        let success_url = support::callback_url(&service, &headers, &uri, success_url)?;
        let return_url = support::callback_url(&service, &headers, &uri, return_url)?;
        let checkout = state
            .client
            .create_checkout(PolarCheckoutCreate {
                external_customer_id: session.as_ref().map(|session| session.user.id.to_string()),
                products,
                success_url,
                return_url,
                metadata,
                custom_field_data: input.custom_field_data,
                allow_discount_codes: input.allow_discount_codes,
                discount_id: input.discount_id,
                embed_origin: input.embed_origin,
                allow_trial: input.allow_trial,
                trial_interval: input.trial_interval,
                trial_interval_count: input.trial_interval_count,
            })
            .await
            .map_err(CheckoutFailure::Provider)?;
        let url = support::themed_url(
            &checkout.url,
            options.theme.map(crate::polar::PolarTheme::as_str),
        )?;
        Ok::<_, CheckoutFailure>(url)
    }
    .await;
    match result {
        Ok(url) => Json(json!({ "url": url, "redirect": input.redirect })).into_response(),
        Err(error) => {
            tracing::error!(message = %error, "Polar checkout creation failed");
            support::internal("Checkout creation failed")
        }
    }
}

async fn selected_products(
    options: &crate::polar::CheckoutOptions,
    input: &CheckoutInput,
) -> Result<Vec<String>, Box<Response>> {
    let Some(slug) = input.slug.as_deref().filter(|slug| !slug.is_empty()) else {
        return Ok(input.products.clone().unwrap_or_default());
    };
    let products = match &options.products {
        Some(products) => products.resolve().await.map_err(|error| {
            tracing::error!(message = %error, "Polar products callback failed");
            Box::new(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        })?,
        None => Vec::new(),
    };
    products
        .into_iter()
        .find(|product| product.slug == slug)
        .map(|product| vec![product.product_id])
        .ok_or_else(|| Box::new(support::bad_request("Product not found")))
}

fn checkout_metadata(input: &CheckoutInput) -> Option<Map<String, Value>> {
    let mut metadata = Map::new();
    if let Some(reference_id) = input
        .reference_id
        .as_deref()
        .filter(|reference_id| !reference_id.is_empty())
    {
        metadata.insert("referenceId".into(), Value::String(reference_id.into()));
    }
    if let Some(fields) = &input.metadata {
        for (key, value) in fields {
            metadata.insert(key.clone(), value.clone());
        }
    }
    (!metadata.is_empty() || input.metadata.is_some()).then_some(metadata)
}

#[derive(Debug, thiserror::Error)]
enum CheckoutFailure {
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error(transparent)]
    Provider(crate::polar::PolarProviderError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_metadata_overwrites_synthetic_reference_id() {
        let input = CheckoutInput::parse(json!({
            "referenceId": "synthetic",
            "metadata": { "referenceId": "body", "tier": 2 }
        }))
        .unwrap();
        let metadata = checkout_metadata(&input).unwrap();
        assert_eq!(metadata["referenceId"], "body");
        assert_eq!(metadata["tier"], 2);
    }

    #[test]
    fn absent_metadata_stays_absent_but_an_explicit_empty_map_is_forwarded() {
        assert_eq!(
            checkout_metadata(&CheckoutInput::parse(json!({})).unwrap()),
            None
        );
        assert_eq!(
            checkout_metadata(&CheckoutInput::parse(json!({ "metadata": {} })).unwrap()),
            Some(Map::new())
        );
    }
}
