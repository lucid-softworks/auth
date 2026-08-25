use serde::Serialize;
use serde_json::Value;

/// URL response shared by existing-subscription changes and Billing Portal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UrlRedirectResponse {
    pub url: String,
    pub redirect: bool,
}

/// A newly-created Stripe Checkout Session with Better Auth's `redirect`
/// field added after the provider object is spread into the response.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CheckoutSessionResponse<T>
where
    T: Serialize,
{
    #[serde(flatten)]
    pub session: T,
    pub redirect: bool,
}

/// Current-plan decoration applied only by `/subscription/list`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListedSubscription<T>
where
    T: Serialize,
{
    #[serde(flatten)]
    pub subscription: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checkout_response_flattens_the_full_provider_object() {
        let response = CheckoutSessionResponse {
            session: json!({
                "id": "cs_123",
                "object": "checkout.session",
                "url": "https://checkout.stripe.test/cs_123",
                "metadata": { "subscriptionId": "sub_local" }
            }),
            redirect: true,
        };

        assert_eq!(
            serde_json::to_value(response).expect("response serializes"),
            json!({
                "id": "cs_123",
                "object": "checkout.session",
                "url": "https://checkout.stripe.test/cs_123",
                "metadata": { "subscriptionId": "sub_local" },
                "redirect": true
            })
        );
    }

    #[test]
    fn list_omits_unresolved_lookup_key_projections() {
        let response = ListedSubscription {
            subscription: json!({ "id": "local_123", "plan": "pro" }),
            limits: None,
            price_id: None,
        };

        assert_eq!(
            serde_json::to_value(response).expect("response serializes"),
            json!({ "id": "local_123", "plan": "pro" })
        );
    }

    #[test]
    fn url_response_uses_the_exact_wire_shape() {
        let response = UrlRedirectResponse {
            url: "/account".into(),
            redirect: false,
        };
        assert_eq!(
            serde_json::to_value(response).expect("response serializes"),
            json!({ "url": "/account", "redirect": false })
        );
    }
}
