use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, AutumnClient, AutumnOperation, AutumnOptions, AutumnPlugin, AutumnProviderError,
};
use serde_json::{Value, json};
use std::sync::Arc;
use url::Url;

#[derive(Debug)]
struct ConformanceAutumn;

pub(super) fn register(config: &mut AuthConfig) {
    let mut options = AutumnOptions::with_client(Arc::new(ConformanceAutumn));
    options.secret_key = Some("autumn_native_conformance_key".into());
    options.base_url = Some("https://autumn.example.test/native".into());
    config
        .add_plugin(AutumnPlugin::new(options))
        .expect("unique Autumn plugin");
}

#[async_trait]
impl AutumnClient for ConformanceAutumn {
    async fn execute(
        &self,
        operation: AutumnOperation,
        request: Value,
        secret_key: &str,
        base_url: &Url,
    ) -> Result<Value, AutumnProviderError> {
        assert_eq!(secret_key, "autumn_native_conformance_key");
        assert_eq!(base_url.as_str(), "https://autumn.example.test/native");
        let customer_id = request
            .get("customerId")
            .and_then(Value::as_str)
            .unwrap_or("anonymous");
        Ok(match operation {
            AutumnOperation::GetOrCreateCustomer => json!({
                "id": customer_id,
                "name": request.get("name").cloned().unwrap_or(json!(null)),
                "email": request.get("email").cloned().unwrap_or(json!(null)),
                "createdAt": 0,
                "fingerprint": null,
                "stripeId": null,
                "env": "live",
                "metadata": {},
                "sendEmailReceipts": false,
                "billingControls": {},
                "subscriptions": [],
                "purchases": [],
                "licenses": [],
                "balances": {},
                "flags": {}
            }),
            AutumnOperation::GetEntity => json!({
                "id": request["entityId"],
                "name": "Native entity",
                "customerId": customer_id,
                "featureId": null,
                "createdAt": 0,
                "env": "live",
                "subscriptions": [],
                "purchases": [],
                "balances": {},
                "flags": {}
            }),
            AutumnOperation::Attach => payment("attach", customer_id),
            AutumnOperation::UpdateSubscription => payment("update", customer_id),
            AutumnOperation::MultiAttach => payment("multi-attach", customer_id),
            AutumnOperation::PreviewAttach => preview(customer_id, false),
            AutumnOperation::PreviewUpdateSubscription => preview(customer_id, true),
            AutumnOperation::PreviewMultiAttach => preview(customer_id, false),
            AutumnOperation::OpenCustomerPortal => json!({
                "customerId": customer_id,
                "url": "https://autumn.example.test/native/portal"
            }),
            AutumnOperation::CreateReferralCode => json!({
                "code": "NATIVE-REFERRAL",
                "customerId": customer_id,
                "createdAt": 0
            }),
            AutumnOperation::RedeemReferralCode => json!({
                "id": "redemption_native",
                "customerId": customer_id,
                "rewardId": "reward_native"
            }),
            AutumnOperation::ListPlans => json!({ "list": [] }),
            AutumnOperation::ListEvents => json!({ "list": [], "nextCursor": "" }),
            AutumnOperation::AggregateEvents => json!({
                "list": [],
                "total": { "value": 0 }
            }),
            AutumnOperation::SetupPayment => json!({
                "customerId": customer_id,
                "url": "https://autumn.example.test/native/setup-payment"
            }),
        })
    }
}

fn payment(kind: &str, customer_id: &str) -> Value {
    json!({
        "customerId": customer_id,
        "paymentUrl": format!("https://autumn.example.test/native/{kind}")
    })
}

fn preview(customer_id: &str, update: bool) -> Value {
    let mut value = json!({
        "customerId": customer_id,
        "lineItems": [],
        "subtotal": 0,
        "total": 0,
        "currency": "usd",
        "incoming": [],
        "outgoing": []
    });
    if update {
        value["intent"] = json!("none");
    } else {
        value["redirectToCheckout"] = json!(false);
        value["checkoutType"] = json!("autumn_checkout");
    }
    value
}
