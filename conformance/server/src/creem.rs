use async_trait::async_trait;
use lucid_auth::{
    AuthConfig, CreemCheckout, CreemCheckoutRequest, CreemOptions, CreemPlugin, CreemPortal,
    CreemPortalRequest, CreemProviderConfig, CreemProviderError, CreemProviderSubscription,
    CreemTransactionPage, CreemTransactionSearch, CreemTransport, MemoryStore,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Debug)]
struct ConformanceCreem {
    config: CreemProviderConfig,
}

pub(super) fn register(config: &mut AuthConfig, auth_store: Arc<MemoryStore>) {
    let transport = Arc::new(ConformanceCreem {
        config: CreemProviderConfig::test("creem_native_conformance_key"),
    });
    let mut options = CreemOptions::with_transport("creem_native_conformance_key", transport);
    options.persist_subscriptions = false;
    config
        .add_plugin(CreemPlugin::in_memory(options, auth_store))
        .expect("unique Creem plugin");
}

#[async_trait]
impl CreemTransport for ConformanceCreem {
    fn config(&self) -> &CreemProviderConfig {
        &self.config
    }

    async fn create_checkout(
        &self,
        request: CreemCheckoutRequest,
    ) -> Result<CreemCheckout, CreemProviderError> {
        Ok(CreemCheckout {
            checkout_url: Some(format!(
                "https://creem.example.test/checkout/{}",
                request.product_id
            )),
            value: json!({"checkoutUrl":"https://creem.example.test/checkout"}),
        })
    }

    async fn create_portal(
        &self,
        request: CreemPortalRequest,
    ) -> Result<CreemPortal, CreemProviderError> {
        Ok(CreemPortal {
            customer_portal_link: format!(
                "https://creem.example.test/portal/{}",
                request.customer_id
            ),
            value: json!({}),
        })
    }

    async fn cancel_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError> {
        Ok(CreemProviderSubscription {
            value: json!({"id":subscription_id,"status":"canceled"}),
        })
    }

    async fn retrieve_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<CreemProviderSubscription, CreemProviderError> {
        Ok(CreemProviderSubscription {
            value: json!({"id":subscription_id,"status":"active"}),
        })
    }

    async fn search_transactions(
        &self,
        search: CreemTransactionSearch,
    ) -> Result<CreemTransactionPage, CreemProviderError> {
        Ok(CreemTransactionPage {
            value: json!({
                "result": {
                    "items": [],
                    "pagination": {
                        "currentPage": search.page_number(),
                        "nextPage": null,
                        "prevPage": null,
                        "totalPages": 1,
                        "totalRecords": 0
                    }
                }
            }),
            next_page: None,
        })
    }
}
