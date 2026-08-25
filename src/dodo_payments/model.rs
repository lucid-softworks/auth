use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, sync::Arc};

/// Product-id to slug mapping accepted by Dodo's checkout contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DodoProduct {
    pub product_id: String,
    pub slug: String,
}

impl DodoProduct {
    pub fn new(product_id: impl Into<String>, slug: impl Into<String>) -> Self {
        Self {
            product_id: product_id.into(),
            slug: slug.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DodoPaymentsCallbackError {
    pub message: String,
}

impl DodoPaymentsCallbackError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[async_trait]
pub trait DodoProductsProvider: Send + Sync {
    async fn products(&self) -> Result<Vec<DodoProduct>, DodoPaymentsCallbackError>;
}

/// Static or asynchronously resolved products, matching the adapter union.
#[derive(Clone)]
pub enum DodoProducts {
    Static(Vec<DodoProduct>),
    Dynamic(Arc<dyn DodoProductsProvider>),
}

impl DodoProducts {
    pub fn static_products(products: Vec<DodoProduct>) -> Self {
        Self::Static(products)
    }

    pub fn dynamic(provider: Arc<dyn DodoProductsProvider>) -> Self {
        Self::Dynamic(provider)
    }

    pub async fn resolve(&self) -> Result<Vec<DodoProduct>, DodoPaymentsCallbackError> {
        match self {
            Self::Static(products) => Ok(products.clone()),
            Self::Dynamic(provider) => provider.products().await,
        }
    }
}

impl fmt::Debug for DodoProducts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(products) => formatter.debug_tuple("Static").field(products).finish(),
            Self::Dynamic(_) => formatter.write_str("Dynamic(..)"),
        }
    }
}

/// Optional extra fields returned by `getCustomerParams`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DodoCustomerParams {
    pub metadata: Option<BTreeMap<String, String>>,
    /// `None` omits the provider field; `Some(None)` sends an explicit null.
    pub phone_number: Option<Option<String>>,
}

/// Complete Better Auth user passed to the customer-parameter callback.
pub type DodoUser = crate::AuthUser;

#[async_trait]
pub trait DodoCustomerParamsProvider: Send + Sync {
    async fn params(
        &self,
        user: &DodoUser,
    ) -> Result<DodoCustomerParams, DodoPaymentsCallbackError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_products_preserve_order_and_exact_identifiers() {
        let products = DodoProducts::static_products(vec![
            DodoProduct::new("product_2", "pro"),
            DodoProduct::new("product_1", "starter"),
        ]);
        assert_eq!(
            products.resolve().await.unwrap(),
            match products {
                DodoProducts::Static(products) => products,
                DodoProducts::Dynamic(_) => unreachable!(),
            }
        );
    }

    #[test]
    fn customer_phone_distinguishes_omission_from_null() {
        assert_eq!(DodoCustomerParams::default().phone_number, None);
        assert_eq!(
            DodoCustomerParams {
                phone_number: Some(None),
                ..DodoCustomerParams::default()
            }
            .phone_number,
            Some(None)
        );
    }
}
