use super::{PolarCallbackError, PolarPrimitiveMetadata, PolarProduct, PolarUser};
use async_trait::async_trait;

#[async_trait]
pub trait PolarProductsProvider: Send + Sync {
    async fn products(&self) -> Result<Vec<PolarProduct>, PolarCallbackError>;
}

/// Static or asynchronously resolved product list, matching the adapter union.
#[derive(Clone)]
pub enum PolarProducts {
    Static(Vec<PolarProduct>),
    Dynamic(std::sync::Arc<dyn PolarProductsProvider>),
}

impl PolarProducts {
    pub fn static_products(products: Vec<PolarProduct>) -> Self {
        Self::Static(products)
    }

    pub fn dynamic(provider: std::sync::Arc<dyn PolarProductsProvider>) -> Self {
        Self::Dynamic(provider)
    }

    pub async fn resolve(&self) -> Result<Vec<PolarProduct>, PolarCallbackError> {
        match self {
            Self::Static(products) => Ok(products.clone()),
            Self::Dynamic(provider) => provider.products().await,
        }
    }
}

impl std::fmt::Debug for PolarProducts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(products) => formatter.debug_tuple("Static").field(products).finish(),
            Self::Dynamic(_) => formatter.write_str("Dynamic(..)"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolarCustomerCreateParams {
    pub metadata: Option<PolarPrimitiveMetadata>,
}

#[async_trait]
pub trait PolarCustomerCreateParamsProvider: Send + Sync {
    async fn params(
        &self,
        user: &PolarUser,
    ) -> Result<PolarCustomerCreateParams, PolarCallbackError>;
}
