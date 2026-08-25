use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Debug, Clone)]
pub(super) struct Nullable<T> {
    present: bool,
    value: Option<T>,
}

impl<T> Nullable<T> {
    pub(super) const fn is_absent(&self) -> bool {
        !self.present
    }
}

impl<T> Default for Nullable<T> {
    fn default() -> Self {
        Self {
            present: false,
            value: None,
        }
    }
}

impl<'de, T> Deserialize<'de> for Nullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self {
            present: true,
            value: Option::<T>::deserialize(deserializer)?,
        })
    }
}

impl<T> Serialize for Nullable<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.value.serialize(serializer)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum EnvironmentMode {
    Test,
    Prod,
    Sandbox,
}

#[derive(Debug, Clone)]
pub(super) struct SdkDate(DateTime<Utc>);

impl<'de> Deserialize<'de> for SdkDate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&value)
            .map(|value| Self(value.with_timezone(&Utc)))
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for SdkDate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_rfc3339_opts(SecondsFormat::Millis, true))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CustomerEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    email: String,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    name: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    metadata: Nullable<serde_json::Map<String, Value>>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    country: Nullable<String>,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: SdkDate,
    #[serde(rename(deserialize = "updated_at", serialize = "updatedAt"))]
    updated_at: SdkDate,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum ProductOrId {
    Product(Box<ProductEntity>),
    Id(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum CustomerOrId {
    Customer(Box<CustomerEntity>),
    Id(String),
}

impl CustomerOrId {
    pub(super) fn validate(&self) -> Result<(), ()> {
        match self {
            Self::Customer(customer) if customer.country.is_absent() => Err(()),
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct FeatureEntity {
    id: String,
    #[serde(rename = "type")]
    feature_type: ProductFeatureType,
    description: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) enum ProductFeatureType {
    #[serde(rename = "custom")]
    Custom,
    #[serde(rename = "file")]
    File,
    #[serde(rename = "licenseKey")]
    LicenseKey,
    #[serde(rename = "customerCredits")]
    CustomerCredits,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) enum CustomFieldType {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "checkbox")]
    Checkbox,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CustomFieldText {
    #[serde(
        rename(deserialize = "max_length", serialize = "maxLength"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    max_length: Nullable<f64>,
    #[serde(
        rename(deserialize = "minimum_length", serialize = "minimumLength"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    minimum_length: Nullable<f64>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    value: Nullable<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CustomFieldCheckbox {
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    label: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    value: Nullable<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ResponseCustomField {
    #[serde(rename = "type")]
    field_type: CustomFieldType,
    key: String,
    label: String,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    optional: Nullable<bool>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    text: Nullable<CustomFieldText>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    checkbox: Nullable<CustomFieldCheckbox>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProductEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    name: String,
    description: String,
    #[serde(
        rename(deserialize = "image_url", serialize = "imageUrl"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    image_url: Option<String>,
    #[serde(
        rename(deserialize = "image_urls", serialize = "imageUrls"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    image_urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    features: Option<Vec<FeatureEntity>>,
    price: f64,
    currency: String,
    #[serde(rename(deserialize = "billing_type", serialize = "billingType"))]
    billing_type: ProductBillingType,
    #[serde(rename(deserialize = "billing_period", serialize = "billingPeriod"))]
    billing_period: ProductBillingPeriod,
    status: ProductStatus,
    #[serde(rename(deserialize = "tax_mode", serialize = "taxMode"))]
    tax_mode: TaxMode,
    #[serde(rename(deserialize = "tax_category", serialize = "taxCategory"))]
    tax_category: TaxCategory,
    #[serde(
        rename(deserialize = "product_url", serialize = "productUrl"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    product_url: Option<String>,
    #[serde(
        rename(deserialize = "default_success_url", serialize = "defaultSuccessUrl"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    default_success_url: Nullable<String>,
    #[serde(
        rename(deserialize = "custom_fields", serialize = "customFields"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    custom_fields: Nullable<Vec<ResponseCustomField>>,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: SdkDate,
    #[serde(rename(deserialize = "updated_at", serialize = "updatedAt"))]
    updated_at: SdkDate,
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub(super) enum $name {
            $(#[serde(rename = $value)] $variant),+
        }
    };
}

string_enum!(ProductBillingType { Recurring => "recurring", Onetime => "onetime" });
string_enum!(ProductBillingPeriod {
    EveryMonth => "every-month",
    EveryThreeMonths => "every-three-months",
    EverySixMonths => "every-six-months",
    EveryYear => "every-year",
    EveryDay => "every-day",
    Once => "once",
});
string_enum!(ProductStatus { Active => "active", Archived => "archived" });
string_enum!(TaxMode { Inclusive => "inclusive", Exclusive => "exclusive" });
string_enum!(TaxCategory {
    Saas => "saas",
    DigitalGoodsService => "digital-goods-service",
    Ebooks => "ebooks",
});
string_enum!(OrderStatus { Pending => "pending", Paid => "paid" });
string_enum!(OrderType { Recurring => "recurring", Onetime => "onetime" });
string_enum!(DiscountType { Percentage => "percentage", Fixed => "fixed" });
string_enum!(DiscountDuration {
    Forever => "forever",
    Once => "once",
    Repeating => "repeating",
});

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct OrderEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    customer: Nullable<String>,
    product: String,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    transaction: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    discount: Nullable<String>,
    amount: f64,
    #[serde(
        rename(deserialize = "sub_total", serialize = "subTotal"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    sub_total: Option<f64>,
    #[serde(
        rename(deserialize = "tax_amount", serialize = "taxAmount"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    tax_amount: Option<f64>,
    #[serde(
        rename(deserialize = "discount_amount", serialize = "discountAmount"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    discount_amount: Option<f64>,
    #[serde(
        rename(deserialize = "amount_due", serialize = "amountDue"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    amount_due: Option<f64>,
    #[serde(
        rename(deserialize = "amount_paid", serialize = "amountPaid"),
        default,
        skip_serializing_if = "Option::is_none"
    )]
    amount_paid: Option<f64>,
    currency: String,
    #[serde(
        rename(deserialize = "fx_amount", serialize = "fxAmount"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    fx_amount: Nullable<f64>,
    #[serde(
        rename(deserialize = "fx_currency", serialize = "fxCurrency"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    fx_currency: Nullable<String>,
    #[serde(
        rename(deserialize = "fx_rate", serialize = "fxRate"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    fx_rate: Nullable<f64>,
    status: OrderStatus,
    #[serde(rename = "type")]
    order_type: OrderType,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    affiliate: Nullable<String>,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: SdkDate,
    #[serde(rename(deserialize = "updated_at", serialize = "updatedAt"))]
    updated_at: SdkDate,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DiscountEntity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    discount_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    discount_type: Option<DiscountType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    amount: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration: Option<DiscountDuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_in_months: Option<f64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CustomerLinksEntity {
    #[serde(rename(deserialize = "customer_portal_link", serialize = "customerPortalLink"))]
    customer_portal_link: String,
}

pub(crate) fn normalize_portal(value: Value) -> Result<(String, Value), ()> {
    let parsed: CustomerLinksEntity = serde_json::from_value(value).map_err(|_| ())?;
    let link = parsed.customer_portal_link.clone();
    serde_json::to_value(parsed)
        .map(|value| (link, value))
        .map_err(|_| ())
}

#[cfg(test)]
#[path = "commerce/contract.rs"]
mod tests;
