use super::commerce::{EnvironmentMode, Nullable, ProductFeatureType, SdkDate};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) enum LicenseStatus {
    #[serde(rename = "inactive")]
    Inactive,
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "disabled")]
    Disabled,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) enum LicenseInstanceStatus {
    #[serde(rename = "active")]
    Active,
    #[serde(rename = "deactivated")]
    Deactivated,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LicenseInstance {
    id: String,
    mode: EnvironmentMode,
    object: String,
    name: String,
    status: LicenseInstanceStatus,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: SdkDate,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct LicenseEntity {
    id: String,
    mode: EnvironmentMode,
    object: String,
    #[serde(rename(deserialize = "product_id", serialize = "productId"))]
    product_id: String,
    status: LicenseStatus,
    key: String,
    activation: f64,
    #[serde(
        rename(deserialize = "activation_limit", serialize = "activationLimit"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    activation_limit: Nullable<f64>,
    #[serde(
        rename(deserialize = "expires_at", serialize = "expiresAt"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    expires_at: Nullable<SdkDate>,
    #[serde(rename(deserialize = "created_at", serialize = "createdAt"))]
    created_at: SdkDate,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    instance: Nullable<LicenseInstance>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct FeatureFile {
    id: String,
    #[serde(rename(deserialize = "file_name", serialize = "fileName"))]
    file_name: String,
    url: String,
    #[serde(rename = "type")]
    file_type: String,
    size: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct FileFeature {
    files: Vec<FeatureFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CustomerCredits {
    amount: String,
    #[serde(
        rename(deserialize = "unit_label", serialize = "unitLabel"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    unit_label: Nullable<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ProductFeatureEntity {
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    id: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    description: Nullable<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    feature_type: Option<ProductFeatureType>,
    #[serde(
        rename(deserialize = "private_note", serialize = "privateNote"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    private_note: Nullable<String>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    file: Nullable<FileFeature>,
    #[serde(
        rename(deserialize = "license_key", serialize = "licenseKey"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    license_key: Nullable<LicenseEntity>,
    #[serde(
        rename(deserialize = "customer_credits", serialize = "customerCredits"),
        default,
        skip_serializing_if = "Nullable::is_absent"
    )]
    customer_credits: Nullable<CustomerCredits>,
    #[serde(default, skip_serializing_if = "Nullable::is_absent")]
    license: Nullable<LicenseEntity>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn nested_feature_fields_are_validated_remapped_and_stripped() {
        let feature: ProductFeatureEntity = serde_json::from_value(json!({
            "id": "feature_1",
            "type": "file",
            "private_note": "note",
            "file": {"files": [{
                "id": "file_1",
                "file_name": "manual.pdf",
                "url": "https://files.test/manual.pdf",
                "type": "application/pdf",
                "size": 20,
                "unknown": true
            }]},
            "unknown": true
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(feature).unwrap(),
            json!({
                "id": "feature_1",
                "type": "file",
                "privateNote": "note",
                "file": {"files": [{
                    "id": "file_1",
                    "fileName": "manual.pdf",
                    "url": "https://files.test/manual.pdf",
                    "type": "application/pdf",
                    "size": 20.0
                }]}
            })
        );
    }
}
