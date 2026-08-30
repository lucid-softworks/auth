use super::{ScimAddress, ScimEnterpriseUser, invalid, optional_bounded};
use crate::scim::ScimError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScimManager {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl<'de> Deserialize<'de> for ScimManager {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let value = match value {
            Value::String(value) => {
                return Ok(Self {
                    value: Some(value),
                    reference: None,
                });
            }
            Value::Array(mut values) if values.len() == 1 => values.remove(0),
            value => value,
        };
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("manager must be a string or object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "value" | "$ref" | "displayName"))
        {
            return Err(serde::de::Error::custom(
                "manager contains an unsupported attribute",
            ));
        }
        let value = optional_string(object.get("value"), "manager.value")?;
        let reference = optional_string(object.get("$ref"), "manager.$ref")?;
        if value.is_none() && reference.is_none() {
            return Err(serde::de::Error::custom(
                "manager must contain value or $ref",
            ));
        }
        Ok(Self { value, reference })
    }
}

fn optional_string<E: serde::de::Error>(
    value: Option<&Value>,
    field: &str,
) -> Result<Option<String>, E> {
    value
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| E::custom(format!("{field} must be a string")))
        })
        .transpose()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimPhoneNumber {
    pub value: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimRole {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimEntitlement {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

pub(super) fn normalize_phone_numbers(values: &mut [ScimPhoneNumber]) -> Result<(), ScimError> {
    for value in values.iter_mut() {
        value.value = required(value.value.clone(), 1024, "phoneNumbers.value")?;
        normalize_type(&mut value.kind, "phoneNumbers.type")?;
    }
    validate_primary_types(
        values.iter().map(|value| (value.primary, value.kind.as_deref())),
        "phoneNumbers",
    )
}

pub(super) fn normalize_addresses(values: &mut [ScimAddress]) -> Result<(), ScimError> {
    for value in values.iter_mut() {
        value.formatted = optional_bounded(value.formatted.take(), 1024, "addresses.formatted")?;
        value.street_address =
            optional_bounded(value.street_address.take(), 1024, "addresses.streetAddress")?;
        value.locality = optional_bounded(value.locality.take(), 256, "addresses.locality")?;
        value.region = optional_bounded(value.region.take(), 256, "addresses.region")?;
        value.postal_code =
            optional_bounded(value.postal_code.take(), 256, "addresses.postalCode")?;
        value.country = optional_bounded(value.country.take(), 256, "addresses.country")?;
        normalize_type(&mut value.kind, "addresses.type")?;
        if [
            value.formatted.as_ref(),
            value.street_address.as_ref(),
            value.locality.as_ref(),
            value.region.as_ref(),
            value.postal_code.as_ref(),
            value.country.as_ref(),
        ]
        .into_iter()
        .all(|value| value.is_none())
        {
            return Err(invalid("addresses must contain at least one address value"));
        }
    }
    validate_primary_types(
        values.iter().map(|value| (value.primary, value.kind.as_deref())),
        "addresses",
    )
}

pub(super) fn normalize_roles(values: &mut [ScimRole], field: &str) -> Result<(), ScimError> {
    for value in values.iter_mut() {
        value.value = required(value.value.clone(), 1024, &format!("{field}.value"))?;
        value.display = optional_bounded(value.display.take(), 1024, &format!("{field}.display"))?;
        normalize_type(&mut value.kind, &format!("{field}.type"))?;
    }
    validate_primary_types(
        values.iter().map(|value| (value.primary, value.kind.as_deref())),
        field,
    )
}

pub(super) fn normalize_entitlements(
    values: &mut [ScimEntitlement],
) -> Result<(), ScimError> {
    for value in values.iter_mut() {
        value.value = required(value.value.clone(), 1024, "entitlements.value")?;
        value.display =
            optional_bounded(value.display.take(), 1024, "entitlements.display")?;
        normalize_type(&mut value.kind, "entitlements.type")?;
    }
    validate_primary_types(
        values.iter().map(|value| (value.primary, value.kind.as_deref())),
        "entitlements",
    )
}

pub(super) fn normalize_enterprise(
    enterprise: &mut Option<ScimEnterpriseUser>,
) -> Result<(), ScimError> {
    let Some(enterprise) = enterprise else {
        return Ok(());
    };
    enterprise.employee_number =
        optional_bounded(enterprise.employee_number.take(), 256, "employeeNumber")?;
    enterprise.cost_center =
        optional_bounded(enterprise.cost_center.take(), 256, "costCenter")?;
    enterprise.organization =
        optional_bounded(enterprise.organization.take(), 1024, "organization")?;
    enterprise.division = optional_bounded(enterprise.division.take(), 1024, "division")?;
    enterprise.department =
        optional_bounded(enterprise.department.take(), 1024, "department")?;
    if let Some(manager) = &mut enterprise.manager {
        manager.value = optional_bounded(manager.value.take(), 256, "manager.value")?;
        manager.reference =
            optional_bounded(manager.reference.take(), 2048, "manager.$ref")?;
        if manager.value.is_none() && manager.reference.is_none() {
            return Err(invalid("manager must contain value or $ref"));
        }
    }
    Ok(())
}

fn required(value: String, maximum: usize, field: &str) -> Result<String, ScimError> {
    optional_bounded(Some(value), maximum, field)?.ok_or_else(|| invalid(format!("{field} is required")))
}

fn normalize_type(value: &mut Option<String>, field: &str) -> Result<(), ScimError> {
    *value = optional_bounded(value.take(), 256, field)?.map(|value| value.to_ascii_lowercase());
    Ok(())
}

fn validate_primary_types<'a>(
    values: impl Iterator<Item = (Option<bool>, Option<&'a str>)>,
    field: &str,
) -> Result<(), ScimError> {
    let values = values.collect::<Vec<_>>();
    if values
        .iter()
        .filter(|(primary, _)| *primary == Some(true))
        .count()
        > 1
    {
        return Err(invalid(format!(
            "{field} cannot contain multiple primary values"
        )));
    }
    let mut types = std::collections::HashSet::new();
    if values
        .iter()
        .filter_map(|(_, kind)| *kind)
        .any(|kind| !types.insert(kind.to_ascii_lowercase()))
    {
        return Err(invalid(format!(
            "{field} cannot contain duplicate defined types"
        )));
    }
    Ok(())
}
