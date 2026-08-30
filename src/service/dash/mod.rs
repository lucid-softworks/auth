#[cfg(feature = "axum")]
use super::{AuthService, SignInResult};
#[cfg(feature = "axum")]
use crate::{
    AdminListCondition, AdminListOperator, AdminListUsersQuery, AdminSortDirection,
    AdminUserUpdate, AuthError, AuthUser, DashAdapterAction, DashAdapterWhere, DashSortDirection,
    DashUserListQuery, PasswordCredentialChanged, PasswordCredentialSource,
};
#[cfg(feature = "axum")]
use chrono::{DateTime, Utc};
#[cfg(feature = "axum")]
use serde_json::{Map, Value, json};

mod activity;
#[cfg(feature = "axum")]
mod adapter;
#[cfg(feature = "axum")]
mod analytics;
#[cfg(feature = "axum")]
mod config;
#[cfg(feature = "axum")]
mod entropy;
#[cfg(feature = "axum")]
mod sessions;
#[cfg(feature = "axum")]
mod users;

#[cfg(feature = "axum")]
mod support {
use super::*;

pub(super) fn percentage(current: i64, previous: i64) -> f64 {
    if previous == 0 {
        return if current > 0 { 100.0 } else { 0.0 };
    }
    (current - previous) as f64 / previous as f64 * 100.0
}

pub(super) fn optional_period(
    current: &Result<i64, AuthError>,
    previous: &Result<i64, AuthError>,
    field: &str,
) -> Value {
    let mut output = Map::new();
    output.insert(
        field.into(),
        current
            .as_ref()
            .ok()
            .copied()
            .map_or(Value::Null, Value::from),
    );
    output.insert(
        "percentage".into(),
        match (current, previous) {
            (Ok(current), Ok(previous)) => Value::from(percentage(*current, *previous)),
            _ => Value::Null,
        },
    );
    Value::Object(output)
}

pub(super) fn add_period(
    value: DateTime<Utc>,
    period: crate::DashPeriod,
    amount: i32,
) -> DateTime<Utc> {
    match period {
        crate::DashPeriod::Daily => value + chrono::Duration::days(i64::from(amount)),
        crate::DashPeriod::Weekly => value + chrono::Duration::weeks(i64::from(amount)),
        crate::DashPeriod::Monthly if amount >= 0 => value
            .checked_add_months(chrono::Months::new(amount as u32))
            .expect("Dash month horizon remains representable"),
        crate::DashPeriod::Monthly => value
            .checked_sub_months(chrono::Months::new(amount.unsigned_abs()))
            .expect("Dash month horizon remains representable"),
    }
}

pub(super) fn dash_field(name: &str, field: &crate::AdditionalField) -> Value {
    json!({
        "name": name,
        "type": match field.field_type {
            crate::AdditionalFieldType::String | crate::AdditionalFieldType::StringLiteral(_) => "string",
            crate::AdditionalFieldType::Number => "number",
            crate::AdditionalFieldType::Boolean => "boolean",
            crate::AdditionalFieldType::Date => "date",
            crate::AdditionalFieldType::Json => "json",
            crate::AdditionalFieldType::StringArray => "string[]",
            crate::AdditionalFieldType::NumberArray => "number[]",
        },
        "required": field.required,
        "input": field.input,
        "unique": field.unique,
        "hasDefaultValue": field.has_default_value(),
        "references": field.references.as_ref().map(|reference| json!({"model": reference.model, "field": reference.field})),
        "returned": field.returned,
        "bigInt": field.bigint,
    })
}

pub(super) fn dash_conditions(values: &[Value]) -> Result<Vec<AdminListCondition>, AuthError> {
    values
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| AuthError::InvalidRequest("where clause is invalid".into()))?;
            let field = object
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| AuthError::InvalidRequest("where field is invalid".into()))?;
            let operator = match object
                .get("operator")
                .and_then(Value::as_str)
                .unwrap_or("eq")
            {
                "eq" => AdminListOperator::Eq,
                "ne" => AdminListOperator::Ne,
                "lt" => AdminListOperator::Lt,
                "lte" => AdminListOperator::Lte,
                "gt" => AdminListOperator::Gt,
                "gte" => AdminListOperator::Gte,
                "in" => AdminListOperator::In,
                "not_in" => AdminListOperator::NotIn,
                "contains" => AdminListOperator::Contains,
                "starts_with" => AdminListOperator::StartsWith,
                "ends_with" => AdminListOperator::EndsWith,
                _ => {
                    return Err(AuthError::InvalidRequest(
                        "where operator is invalid".into(),
                    ));
                }
            };
            Ok(AdminListCondition {
                field: field.into(),
                operator,
                value: object.get("value").cloned().unwrap_or(Value::Null),
            })
        })
        .collect()
}

pub(super) fn take_required_string(
    body: &mut Map<String, Value>,
    key: &str,
) -> Result<String, AuthError> {
    let value = take_optional_string(body, key)?
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AuthError::InvalidRequest(format!("{key} is required")))?;
    Ok(value)
}

pub(super) fn take_optional_string(
    body: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<String>, AuthError> {
    body.remove(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AuthError::InvalidRequest(format!("{key} is invalid")))
        })
        .transpose()
}

pub(super) fn retain_writable_user_fields(
    body: &mut Map<String, Value>,
    fields: &crate::AdditionalFieldSet,
    require_configured: bool,
) -> Result<(), AuthError> {
    body.retain(|name, _| {
        matches!(name.as_str(), "name" | "email" | "image" | "emailVerified")
            || fields
                .get(name)
                .is_some_and(|field| field.input && field.references.is_none())
    });
    for (name, field) in fields {
        if !field.input || field.references.is_some() {
            continue;
        }
        if require_configured
            && field.required
            && !field.has_default_value()
            && !body.contains_key(name)
        {
            return Err(AuthError::InvalidRequest(format!("{name} is required")));
        }
        if let Some(value) = body.get_mut(name) {
            coerce_dash_field(name, field, value)?;
        }
    }
    Ok(())
}

pub(super) fn dash_user_additional_fields(service: &AuthService) -> crate::AdditionalFieldSet {
    const CORE_FIELDS: &[&str] = &[
        "id",
        "name",
        "email",
        "emailVerified",
        "image",
        "createdAt",
        "updatedAt",
    ];
    service
        .database_schema()
        .table("user")
        .expect("the user schema always exists")
        .fields
        .iter()
        .filter(|(name, _)| !CORE_FIELDS.contains(&name.as_str()))
        .map(|(name, field)| (name.clone(), field.clone()))
        .collect()
}

pub(super) fn coerce_dash_field(
    name: &str,
    field: &crate::AdditionalField,
    value: &mut Value,
) -> Result<(), AuthError> {
    use crate::AdditionalFieldType;
    let valid = match field.field_type {
        AdditionalFieldType::Number => {
            if value.is_number() {
                true
            } else if let Some(raw) = value.as_str() {
                raw.parse::<f64>()
                    .ok()
                    .and_then(serde_json::Number::from_f64)
                    .map(|number| *value = Value::Number(number))
                    .is_some()
            } else {
                false
            }
        }
        AdditionalFieldType::Boolean => {
            if value.is_boolean() {
                true
            } else if let Some(raw) = value.as_str() {
                *value = Value::Bool(!raw.is_empty());
                true
            } else if let Some(number) = value.as_f64() {
                *value = Value::Bool(number != 0.0);
                true
            } else {
                false
            }
        }
        AdditionalFieldType::Date => value
            .as_str()
            .is_some_and(|raw| !field.required || !raw.is_empty()),
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => value
            .as_str()
            .is_some_and(|raw| !field.required || !raw.is_empty()),
        AdditionalFieldType::Json => true,
        AdditionalFieldType::StringArray => value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string)),
        AdditionalFieldType::NumberArray => value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_number)),
    };
    if valid {
        Ok(())
    } else {
        Err(AuthError::InvalidRequest(format!("{name} is invalid")))
    }
}

pub(super) fn dash_user_update(
    mut data: Map<String, Value>,
) -> Result<AdminUserUpdate, AuthError> {
    let name = nullable_string(&mut data, "name")?.flatten();
    let email = nullable_string(&mut data, "email")?
        .flatten()
        .map(|email| email.to_lowercase());
    let image = nullable_string(&mut data, "image")?;
    let email_verified = data
        .remove("emailVerified")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| AuthError::InvalidRequest("emailVerified is invalid".into()))
        })
        .transpose()?;
    Ok(AdminUserUpdate {
        name,
        email,
        email_verified,
        image,
        additional_fields: data,
        ..AdminUserUpdate::default()
    })
}

pub(super) fn nullable_string(
    data: &mut Map<String, Value>,
    key: &str,
) -> Result<Option<Option<String>>, AuthError> {
    data.remove(key)
        .map(|value| match value {
            Value::Null => Ok(None),
            Value::String(value) => Ok(Some(value)),
            _ => Err(AuthError::InvalidRequest(format!("{key} is invalid"))),
        })
        .transpose()
}

pub(super) fn random_password() -> String {
    use rand::distr::{Alphanumeric, SampleString as _};
    Alphanumeric.sample_string(&mut rand::rng(), 12)
}

pub(super) fn js_index(value: f64) -> usize {
    if !value.is_finite() || value <= 0.0 {
        0
    } else {
        value.floor().min(usize::MAX as f64) as usize
    }
}

pub(super) fn equality_string<'a>(
    where_clause: &'a [DashAdapterWhere],
    field: &str,
) -> Result<&'a str, AuthError> {
    where_clause
        .iter()
        .find(|condition| {
            condition.field == field && matches!(condition.operator, crate::DashAdapterOperator::Eq)
        })
        .and_then(|condition| condition.value.as_str())
        .ok_or_else(|| {
            AuthError::Storage(format!(
                "the configured adapter requires an equality filter for '{field}'"
            ))
        })
}

pub(super) fn dash_adapter_condition(
    condition: &DashAdapterWhere,
) -> Result<AdminListCondition, AuthError> {
    let operator = match condition.operator {
        crate::DashAdapterOperator::Eq => AdminListOperator::Eq,
        crate::DashAdapterOperator::Ne => AdminListOperator::Ne,
        crate::DashAdapterOperator::Gt => AdminListOperator::Gt,
        crate::DashAdapterOperator::Gte => AdminListOperator::Gte,
        crate::DashAdapterOperator::Lt => AdminListOperator::Lt,
        crate::DashAdapterOperator::Lte => AdminListOperator::Lte,
        crate::DashAdapterOperator::In => AdminListOperator::In,
        crate::DashAdapterOperator::Contains => AdminListOperator::Contains,
        crate::DashAdapterOperator::StartsWith => AdminListOperator::StartsWith,
        crate::DashAdapterOperator::EndsWith => AdminListOperator::EndsWith,
    };
    Ok(AdminListCondition {
        field: condition.field.clone(),
        operator,
        value: condition.value.clone(),
    })
}

pub(super) fn dash_matches(value: &Value, conditions: &[DashAdapterWhere]) -> bool {
    conditions.iter().all(|condition| {
        let candidate = value.get(&condition.field).unwrap_or(&Value::Null);
        match condition.operator {
            crate::DashAdapterOperator::Eq => candidate == &condition.value,
            crate::DashAdapterOperator::Ne => candidate != &condition.value,
            crate::DashAdapterOperator::In => condition
                .value
                .as_array()
                .is_some_and(|values| values.contains(candidate)),
            crate::DashAdapterOperator::Contains => candidate
                .as_str()
                .zip(condition.value.as_str())
                .is_some_and(|(candidate, expected)| candidate.contains(expected)),
            crate::DashAdapterOperator::StartsWith => candidate
                .as_str()
                .zip(condition.value.as_str())
                .is_some_and(|(candidate, expected)| candidate.starts_with(expected)),
            crate::DashAdapterOperator::EndsWith => candidate
                .as_str()
                .zip(condition.value.as_str())
                .is_some_and(|(candidate, expected)| candidate.ends_with(expected)),
            crate::DashAdapterOperator::Gt
            | crate::DashAdapterOperator::Gte
            | crate::DashAdapterOperator::Lt
            | crate::DashAdapterOperator::Lte => compare_values(candidate, &condition.value)
                .is_some_and(|ordering| match condition.operator {
                    crate::DashAdapterOperator::Gt => ordering.is_gt(),
                    crate::DashAdapterOperator::Gte => !ordering.is_lt(),
                    crate::DashAdapterOperator::Lt => ordering.is_lt(),
                    crate::DashAdapterOperator::Lte => !ordering.is_gt(),
                    _ => false,
                }),
        }
    })
}

pub(super) fn compare_values(left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
    if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        return left.partial_cmp(&right);
    }
    left.as_str()?.partial_cmp(right.as_str()?)
}

pub(super) fn project(mut value: Value, select: Option<&[String]>) -> Value {
    let Some(select) = select else {
        return value;
    };
    let object = value
        .as_object_mut()
        .expect("adapter records serialize as objects");
    object.retain(|field, _| select.iter().any(|selected| selected == field));
    value
}

}

#[cfg(feature = "axum")]
use support::*;
#[cfg(feature = "axum")]
use entropy::estimate_entropy;
