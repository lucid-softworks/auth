use crate::{
    AdminCreateUser, AdminListCondition, AdminListOperator, AdminListUsersQuery,
    AdminPermissionSet, AdminSortDirection, AdminUserUpdate, AuthError,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListUsersQuery {
    pub(super) limit: Option<usize>,
    pub(super) offset: Option<usize>,
    search_value: Option<String>,
    search_field: Option<String>,
    search_operator: Option<String>,
    sort_by: Option<String>,
    sort_direction: Option<String>,
    filter_field: Option<String>,
    filter_value: Option<String>,
    filter_operator: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(super) enum RoleInput {
    One(String),
    Many(Vec<String>),
}

impl RoleInput {
    pub(super) fn roles(self) -> Vec<String> {
        match self {
            Self::One(role) => vec![role],
            Self::Many(roles) => roles,
        }
    }

    pub(super) fn stored(self) -> String {
        self.roles().join(",")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SetRoleRequest {
    pub(super) user_id: String,
    pub(super) role: RoleInput,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UserRequest {
    pub(super) user_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateUserRequest {
    pub(super) email: String,
    pub(super) password: Option<String>,
    pub(super) name: String,
    pub(super) role: Option<RoleInput>,
    pub(super) data: Option<serde_json::Map<String, Value>>,
}

impl CreateUserRequest {
    pub(super) fn into_admin_input(self) -> Result<AdminCreateUser, AuthError> {
        if self.email.trim().is_empty() {
            return Err(AuthError::InvalidEmail);
        }
        let mut data = self.data.unwrap_or_default();
        let data_role = data.remove("role");
        let roles = match self.role {
            Some(role) => role.roles(),
            None => data_role
                .map(parse_role_array)
                .transpose()?
                .unwrap_or_default(),
        };
        Ok(AdminCreateUser {
            email: self.email,
            password: self.password,
            name: self.name,
            roles,
            data,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateUserRequest {
    pub(super) user_id: String,
    pub(super) data: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct HasPermissionRequest {
    pub(super) user_id: Option<String>,
    pub(super) role: Option<String>,
    pub(super) permissions: Option<AdminPermissionSet>,
    pub(super) permission: Option<AdminPermissionSet>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SetUserPasswordRequest {
    pub(super) user_id: String,
    pub(super) new_password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct BanUserRequest {
    pub(super) user_id: String,
    pub(super) ban_reason: Option<String>,
    pub(super) ban_expires_in: Option<i64>,
}

pub(super) fn admin_list_query(
    input: ListUsersQuery,
    limit: usize,
    offset: usize,
    filter_values: Vec<String>,
) -> Result<AdminListUsersQuery, AuthError> {
    let mut conditions = Vec::new();
    if let Some(value) = input.search_value {
        conditions.push(AdminListCondition {
            field: input.search_field.unwrap_or_else(|| "email".into()),
            operator: parse_list_operator(input.search_operator.as_deref().unwrap_or("contains"))?,
            value: Value::String(value),
        });
    }
    if let Some(value) = input.filter_value {
        let operator = parse_list_operator(input.filter_operator.as_deref().unwrap_or("eq"))?;
        let value = if matches!(operator, AdminListOperator::In | AdminListOperator::NotIn) {
            let values = if filter_values.is_empty() {
                vec![value]
            } else {
                filter_values
            };
            Value::Array(
                values
                    .iter()
                    .map(|value| parse_filter_value(value))
                    .collect(),
            )
        } else {
            parse_filter_value(&value)
        };
        conditions.push(AdminListCondition {
            field: input.filter_field.unwrap_or_else(|| "email".into()),
            operator,
            value,
        });
    }
    Ok(AdminListUsersQuery {
        limit,
        offset,
        sort_by: input.sort_by,
        sort_direction: match input.sort_direction.as_deref().unwrap_or("asc") {
            "asc" => AdminSortDirection::Asc,
            "desc" => AdminSortDirection::Desc,
            _ => return Err(AuthError::InvalidRequest("sortDirection is invalid".into())),
        },
        conditions,
    })
}

pub(super) fn repeated_filter_values(raw_query: Option<&str>) -> Vec<String> {
    raw_query
        .into_iter()
        .flat_map(|query| url::form_urlencoded::parse(query.as_bytes()))
        .filter(|(key, _)| key == "filterValue")
        .map(|(_, value)| value.into_owned())
        .collect()
}

fn parse_list_operator(value: &str) -> Result<AdminListOperator, AuthError> {
    match value {
        "eq" => Ok(AdminListOperator::Eq),
        "ne" => Ok(AdminListOperator::Ne),
        "lt" => Ok(AdminListOperator::Lt),
        "lte" => Ok(AdminListOperator::Lte),
        "gt" => Ok(AdminListOperator::Gt),
        "gte" => Ok(AdminListOperator::Gte),
        "in" => Ok(AdminListOperator::In),
        "not_in" => Ok(AdminListOperator::NotIn),
        "contains" => Ok(AdminListOperator::Contains),
        "starts_with" => Ok(AdminListOperator::StartsWith),
        "ends_with" => Ok(AdminListOperator::EndsWith),
        _ => Err(AuthError::InvalidRequest(
            "filter operator is invalid".into(),
        )),
    }
}

fn parse_filter_value(value: &str) -> Value {
    serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_owned()))
}

pub(super) fn parse_user_update(
    mut data: serde_json::Map<String, Value>,
) -> Result<AdminUserUpdate, AuthError> {
    if data.is_empty() {
        return Err(crate::AdminError::NoDataToUpdate.into());
    }
    if data.contains_key("password") {
        return Err(crate::AdminError::PasswordUpdateForbidden.into());
    }
    let role = data.remove("role").map(parse_role_value).transpose()?;
    let name = optional_string(&mut data, "name")?;
    let email = optional_string(&mut data, "email")?.map(|email| email.to_lowercase());
    let email_verified = optional_bool(&mut data, "emailVerified")?;
    let image = optional_nullable_string(&mut data, "image")?;
    let banned = optional_bool(&mut data, "banned")?;
    let ban_reason = optional_nullable_string(&mut data, "banReason")?;
    let ban_expires = parse_ban_expiry(&mut data)?;
    crate::admin::sanitize_additional_fields(&mut data);
    Ok(AdminUserUpdate {
        name,
        email,
        email_verified,
        image,
        role,
        banned,
        ban_reason,
        ban_expires,
        additional_fields: data,
    })
}

fn parse_ban_expiry(
    data: &mut serde_json::Map<String, Value>,
) -> Result<Option<Option<chrono::DateTime<chrono::Utc>>>, AuthError> {
    match data.remove("banExpires") {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(value) => serde_json::from_value(value)
            .map(Some)
            .map(Some)
            .map_err(|_| AuthError::InvalidRequest("banExpires is invalid".into())),
    }
}

fn parse_role_value(value: Value) -> Result<String, AuthError> {
    parse_role_array(value).map(|roles| roles.join(","))
}

fn parse_role_array(value: Value) -> Result<Vec<String>, AuthError> {
    match value {
        Value::String(role) => Ok(vec![role]),
        Value::Array(roles) => roles
            .into_iter()
            .map(|role| {
                role.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| crate::AdminError::InvalidRoleType.into())
            })
            .collect::<Result<Vec<_>, AuthError>>(),
        _ => Err(crate::AdminError::InvalidRoleType.into()),
    }
}

fn optional_string(
    data: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<String>, AuthError> {
    data.remove(key)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AuthError::InvalidRequest(format!("{key} is invalid")))
        })
        .transpose()
}

fn optional_bool(
    data: &mut serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, AuthError> {
    data.remove(key)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| AuthError::InvalidRequest(format!("{key} is invalid")))
        })
        .transpose()
}

fn optional_nullable_string(
    data: &mut serde_json::Map<String, Value>,
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
