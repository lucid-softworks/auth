use crate::{AuthError, OrganizationMemberWithUser};
use serde::Deserialize;
use std::cmp::Reverse;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MemberQuery {
    pub organization_id: Option<String>,
    pub organization_slug: Option<String>,
    pub user_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    sort_by: Option<String>,
    sort_direction: Option<String>,
    filter_field: Option<String>,
    filter_value: Option<String>,
    filter_operator: Option<String>,
}

pub(super) fn apply(
    members: &mut Vec<OrganizationMemberWithUser>,
    options: &MemberQuery,
) -> Result<(), AuthError> {
    if let Some(field) = options.filter_field.as_deref() {
        let expected = options.filter_value.as_deref().unwrap_or_default();
        let operator = options.filter_operator.as_deref().unwrap_or("eq");
        if !valid_operator(operator) {
            return Err(AuthError::InvalidRequest("invalid filterOperator".into()));
        }
        members.retain(|entry| compare(&field_value(entry, field), expected, operator));
    }
    if let Some(field) = options.sort_by.as_deref() {
        match options.sort_direction.as_deref() {
            Some("asc") | None => members.sort_by_key(|entry| field_value(entry, field)),
            Some("desc") => members.sort_by_key(|entry| Reverse(field_value(entry, field))),
            Some(_) => return Err(AuthError::InvalidRequest("invalid sortDirection".into())),
        }
    }
    Ok(())
}

fn field_value(entry: &OrganizationMemberWithUser, field: &str) -> String {
    match field {
        "id" => entry.member.id.to_string(),
        "organizationId" => entry.member.organization_id.to_string(),
        "userId" => entry.member.user_id.to_string(),
        "role" => entry.member.role.clone(),
        "createdAt" => entry.member.created_at.to_rfc3339(),
        _ => String::new(),
    }
}

fn compare(actual: &str, expected: &str, operator: &str) -> bool {
    match operator {
        "eq" => actual == expected,
        "ne" => actual != expected,
        "lt" => actual < expected,
        "lte" => actual <= expected,
        "gt" => actual > expected,
        "gte" => actual >= expected,
        "in" => values(expected).any(|value| actual == value),
        "not_in" => values(expected).all(|value| actual != value),
        "contains" => actual.contains(expected),
        "starts_with" => actual.starts_with(expected),
        "ends_with" => actual.ends_with(expected),
        _ => false,
    }
}

fn values(value: &str) -> impl Iterator<Item = &str> {
    value.split(',').map(str::trim)
}

fn valid_operator(value: &str) -> bool {
    matches!(
        value,
        "eq" | "ne"
            | "lt"
            | "lte"
            | "gt"
            | "gte"
            | "in"
            | "not_in"
            | "contains"
            | "starts_with"
            | "ends_with"
    )
}
