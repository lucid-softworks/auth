use super::{
    SCIM_ENTERPRISE_USER_SCHEMA, SCIM_LIST_RESPONSE_SCHEMA, SCIM_USER_SCHEMA, ScimError,
    ScimErrorType,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

mod managed;
mod patch;
mod structured;
mod group;

pub use managed::{ScimManagedConnection, ScimManagedConnectionEvent, ScimManagedCredential};
pub use patch::{ScimPatchOperation, ScimPatchRequest};
pub use structured::{ScimEntitlement, ScimManager, ScimPhoneNumber, ScimRole};
pub use group::{ScimGroup, ScimGroupMember};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimName {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub middle_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honorific_suffix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScimEmail {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimAddress {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimEnterpriseUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub employee_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_center: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub division: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<ScimManager>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScimUser {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<ScimName>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<ScimEmail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phone_numbers: Vec<ScimPhoneNumber>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<ScimAddress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<ScimRole>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entitlements: Vec<ScimEntitlement>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(rename = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enterprise: Option<ScimEnterpriseUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<ScimMeta>,
}

fn default_active() -> bool {
    true
}

impl ScimUser {
    pub fn normalize(mut self) -> Result<Self, ScimError> {
        validate_user_schemas(&self.schemas, self.enterprise.is_some())?;
        self.schemas = [SCIM_USER_SCHEMA]
            .into_iter()
            .chain(
                self.schemas
                    .iter()
                    .any(|schema| schema == SCIM_ENTERPRISE_USER_SCHEMA)
                    .then_some(SCIM_ENTERPRISE_USER_SCHEMA),
            )
            .map(str::to_owned)
            .collect();
        self.user_name = bounded(self.user_name, 512, "userName")?;
        self.external_id = optional_bounded(self.external_id, 1024, "externalId")?;
        self.display_name = optional_bounded(self.display_name, 1024, "displayName")?;
        self.title = optional_bounded(self.title, 1024, "title")?;
        self.user_type = optional_bounded(self.user_type, 256, "userType")?;
        self.preferred_language =
            optional_bounded(self.preferred_language, 256, "preferredLanguage")?;
        self.locale = optional_bounded(self.locale, 256, "locale")?;
        self.timezone = optional_bounded(self.timezone, 256, "timezone")?;
        normalize_emails(&self.user_name, &mut self.emails)?;
        normalize_name(&self.user_name, &mut self.display_name, &mut self.name)?;
        validate_structured_counts(&self)?;
        structured::normalize_phone_numbers(&mut self.phone_numbers)?;
        structured::normalize_addresses(&mut self.addresses)?;
        structured::normalize_roles(&mut self.roles, "roles")?;
        structured::normalize_entitlements(&mut self.entitlements)?;
        structured::normalize_enterprise(&mut self.enterprise)?;
        if serde_json::to_vec(&self).map_or(usize::MAX, |value| value.len()) > 65_535 {
            return Err(invalid("SCIM User attributes exceed the supported serialized size"));
        }
        self.meta = None;
        self.id = None;
        Ok(self)
    }

    pub fn primary_email(&self) -> &str {
        self.emails
            .iter()
            .find(|email| email.primary == Some(true))
            .or_else(|| self.emails.first())
            .map(|email| email.value.as_str())
            .unwrap_or(&self.user_name)
    }
}

fn normalize_emails(user_name: &str, emails: &mut Vec<ScimEmail>) -> Result<(), ScimError> {
    if emails.len() > 20 {
        return Err(invalid("emails must contain at most 20 values"));
    }
    if emails.is_empty() {
        if !looks_like_email(user_name) {
            return Err(invalid(
                "emails must contain an email when userName is not an email address",
            ));
        }
        emails.push(ScimEmail {
            value: user_name.into(),
            primary: Some(true),
            kind: None,
        });
    }
    let primary_count = emails
        .iter()
        .filter(|email| email.primary == Some(true))
        .count();
    if primary_count > 1 {
        return Err(invalid("emails cannot contain multiple primary values"));
    }
    for email in emails.iter_mut() {
        if email.value.is_empty()
            || email.value.chars().count() > 254
            || !looks_like_email(&email.value)
        {
            return Err(invalid("Invalid email address"));
        }
        email.value.make_ascii_lowercase();
        email.kind = optional_bounded(email.kind.take(), 256, "emails.type")?
            .map(|kind| kind.to_lowercase());
    }
    let primary = if primary_count == 0 {
        emails
            .iter()
            .position(|email| email.kind.as_deref() == Some("work"))
            .unwrap_or(0)
    } else {
        emails
            .iter()
            .position(|email| email.primary == Some(true))
            .expect("the explicit primary email was counted")
    };
    for (index, email) in emails.iter_mut().enumerate() {
        email.primary = Some(index == primary);
    }
    validate_email_uniqueness(emails)
}

fn validate_email_uniqueness(emails: &[ScimEmail]) -> Result<(), ScimError> {
    let mut tuples = std::collections::HashSet::new();
    let mut types = std::collections::HashSet::new();
    for email in emails {
        let tuple = (
            email.kind.as_deref().map(str::to_lowercase),
            email.value.to_lowercase(),
        );
        if !tuples.insert(tuple) {
            return Err(invalid("emails cannot contain duplicate type and value pairs"));
        }
        if let Some(kind) = &email.kind
            && !types.insert(kind.to_lowercase())
        {
            return Err(invalid("emails cannot contain duplicate defined types"));
        }
    }
    Ok(())
}

fn normalize_name(
    user_name: &str,
    display_name: &mut Option<String>,
    name: &mut Option<ScimName>,
) -> Result<(), ScimError> {
    let mut normalized = name.take().unwrap_or_default();
    for value in [
        &mut normalized.given_name,
        &mut normalized.family_name,
        &mut normalized.middle_name,
        &mut normalized.honorific_prefix,
        &mut normalized.honorific_suffix,
    ] {
        *value = optional_bounded(value.take(), 256, "name")?;
    }
    normalized.formatted =
        optional_bounded(normalized.formatted.take(), 1024, "name.formatted")?;
    let composed = [
        normalized.given_name.as_deref(),
        normalized.family_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join(" ");
    let display = display_name
        .clone()
        .or_else(|| normalized.formatted.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| if composed.is_empty() { user_name.into() } else { composed });
    if normalized.formatted.is_none() {
        normalized.formatted = Some(display.clone());
    }
    *display_name = Some(display);
    *name = Some(normalized);
    Ok(())
}

fn validate_structured_counts(user: &ScimUser) -> Result<(), ScimError> {
    if user.phone_numbers.len() > 10
        || user.roles.len() > 10
        || user.entitlements.len() > 10
        || user.addresses.len() > 10
    {
        return Err(invalid(
            "SCIM structured attributes contain too many values",
        ));
    }
    Ok(())
}

fn validate_user_schemas(schemas: &[String], enterprise: bool) -> Result<(), ScimError> {
    if schemas.is_empty() || schemas.len() > 2 {
        return Err(invalid("schemas must contain the core SCIM User schema"));
    }
    let mut unique = std::collections::HashSet::new();
    for schema in schemas {
        if !matches!(schema.as_str(), SCIM_USER_SCHEMA | SCIM_ENTERPRISE_USER_SCHEMA) {
            return Err(invalid(format!("Unsupported SCIM User schema {schema}")));
        }
        if !unique.insert(schema.as_str()) {
            return Err(invalid(format!(
                "SCIM User schema {schema} must not be duplicated"
            )));
        }
    }
    if !schemas.iter().any(|schema| schema == SCIM_USER_SCHEMA) {
        return Err(invalid(format!("schemas must contain {SCIM_USER_SCHEMA}")));
    }
    if enterprise
        && !schemas
            .iter()
            .any(|schema| schema == SCIM_ENTERPRISE_USER_SCHEMA)
    {
        return Err(invalid(format!(
            "The Enterprise User extension requires {SCIM_ENTERPRISE_USER_SCHEMA} in schemas"
        )));
    }
    Ok(())
}

fn bounded(value: String, max: usize, field: &str) -> Result<String, ScimError> {
    let value = value.trim().to_owned();
    if value.is_empty() || value.chars().count() > max {
        Err(invalid(format!(
            "{field} must contain between 1 and {max} characters"
        )))
    } else {
        Ok(value)
    }
}

fn optional_bounded(
    value: Option<String>,
    max: usize,
    field: &str,
) -> Result<Option<String>, ScimError> {
    value.map(|value| bounded(value, max, field)).transpose()
}

fn invalid(detail: impl Into<String>) -> ScimError {
    ScimError::typed(400, detail, ScimErrorType::InvalidValue)
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !value.chars().any(char::is_whitespace)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimMeta {
    pub resource_type: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "super::timestamp::serialize_optional"
    )]
    pub created: Option<DateTime<Utc>>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "super::timestamp::serialize_optional"
    )]
    pub last_modified: Option<DateTime<Utc>>,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimListResponse<T> {
    pub schemas: [&'static str; 1],
    pub total_results: usize,
    pub start_index: usize,
    pub items_per_page: usize,
    #[serde(rename = "Resources")]
    pub resources: Vec<T>,
}

impl<T> ScimListResponse<T> {
    pub fn new(total_results: usize, start_index: usize, resources: Vec<T>) -> Self {
        let items_per_page = resources.len();
        Self {
            schemas: [SCIM_LIST_RESPONSE_SCHEMA],
            total_results,
            start_index,
            items_per_page,
            resources,
        }
    }
}
