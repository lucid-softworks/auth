use crate::OAuthAccount;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedAccount {
    pub id: String,
    pub provider_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub issuer: String,
    pub account_id: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, Value>,
}

impl From<OAuthAccount> for LinkedAccount {
    fn from(account: OAuthAccount) -> Self {
        Self {
            id: account.id,
            provider_id: account.provider_id,
            created_at: account.created_at,
            updated_at: account.updated_at,
            issuer: account.issuer,
            account_id: account.account_id,
            user_id: account.user_id,
            scopes: parse_scopes(account.scope.as_deref()),
            additional_fields: account.additional_fields,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderTokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountInfo {
    pub user: ProviderAccountUser,
    pub data: Value,
    pub account: ProviderAccountIdentity,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountUser {
    pub name: String,
    pub email: String,
    pub image: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderAccountIdentity {
    pub id: String,
    pub provider_id: String,
    pub issuer: String,
    pub account_id: String,
}

pub(super) fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect()
}
