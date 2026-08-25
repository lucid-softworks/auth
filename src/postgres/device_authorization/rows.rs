use crate::{
    AuthError,
    device_authorization::{DeviceCode, DeviceCodeStatus},
};
use chrono::{DateTime, Utc};
use sqlx::FromRow;
use std::str::FromStr;
use uuid::Uuid;

pub(super) const STANDALONE_FIELDS: &[(&str, &str)] = &[
    ("id", "id"),
    ("deviceCode", "device_code"),
    ("userCode", "user_code"),
    ("userId", "user_id"),
    ("expiresAt", "expires_at"),
    ("status", "status"),
    ("lastPolledAt", "last_polled_at"),
    ("pollingInterval", "polling_interval"),
    ("clientId", "client_id"),
    ("scope", "scope"),
];
pub(super) const OAUTH_FIELDS: &[(&str, &str)] = &[
    ("resources", "resources"),
    ("oauthClientId", "oauth_client_id"),
];

#[derive(FromRow)]
pub(super) struct DeviceCodeRow {
    id: Uuid,
    device_code: String,
    user_code: String,
    user_id: Option<Uuid>,
    expires_at: DateTime<Utc>,
    status: String,
    last_polled_at: Option<DateTime<Utc>>,
    polling_interval: Option<f64>,
    client_id: Option<String>,
    scope: Option<String>,
    resources: Option<Vec<String>>,
    oauth_client_id: Option<String>,
}

impl TryFrom<DeviceCodeRow> for DeviceCode {
    type Error = AuthError;

    fn try_from(row: DeviceCodeRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            device_code: row.device_code,
            user_code: row.user_code,
            user_id: row.user_id,
            expires_at: row.expires_at,
            status: DeviceCodeStatus::from_str(&row.status)
                .map_err(|error| AuthError::Storage(error.to_string()))?,
            last_polled_at: row.last_polled_at,
            polling_interval: row.polling_interval,
            client_id: row.client_id,
            scope: row.scope,
            resources: row.resources,
            oauth_client_id: row.oauth_client_id,
        })
    }
}
