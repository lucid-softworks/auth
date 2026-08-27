use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Durable device-authorization request owned by the plugin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceCode {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub user_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub status: DeviceCodeStatus,
    pub last_polled_at: Option<DateTime<Utc>>,
    /// Minimum polling interval in milliseconds.
    pub polling_interval: Option<f64>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    /// Present only when the OAuth Provider device grant is installed.
    pub resources: Option<Vec<String>>,
    /// Present only when the OAuth Provider device grant is installed.
    pub oauth_client_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceCodeStatus {
    Pending,
    Approved,
    Denied,
}

impl DeviceCodeStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
        }
    }
}

impl fmt::Display for DeviceCodeStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DeviceCodeStatus {
    type Err = DeviceCodeStatusParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            _ => Err(DeviceCodeStatusParseError(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid device authorization status `{0}`")]
pub struct DeviceCodeStatusParseError(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCodeOwner {
    ClientId(String),
    OAuthClientId(String),
}

impl DeviceCodeOwner {
    pub fn matches(&self, code: &DeviceCode) -> bool {
        match self {
            Self::ClientId(client_id) => code.client_id.as_deref() == Some(client_id),
            Self::OAuthClientId(client_id) => code.oauth_client_id.as_deref() == Some(client_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_uses_upstream_storage_values() {
        for (status, value) in [
            (DeviceCodeStatus::Pending, "pending"),
            (DeviceCodeStatus::Approved, "approved"),
            (DeviceCodeStatus::Denied, "denied"),
        ] {
            assert_eq!(status.as_str(), value);
            assert_eq!(value.parse(), Ok(status));
        }
        assert!("APPROVED".parse::<DeviceCodeStatus>().is_err());
    }
}
