use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthProxyStatePackage {
    pub state: String,
    pub state_cookie: String,
    pub is_o_auth_proxy: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthProxyPayload {
    pub user_info: OAuthProxyUserInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<Value>,
    pub account: OAuthProxyAccount,
    pub state: String,
    #[serde(rename = "callbackURL")]
    pub callback_url: String,
    #[serde(rename = "newUserURL", skip_serializing_if = "Option::is_none")]
    pub new_user_url: Option<String>,
    #[serde(rename = "errorURL", skip_serializing_if = "Option::is_none")]
    pub error_url: Option<String>,
    #[serde(default)]
    pub disable_sign_up: bool,
    pub timestamp: i64,
}

impl OAuthProxyPayload {
    pub(crate) fn is_within_age(&self, now_millis: i64, max_age: chrono::Duration) -> bool {
        let age = (now_millis as f64 - self.timestamp as f64) / 1_000.0;
        age >= -10.0 && age <= max_age.num_milliseconds() as f64 / 1_000.0
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthProxyUserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthProxyAccount {
    pub provider_id: String,
    pub issuer: String,
    pub account_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn state_package_uses_better_auths_unusual_is_oauth_proxy_casing() {
        let value = serde_json::to_value(OAuthProxyStatePackage {
            state: "state".into(),
            state_cookie: "cookie".into(),
            is_o_auth_proxy: true,
        })
        .unwrap();
        assert_eq!(
            value,
            json!({"state":"state","stateCookie":"cookie","isOAuthProxy":true})
        );
    }

    #[test]
    fn profile_payload_uses_exact_callback_and_account_field_names() {
        let value = serde_json::to_value(OAuthProxyPayload {
            user_info: OAuthProxyUserInfo {
                id: "subject".into(),
                email: "user@example.com".into(),
                name: "Proxy User".into(),
                image: None,
                email_verified: Some(true),
            },
            profile: Some(json!({"login":"proxy"})),
            account: OAuthProxyAccount {
                provider_id: "github".into(),
                issuer: "https://github.com".into(),
                account_id: "subject".into(),
                access_token: Some("access".into()),
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: Some("read:user,user:email".into()),
            },
            state: "state".into(),
            callback_url: "https://app.example/done".into(),
            new_user_url: Some("https://app.example/welcome".into()),
            error_url: None,
            disable_sign_up: false,
            timestamp: 1_725_000_000_000,
        })
        .unwrap();
        assert_eq!(value["callbackURL"], "https://app.example/done");
        assert_eq!(value["newUserURL"], "https://app.example/welcome");
        assert_eq!(value["account"]["providerId"], "github");
        assert_eq!(value["account"]["accountId"], "subject");
        assert_eq!(value["userInfo"]["emailVerified"], true);
        assert!(value.get("errorURL").is_none());
    }

    #[test]
    fn age_window_includes_boundaries_and_rejects_more_than_ten_seconds_future() {
        let payload = OAuthProxyPayload {
            user_info: OAuthProxyUserInfo {
                id: String::new(),
                email: String::new(),
                name: String::new(),
                image: None,
                email_verified: None,
            },
            profile: None,
            account: OAuthProxyAccount {
                provider_id: String::new(),
                issuer: String::new(),
                account_id: String::new(),
                access_token: None,
                refresh_token: None,
                id_token: None,
                access_token_expires_at: None,
                refresh_token_expires_at: None,
                scope: None,
            },
            state: String::new(),
            callback_url: String::new(),
            new_user_url: None,
            error_url: None,
            disable_sign_up: false,
            timestamp: 1_000_000,
        };
        assert!(payload.is_within_age(1_060_000, chrono::Duration::seconds(60)));
        assert!(payload.is_within_age(990_000, chrono::Duration::seconds(60)));
        assert!(!payload.is_within_age(1_060_001, chrono::Duration::seconds(60)));
        assert!(!payload.is_within_age(989_999, chrono::Duration::seconds(60)));
    }
}
