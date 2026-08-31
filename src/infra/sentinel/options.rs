use crate::infra::dash::InfraConnectionOptions;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityAction {
    Log,
    Block,
    Challenge,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoAction {
    Block,
    Challenge,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailStrictness {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStuffingOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<ThresholdConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpossibleTravelOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_speed_kmh: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GeoBlockingOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_list: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_list: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<GeoAction>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum BooleanSecurityRule {
    Enabled(bool),
    Config { action: SecurityAction },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VelocityOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<ThresholdConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_signups_per_visitor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_password_resets_per_ip: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sign_ins_per_ip: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeTrialAbuseOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thresholds: Option<ThresholdConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_accounts_per_visitor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CompromisedPasswordOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_breach_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailValidationOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strictness: Option<EmailStrictness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_allowlist: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailNormalizationOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleUsersOptions {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_days: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<SecurityAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify_admin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_email: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_device_notification: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_stuffing: Option<CredentialStuffingOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impossible_travel: Option<ImpossibleTravelOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_blocking: Option<GeoBlockingOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_blocking: Option<BooleanSecurityRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspicious_ip_blocking: Option<BooleanSecurityRule>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub velocity: Option<VelocityOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_trial_abuse: Option<FreeTrialAbuseOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compromised_password: Option<CompromisedPasswordOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_validation: Option<EmailValidationOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_normalization: Option<EmailNormalizationOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stale_users: Option<StaleUsersOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_difficulty: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct SentinelOptions {
    pub connection: InfraConnectionOptions,
    pub security: SecurityOptions,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_only_the_published_security_shape() {
        let options = SecurityOptions {
            bot_blocking: Some(BooleanSecurityRule::Config {
                action: SecurityAction::Challenge,
            }),
            geo_blocking: Some(GeoBlockingOptions {
                allow_list: Some(vec!["GB".into()]),
                deny_list: None,
                action: Some(GeoAction::Block),
            }),
            challenge_difficulty: Some(21),
            ..SecurityOptions::default()
        };

        assert_eq!(
            serde_json::to_value(options).unwrap(),
            json!({
                "botBlocking": { "action": "challenge" },
                "geoBlocking": { "allowList": ["GB"], "action": "block" },
                "challengeDifficulty": 21
            })
        );
    }
}
