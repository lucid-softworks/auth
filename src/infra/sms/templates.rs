use serde::Serialize;
use std::{collections::BTreeMap, sync::LazyLock};

/// Template identifiers published by `@better-auth/infra` 0.4.3.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SmsTemplateId {
    #[serde(rename = "phone-verification")]
    PhoneVerification,
    #[serde(rename = "two-factor")]
    TwoFactor,
    #[serde(rename = "sign-in-otp")]
    SignInOtp,
}

/// The exact three-entry runtime template inventory.
pub static SMS_TEMPLATES: LazyLock<BTreeMap<SmsTemplateId, serde_json::Value>> =
    LazyLock::new(|| {
        [
            SmsTemplateId::PhoneVerification,
            SmsTemplateId::TwoFactor,
            SmsTemplateId::SignInOtp,
        ]
        .into_iter()
        .map(|id| (id, serde_json::json!({ "variables": {} })))
        .collect()
    });

/// The declaration-only variable shape published for all three SMS templates.
///
/// The callable managed SMS API accepts `code` directly on [`SendSmsOptions`]
/// and has no variables input.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SmsTemplateVariables {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_minutes: Option<String>,
}

impl SmsTemplateVariables {
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            app_name: None,
            expiration_minutes: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_inventory_has_exact_empty_variable_entries() {
        assert_eq!(SMS_TEMPLATES.len(), 3);
        assert_eq!(
            serde_json::to_value(&*SMS_TEMPLATES).unwrap(),
            json!({
                "phone-verification": { "variables": {} },
                "two-factor": { "variables": {} },
                "sign-in-otp": { "variables": {} }
            })
        );
    }

    #[test]
    fn declaration_variable_shape_uses_strings_and_omits_absent_members() {
        assert_eq!(
            serde_json::to_value(SmsTemplateVariables::new("123456")).unwrap(),
            json!({ "code": "123456" })
        );
    }
}
