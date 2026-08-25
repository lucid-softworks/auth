use super::SmsTemplateId;
use serde::Serialize;
use serde_json::Value;

/// Options for one managed SMS request.
pub struct SendSmsOptions {
    pub to: String,
    pub code: String,
    pub template: Option<SmsTemplateId>,
    pub client_ip: Option<String>,
}

impl SendSmsOptions {
    pub fn new(to: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            code: code.into(),
            template: None,
            client_ip: None,
        }
    }

    pub fn with_template(mut self, template: SmsTemplateId) -> Self {
        self.template = Some(template);
        self
    }

    pub fn with_client_ip(mut self, client_ip: impl Into<String>) -> Self {
        self.client_ip = Some(client_ip.into());
        self
    }
}

/// The normalized result of one managed SMS request.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendSmsResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl SendSmsResult {
    pub(super) fn success(message_id: Option<Value>) -> Self {
        Self {
            success: true,
            message_id,
            error: None,
        }
    }

    pub(super) fn failure(error: impl Into<Value>) -> Self {
        Self {
            success: false,
            message_id: None,
            error: Some(error.into()),
        }
    }
}
