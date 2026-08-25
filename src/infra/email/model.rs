use super::EmailTemplateVariables;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Type-safe single-recipient send options.
pub struct SendEmailOptions<V: EmailTemplateVariables> {
    pub to: String,
    pub variables: V,
    pub subject: Option<String>,
}

impl<V: EmailTemplateVariables> SendEmailOptions<V> {
    pub fn new(to: impl Into<String>, variables: V) -> Self {
        Self {
            to: to.into(),
            variables,
            subject: None,
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }
}

/// The normalized result of one managed email request.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

impl SendEmailResult {
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

/// One recipient in a managed bulk email request.
pub struct BulkEmailRecipient<V: EmailTemplateVariables> {
    pub to: String,
    pub variables: Option<V>,
}

impl<V: EmailTemplateVariables> BulkEmailRecipient<V> {
    pub fn new(to: impl Into<String>, variables: V) -> Self {
        Self {
            to: to.into(),
            variables: Some(variables),
        }
    }

    pub fn without_variables(to: impl Into<String>) -> Self {
        Self {
            to: to.into(),
            variables: None,
        }
    }
}

/// Type-safe bulk send options for one shared template.
pub struct SendBulkEmailsOptions<V: EmailTemplateVariables> {
    pub emails: Vec<BulkEmailRecipient<V>>,
    pub subject: Option<String>,
    pub variables: BTreeMap<String, String>,
}

impl<V: EmailTemplateVariables> SendBulkEmailsOptions<V> {
    pub fn new(emails: Vec<BulkEmailRecipient<V>>) -> Self {
        Self {
            emails,
            subject: None,
            variables: BTreeMap::new(),
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_shared_variables(mut self, variables: BTreeMap<String, String>) -> Self {
        self.variables = variables;
        self
    }
}

/// Declared failure member used when the client synthesizes per-address errors.
#[derive(Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailFailure {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<Value>,
}

impl EmailFailure {
    pub(super) fn error(message: impl Into<Value>) -> Self {
        Self {
            error: Some(message.into()),
            message_id: None,
        }
    }
}

/// The normalized result of one managed bulk email request.
#[derive(Clone, PartialEq, Serialize)]
pub struct SendBulkEmailsResult {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failures: Option<Value>,
}

impl SendBulkEmailsResult {
    pub(super) fn from_response(success: bool, failures: Option<Value>) -> Self {
        Self { success, failures }
    }

    pub(super) fn failure_for<V: EmailTemplateVariables>(
        emails: &[BulkEmailRecipient<V>],
        message: impl Into<Value>,
    ) -> Self {
        let message = message.into();
        let mut failures = serde_json::Map::new();
        for email in emails {
            failures.insert(
                email.to.clone(),
                serde_json::to_value([EmailFailure::error(message.clone())])
                    .expect("email failure values are serializable"),
            );
        }
        Self {
            success: false,
            failures: Some(Value::Object(failures)),
        }
    }
}

/// An unvalidated member returned by the managed template-list operation.
pub type EmailTemplate = Value;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::email::ResetPasswordVariables;
    use serde_json::json;

    #[test]
    fn duplicate_failure_addresses_collapse_like_object_from_entries() {
        let emails: Vec<BulkEmailRecipient<ResetPasswordVariables>> = vec![
            BulkEmailRecipient::new(
                "same@example.com",
                ResetPasswordVariables::new("first", "same@example.com"),
            ),
            BulkEmailRecipient::new(
                "same@example.com",
                ResetPasswordVariables::new("second", "same@example.com"),
            ),
        ];

        let result = SendBulkEmailsResult::failure_for(&emails, "unavailable");
        assert_eq!(
            result.failures,
            Some(json!({ "same@example.com": [{ "error": "unavailable" }] }))
        );
    }

    #[test]
    fn failure_addresses_keep_first_insertion_order_when_duplicates_replace() {
        let emails: Vec<BulkEmailRecipient<ResetPasswordVariables>> = vec![
            BulkEmailRecipient::without_variables("z@example.com"),
            BulkEmailRecipient::without_variables("a@example.com"),
            BulkEmailRecipient::without_variables("z@example.com"),
        ];

        let result = SendBulkEmailsResult::failure_for(&emails, "unavailable");
        assert_eq!(
            serde_json::to_string(&result.failures.unwrap()).unwrap(),
            r#"{"z@example.com":[{"error":"unavailable"}],"a@example.com":[{"error":"unavailable"}]}"#
        );
    }
}
