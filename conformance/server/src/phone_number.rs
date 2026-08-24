use async_trait::async_trait;
use axum::{
    Extension, Json,
    extract::Path,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use lucid_auth::{
    AuthError, PhoneNumberMessage, PhoneNumberOtpSender, PhoneNumberRequestContext,
    PhoneNumberTemporaryEmail, PhoneNumberTemporaryName,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
pub(crate) struct ConformancePhoneNumberMessages {
    pub(crate) verification: Arc<Mutex<Vec<PhoneNumberMessage>>>,
    pub(crate) password_reset: Arc<Mutex<Vec<PhoneNumberMessage>>>,
}

pub(crate) struct ConformancePhoneNumberSender {
    pub(crate) messages: Arc<Mutex<Vec<PhoneNumberMessage>>>,
}

pub(crate) struct ConformancePhoneNumberTemporaryEmail;

pub(crate) struct ConformancePhoneNumberTemporaryName;

pub(crate) async fn captured(
    Extension(fixture): Extension<super::Fixture>,
    Path((kind, phone_number)): Path<(String, String)>,
) -> Response {
    let messages = match kind.as_str() {
        "verification" => &fixture.phone_number_otps,
        "password-reset" => &fixture.phone_number_reset_otps,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let sent = messages.lock().await;
    match sent
        .iter()
        .rev()
        .find(|message| message.phone_number == phone_number)
    {
        Some(message) => Json(serde_json::json!({ "code": message.code })).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[async_trait]
impl PhoneNumberOtpSender for ConformancePhoneNumberSender {
    async fn send(
        &self,
        message: PhoneNumberMessage,
        _context: PhoneNumberRequestContext,
    ) -> Result<(), AuthError> {
        self.messages.lock().await.push(message);
        Ok(())
    }
}

#[async_trait]
impl PhoneNumberTemporaryEmail for ConformancePhoneNumberTemporaryEmail {
    async fn generate(&self, phone_number: &str) -> Result<String, AuthError> {
        Ok(format!("phone-{phone_number}@example.com"))
    }
}

#[async_trait]
impl PhoneNumberTemporaryName for ConformancePhoneNumberTemporaryName {
    async fn generate(&self, phone_number: &str) -> Result<String, AuthError> {
        Ok(format!("Phone {phone_number}"))
    }
}
