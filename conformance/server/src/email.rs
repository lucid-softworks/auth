use async_trait::async_trait;
use lucid_auth::{AuthError, VerificationEmail, VerificationEmailSender};
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) struct ConformanceEmailSender(pub(crate) Arc<Mutex<Vec<VerificationEmail>>>);

#[async_trait]
impl VerificationEmailSender for ConformanceEmailSender {
    async fn send(&self, email: VerificationEmail) -> Result<(), AuthError> {
        self.0.lock().await.push(email);
        Ok(())
    }
}
