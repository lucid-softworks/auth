use async_trait::async_trait;
use lucid_auth::{
    AuthError, MagicLinkEmail, MagicLinkRequestContext, MagicLinkSender, PasswordResetEmail,
    PasswordResetEmailSender, VerificationEmail, VerificationEmailSender,
};
use std::sync::Arc;
use tokio::sync::Mutex;

pub(crate) struct ConformanceEmailSender {
    pub(crate) verification: Arc<Mutex<Vec<VerificationEmail>>>,
    pub(crate) password_reset: Arc<Mutex<Vec<PasswordResetEmail>>>,
}

pub(crate) struct ConformanceMagicLinkSender {
    pub(crate) messages: Arc<Mutex<Vec<MagicLinkEmail>>>,
}

#[async_trait]
impl MagicLinkSender for ConformanceMagicLinkSender {
    async fn send(
        &self,
        email: MagicLinkEmail,
        _context: MagicLinkRequestContext,
    ) -> Result<(), AuthError> {
        self.messages.lock().await.push(email);
        Ok(())
    }
}

#[async_trait]
impl VerificationEmailSender for ConformanceEmailSender {
    async fn send(&self, email: VerificationEmail) -> Result<(), AuthError> {
        self.verification.lock().await.push(email);
        Ok(())
    }
}

#[async_trait]
impl PasswordResetEmailSender for ConformanceEmailSender {
    async fn send(&self, email: PasswordResetEmail) -> Result<(), AuthError> {
        self.password_reset.lock().await.push(email);
        Ok(())
    }
}
