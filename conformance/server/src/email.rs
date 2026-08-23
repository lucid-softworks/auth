use async_trait::async_trait;
use lucid_auth::{
    AuthError, MagicLinkEmail, MagicLinkRequestContext, MagicLinkSender, PasswordResetEmail,
    PasswordResetEmailSender, TwoFactorOtp, TwoFactorOtpSender, VerificationEmail,
    VerificationEmailSender,
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

#[derive(Clone)]
pub(crate) struct ConformanceOtpSender {
    pub(crate) messages: Arc<Mutex<Vec<TwoFactorOtp>>>,
}

#[derive(Default)]
pub(crate) struct ConformanceMessages {
    pub(crate) verification_emails: Arc<Mutex<Vec<VerificationEmail>>>,
    pub(crate) password_reset_emails: Arc<Mutex<Vec<PasswordResetEmail>>>,
    pub(crate) magic_links: Arc<Mutex<Vec<MagicLinkEmail>>>,
    pub(crate) two_factor_otps: Arc<Mutex<Vec<TwoFactorOtp>>>,
}

#[async_trait]
impl TwoFactorOtpSender for ConformanceOtpSender {
    async fn send(&self, otp: TwoFactorOtp) -> Result<(), AuthError> {
        self.messages.lock().await.push(otp);
        Ok(())
    }
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
