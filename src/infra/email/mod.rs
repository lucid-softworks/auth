//! Managed email client compatible with `@better-auth/infra` 0.4.3.
//!
//! Calls send message contents, recipient addresses, and template variables to
//! the configured Better Auth infrastructure origin. Treat custom origins as
//! trusted recipients of both that data and the configured bearer credential.

mod config;
mod model;
mod sender;
mod templates;

pub use config::{EmailApiOptions, EmailConfig};
pub use model::{
    BulkEmailRecipient, EmailFailure, EmailTemplate, SendBulkEmailsOptions, SendBulkEmailsResult,
    SendEmailOptions, SendEmailResult,
};
pub use sender::{EmailSender, create_email_sender, send_bulk_emails, send_email};
pub use templates::{
    ApplicationInviteVariables, ChangeEmailVariables, DeleteAccountVariables, EMAIL_TEMPLATES,
    EmailTemplateDefinition, EmailTemplateId, EmailTemplateVariables, EmptyEmailTemplateVariables,
    InvitationVariables, MagicLinkVariables, ResetPasswordOtpVariables, ResetPasswordVariables,
    SignInOtpVariables, StaleAccountAdminVariables, StaleAccountUserVariables, TwoFactorVariables,
    VerifyEmailOtpVariables, VerifyEmailVariables,
};
