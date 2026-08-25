//! Managed SMS client compatible with `@better-auth/infra` 0.4.3.
//!
//! Calls disclose the recipient number, verification code, selected template,
//! and optional end-user IP to the configured Better Auth infrastructure
//! origin. Treat custom origins as trusted recipients of that data and the
//! configured bearer credential.

mod config;
mod model;
mod sender;
mod templates;

pub use config::{SmsApiOptions, SmsConfig};
pub use model::{SendSmsOptions, SendSmsResult};
pub use sender::{SmsSender, create_sms_sender, send_sms};
pub use templates::{SMS_TEMPLATES, SmsTemplateId, SmsTemplateVariables};
