use serde::Serialize;
use std::{collections::BTreeMap, sync::LazyLock};

/// Template identifiers published by `@better-auth/infra` 0.4.3.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum EmailTemplateId {
    #[serde(rename = "verify-email")]
    VerifyEmail,
    #[serde(rename = "reset-password")]
    ResetPassword,
    #[serde(rename = "change-email")]
    ChangeEmail,
    #[serde(rename = "sign-in-otp")]
    SignInOtp,
    #[serde(rename = "verify-email-otp")]
    VerifyEmailOtp,
    #[serde(rename = "reset-password-otp")]
    ResetPasswordOtp,
    #[serde(rename = "magic-link")]
    MagicLink,
    #[serde(rename = "two-factor")]
    TwoFactor,
    #[serde(rename = "invitation")]
    Invitation,
    #[serde(rename = "application-invite")]
    ApplicationInvite,
    #[serde(rename = "delete-account")]
    DeleteAccount,
    #[serde(rename = "stale-account-user")]
    StaleAccountUser,
    #[serde(rename = "stale-account-admin")]
    StaleAccountAdmin,
}

/// Empty runtime variable metadata retained by the published template table.
#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize)]
pub struct EmptyEmailTemplateVariables {}

/// Runtime value for each entry in [`EMAIL_TEMPLATES`].
#[derive(Clone, Copy, Default, Eq, PartialEq, Serialize)]
pub struct EmailTemplateDefinition {
    pub variables: EmptyEmailTemplateVariables,
}

/// The exact 13-entry runtime template inventory.
pub static EMAIL_TEMPLATES: LazyLock<BTreeMap<EmailTemplateId, EmailTemplateDefinition>> =
    LazyLock::new(|| {
        [
            EmailTemplateId::VerifyEmail,
            EmailTemplateId::ResetPassword,
            EmailTemplateId::ChangeEmail,
            EmailTemplateId::SignInOtp,
            EmailTemplateId::VerifyEmailOtp,
            EmailTemplateId::ResetPasswordOtp,
            EmailTemplateId::MagicLink,
            EmailTemplateId::TwoFactor,
            EmailTemplateId::Invitation,
            EmailTemplateId::ApplicationInvite,
            EmailTemplateId::DeleteAccount,
            EmailTemplateId::StaleAccountUser,
            EmailTemplateId::StaleAccountAdmin,
        ]
        .into_iter()
        .map(|id| (id, EmailTemplateDefinition::default()))
        .collect()
    });

/// A typed variable set whose associated identifier selects the wire template.
///
/// The managed client serializes variables but performs no additional runtime
/// validation, matching the source package's declaration-only checks.
pub trait EmailTemplateVariables: sealed::Sealed + Serialize + Send + Sync {
    const TEMPLATE: EmailTemplateId;
}

mod sealed {
    pub trait Sealed {}
}

macro_rules! template_variables {
    (
        $name:ident, $template:ident,
        required { $( $required:ident ),+ $(,)? },
        optional { $( $optional:ident ),* $(,)? }
    ) => {
        #[derive(Clone, Eq, PartialEq, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub struct $name {
            $( pub $required: String, )+
            $( #[serde(skip_serializing_if = "Option::is_none")] pub $optional: Option<String>, )*
        }

        impl $name {
            pub fn new($( $required: impl Into<String> ),+) -> Self {
                Self {
                    $( $required: $required.into(), )+
                    $( $optional: None, )*
                }
            }
        }

        impl EmailTemplateVariables for $name {
            const TEMPLATE: EmailTemplateId = EmailTemplateId::$template;
        }

        impl sealed::Sealed for $name {}
    };
}

template_variables!(
    VerifyEmailVariables,
    VerifyEmail,
    required {
        verification_url,
        user_email
    },
    optional {
        verification_code,
        user_name,
        app_name,
        expiration_minutes
    }
);
template_variables!(
    ResetPasswordVariables,
    ResetPassword,
    required {
        reset_link,
        user_email
    },
    optional {
        user_name,
        app_name,
        expiration_minutes
    }
);
template_variables!(
    ChangeEmailVariables,
    ChangeEmail,
    required {
        confirmation_link,
        new_email,
        current_email
    },
    optional {
        user_name,
        app_name,
        expiration_minutes
    }
);
template_variables!(
    SignInOtpVariables,
    SignInOtp,
    required {
        otp_code,
        user_email
    },
    optional {
        app_name,
        expiration_minutes
    }
);
template_variables!(
    VerifyEmailOtpVariables,
    VerifyEmailOtp,
    required {
        otp_code,
        user_email
    },
    optional {
        app_name,
        expiration_minutes
    }
);
template_variables!(
    ResetPasswordOtpVariables,
    ResetPasswordOtp,
    required {
        otp_code,
        user_email
    },
    optional {
        app_name,
        expiration_minutes
    }
);
template_variables!(
    MagicLinkVariables,
    MagicLink,
    required {
        magic_link,
        user_email
    },
    optional {
        app_name,
        expiration_minutes
    }
);
template_variables!(
    TwoFactorVariables,
    TwoFactor,
    required {
        otp_code,
        user_email
    },
    optional {
        user_name,
        app_name,
        expiration_minutes
    }
);
template_variables!(
    InvitationVariables,
    Invitation,
    required {
        invite_link,
        inviter_name,
        inviter_email,
        organization_name,
        role
    },
    optional {
        app_name,
        expiration_days
    }
);
template_variables!(
    ApplicationInviteVariables,
    ApplicationInvite,
    required {
        invite_link,
        inviter_name,
        inviter_email,
        invitee_email
    },
    optional {
        app_name,
        expiration_days
    }
);
template_variables!(
    DeleteAccountVariables,
    DeleteAccount,
    required {
        deletion_link,
        user_email
    },
    optional {
        user_name,
        app_name,
        expiration_minutes
    }
);
template_variables!(
    StaleAccountUserVariables,
    StaleAccountUser,
    required {
        user_email,
        days_since_last_active,
        login_time
    },
    optional {
        user_name,
        app_name,
        login_location,
        login_device,
        login_ip
    }
);
template_variables!(
    StaleAccountAdminVariables,
    StaleAccountAdmin,
    required {
        user_email,
        user_id,
        days_since_last_active,
        login_time,
        admin_email
    },
    optional {
        user_name,
        app_name,
        login_location,
        login_device,
        login_ip
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn runtime_inventory_has_exact_empty_variable_entries() {
        assert_eq!(EMAIL_TEMPLATES.len(), 13);
        assert_eq!(
            serde_json::to_value(&*EMAIL_TEMPLATES).unwrap(),
            json!({
                "verify-email": { "variables": {} },
                "reset-password": { "variables": {} },
                "change-email": { "variables": {} },
                "sign-in-otp": { "variables": {} },
                "verify-email-otp": { "variables": {} },
                "reset-password-otp": { "variables": {} },
                "magic-link": { "variables": {} },
                "two-factor": { "variables": {} },
                "invitation": { "variables": {} },
                "application-invite": { "variables": {} },
                "delete-account": { "variables": {} },
                "stale-account-user": { "variables": {} },
                "stale-account-admin": { "variables": {} }
            })
        );
    }

    #[test]
    fn variables_use_the_published_camel_case_names() {
        let mut variables = VerifyEmailVariables::new("https://app.test/verify", "a@example.com");
        variables.verification_code = Some("123456".into());

        assert_eq!(
            serde_json::to_value(variables).unwrap(),
            json!({
                "verificationUrl": "https://app.test/verify",
                "userEmail": "a@example.com",
                "verificationCode": "123456"
            })
        );
    }
}
