use crate::VerificationValue;

const PREFIXES: &[&str] = &[
    "email-verification-otp-",
    "sign-in-otp-",
    "forget-password-otp-",
    "phone-verification-otp-",
];

pub(super) fn capture(verification: &VerificationValue) -> Option<(String, String)> {
    let otp = verification.value.split(':').next()?.to_owned();
    if otp.is_empty() || verification.identifier.is_empty() {
        return None;
    }
    let mut identifier = verification.identifier.as_str();
    for prefix in PREFIXES {
        if let Some(stripped) = identifier.strip_prefix(prefix) {
            identifier = stripped;
            break;
        }
    }
    Some((identifier.to_owned(), otp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn projects_value_before_splitting_and_strips_one_prefix() {
        let verification =
            VerificationValue::new("sign-in-otp-user@example.com", "123456:2", Utc::now());
        assert_eq!(
            capture(&verification),
            Some(("user@example.com".into(), "123456".into()))
        );
    }
}
