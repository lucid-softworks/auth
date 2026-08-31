use super::SentinelSecurityClient;
use crate::infra::{
    dash::IdentificationContext,
    email::{
        EmailApiOptions, EmailConfig, SendEmailOptions, StaleAccountAdminVariables,
        StaleAccountUserVariables, create_email_sender,
    },
};
use chrono::Utc;

impl SentinelSecurityClient {
    pub async fn notify_stale_account_user(
        &self,
        email: &str,
        name: Option<&str>,
        days_since_last_active: u64,
        identification: &IdentificationContext,
    ) {
        let mut variables = StaleAccountUserVariables::new(
            email,
            days_since_last_active.to_string(),
            login_time(),
        );
        variables.user_name = Some(name.unwrap_or("User").to_owned());
        variables.login_location = Some(login_location(identification));
        variables.login_device = Some(login_device(identification));
        variables.login_ip = Some(identification.ip.as_deref().unwrap_or("Unknown").to_owned());
        let _ = self
            .email_sender()
            .send(SendEmailOptions::new(email, variables))
            .await;
    }

    pub async fn notify_stale_account_admin(
        &self,
        admin_email: &str,
        user_id: &str,
        user_email: &str,
        user_name: Option<&str>,
        days_since_last_active: u64,
        identification: &IdentificationContext,
    ) {
        let mut variables = StaleAccountAdminVariables::new(
            user_email,
            user_id,
            days_since_last_active.to_string(),
            login_time(),
            admin_email,
        );
        variables.user_name = Some(user_name.unwrap_or("User").to_owned());
        variables.login_location = Some(login_location(identification));
        variables.login_device = Some(login_device(identification));
        variables.login_ip = Some(identification.ip.as_deref().unwrap_or("Unknown").to_owned());
        let _ = self
            .email_sender()
            .send(SendEmailOptions::new(admin_email, variables))
            .await;
    }

    fn email_sender(&self) -> crate::infra::email::EmailSender {
        let timeout = u64::try_from(self.connection.api_timeout.as_millis()).unwrap_or(u64::MAX);
        create_email_sender(Some(EmailConfig {
            api_key: Some(self.connection.api_key().to_owned()),
            api_url: Some(self.connection.api_url.clone()),
            api_options: Some(EmailApiOptions {
                timeout: Some(timeout),
            }),
            ..EmailConfig::default()
        }))
    }
}

fn login_time() -> String {
    format!("{} UTC", Utc::now().format("%B %-d, %Y at %-I:%M %p"))
}

fn login_location(identification: &IdentificationContext) -> String {
    let location = identification
        .identification
        .as_ref()
        .and_then(|identification| identification.location.as_ref());
    match (
        location.and_then(|location| location.city.as_deref()),
        location.and_then(|location| location.country.as_ref()),
    ) {
        (Some(city), Some(country)) => format!("{city}, {}", country.code),
        (_, Some(country)) => country.name.clone(),
        _ => "Unknown".into(),
    }
}

fn login_device(identification: &IdentificationContext) -> String {
    let browser = identification
        .identification
        .as_ref()
        .map(|identification| &identification.browser);
    match (
        browser
            .and_then(|browser| browser.get("name"))
            .and_then(|value| value.as_str()),
        browser
            .and_then(|browser| browser.get("os"))
            .and_then(|value| value.as_str()),
    ) {
        (Some(name), Some(os)) => format!("{name} on {os}"),
        _ => "Unknown device".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infra::dash::{Identification, IdentificationCountry, IdentificationGeo};
    use serde_json::json;

    #[test]
    fn renders_the_published_location_and_device_fallbacks() {
        let context = IdentificationContext {
            identification: Some(Identification {
                visitor_id: "visitor".into(),
                request_id: "request".into(),
                timestamp: 0.0,
                url: "https://app.example".into(),
                ip: Some("203.0.113.1".into()),
                location: Some(IdentificationGeo {
                    lat: 0.0,
                    lng: 0.0,
                    city: Some("London".into()),
                    region: None,
                    postal_code: None,
                    country: Some(IdentificationCountry {
                        code: "GB".into(),
                        name: "United Kingdom".into(),
                    }),
                    timezone: None,
                }),
                browser: json!({"name": "Safari", "os": "macOS"}),
                confidence: 1.0,
                incognito: false,
                bot: "none".into(),
            }),
            ..IdentificationContext::default()
        };
        assert_eq!(login_location(&context), "London, GB");
        assert_eq!(login_device(&context), "Safari on macOS");
        assert_eq!(login_location(&IdentificationContext::default()), "Unknown");
    }
}
