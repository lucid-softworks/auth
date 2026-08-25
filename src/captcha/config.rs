use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptchaProvider {
    CloudflareTurnstile,
    GoogleRecaptcha,
    HCaptcha,
    CaptchaFox,
}

impl CaptchaProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloudflareTurnstile => "cloudflare-turnstile",
            Self::GoogleRecaptcha => "google-recaptcha",
            Self::HCaptcha => "hcaptcha",
            Self::CaptchaFox => "captchafox",
        }
    }
}

#[derive(Clone)]
pub struct CloudflareTurnstileOptions {
    pub secret_key: String,
    pub endpoints: Option<Vec<String>>,
    pub site_verify_url_override: Option<String>,
    pub expected_action: Option<String>,
    pub allowed_hostnames: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct GoogleRecaptchaOptions {
    pub secret_key: String,
    pub endpoints: Option<Vec<String>>,
    pub site_verify_url_override: Option<String>,
    pub min_score: Option<f64>,
    pub expected_action: Option<String>,
    pub allowed_hostnames: Option<Vec<String>>,
}

#[derive(Clone)]
pub struct HCaptchaOptions {
    pub secret_key: String,
    pub endpoints: Option<Vec<String>>,
    pub site_verify_url_override: Option<String>,
    pub site_key: Option<String>,
}

#[derive(Clone)]
pub struct CaptchaFoxOptions {
    pub secret_key: String,
    pub endpoints: Option<Vec<String>>,
    pub site_verify_url_override: Option<String>,
    pub site_key: Option<String>,
}

macro_rules! base_options {
    ($name:ident) => {
        impl $name {
            pub fn new(secret_key: impl Into<String>) -> Self {
                Self {
                    secret_key: secret_key.into(),
                    endpoints: None,
                    site_verify_url_override: None,
                    ..Self::provider_defaults()
                }
            }
        }
    };
}

impl CloudflareTurnstileOptions {
    fn provider_defaults() -> Self {
        Self {
            secret_key: String::new(),
            endpoints: None,
            site_verify_url_override: None,
            expected_action: None,
            allowed_hostnames: None,
        }
    }
}
impl GoogleRecaptchaOptions {
    fn provider_defaults() -> Self {
        Self {
            secret_key: String::new(),
            endpoints: None,
            site_verify_url_override: None,
            min_score: None,
            expected_action: None,
            allowed_hostnames: None,
        }
    }
}
impl HCaptchaOptions {
    fn provider_defaults() -> Self {
        Self {
            secret_key: String::new(),
            endpoints: None,
            site_verify_url_override: None,
            site_key: None,
        }
    }
}
impl CaptchaFoxOptions {
    fn provider_defaults() -> Self {
        Self {
            secret_key: String::new(),
            endpoints: None,
            site_verify_url_override: None,
            site_key: None,
        }
    }
}

base_options!(CloudflareTurnstileOptions);
base_options!(GoogleRecaptchaOptions);
base_options!(HCaptchaOptions);
base_options!(CaptchaFoxOptions);

#[derive(Clone)]
pub enum CaptchaConfig {
    CloudflareTurnstile(CloudflareTurnstileOptions),
    GoogleRecaptcha(GoogleRecaptchaOptions),
    HCaptcha(HCaptchaOptions),
    CaptchaFox(CaptchaFoxOptions),
}

impl CaptchaConfig {
    pub const fn provider(&self) -> CaptchaProvider {
        match self {
            Self::CloudflareTurnstile(_) => CaptchaProvider::CloudflareTurnstile,
            Self::GoogleRecaptcha(_) => CaptchaProvider::GoogleRecaptcha,
            Self::HCaptcha(_) => CaptchaProvider::HCaptcha,
            Self::CaptchaFox(_) => CaptchaProvider::CaptchaFox,
        }
    }

    #[cfg(feature = "axum")]
    pub(crate) fn secret_key(&self) -> &str {
        match self {
            Self::CloudflareTurnstile(o) => &o.secret_key,
            Self::GoogleRecaptcha(o) => &o.secret_key,
            Self::HCaptcha(o) => &o.secret_key,
            Self::CaptchaFox(o) => &o.secret_key,
        }
    }

    pub(crate) fn endpoints(&self) -> Option<&[String]> {
        match self {
            Self::CloudflareTurnstile(o) => o.endpoints.as_deref(),
            Self::GoogleRecaptcha(o) => o.endpoints.as_deref(),
            Self::HCaptcha(o) => o.endpoints.as_deref(),
            Self::CaptchaFox(o) => o.endpoints.as_deref(),
        }
    }

    pub(crate) fn site_verify_url_override(&self) -> Option<&str> {
        match self {
            Self::CloudflareTurnstile(o) => o.site_verify_url_override.as_deref(),
            Self::GoogleRecaptcha(o) => o.site_verify_url_override.as_deref(),
            Self::HCaptcha(o) => o.site_verify_url_override.as_deref(),
            Self::CaptchaFox(o) => o.site_verify_url_override.as_deref(),
        }
    }
}

impl fmt::Debug for CaptchaConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptchaConfig")
            .field("provider", &self.provider())
            .field("secret_key", &"[REDACTED]")
            .field("endpoints", &self.endpoints())
            .field("site_verify_url_override", &self.site_verify_url_override())
            .finish_non_exhaustive()
    }
}
