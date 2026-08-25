use super::DeviceAuthorizationSchema;
use crate::AuthError;
use async_trait::async_trait;
use std::{fmt, sync::Arc};

pub const DEFAULT_EXPIRES_IN: &str = "30m";
pub const DEFAULT_INTERVAL: &str = "5s";
pub const DEFAULT_DEVICE_CODE_LENGTH: usize = 40;
pub const DEFAULT_USER_CODE_LENGTH: usize = 8;
pub const MAX_GENERATED_CODE_CHARACTERS: usize = 191;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum DeviceAuthorizationMode {
    #[default]
    Standalone,
    OAuthProvider,
}

#[async_trait]
pub trait DeviceCodeGenerator: Send + Sync {
    async fn generate(&self) -> Result<String, AuthError>;
}

#[async_trait]
pub trait DeviceClientValidator: Send + Sync {
    async fn validate(&self, client_id: &str) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait DeviceAuthorizationRequestObserver: Send + Sync {
    async fn on_device_auth_request(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct DeviceAuthorizationConfig {
    pub expires_in: String,
    pub interval: String,
    pub device_code_length: usize,
    pub user_code_length: usize,
    pub generate_device_code: Option<Arc<dyn DeviceCodeGenerator>>,
    pub generate_user_code: Option<Arc<dyn DeviceCodeGenerator>>,
    pub validate_client: Option<Arc<dyn DeviceClientValidator>>,
    pub on_device_auth_request: Option<Arc<dyn DeviceAuthorizationRequestObserver>>,
    pub verification_uri: Option<String>,
    pub schema: DeviceAuthorizationSchema,
    /// Native representation of Better Auth's companion grant contribution.
    pub(crate) mode: DeviceAuthorizationMode,
}

impl Default for DeviceAuthorizationConfig {
    fn default() -> Self {
        Self {
            expires_in: DEFAULT_EXPIRES_IN.into(),
            interval: DEFAULT_INTERVAL.into(),
            device_code_length: DEFAULT_DEVICE_CODE_LENGTH,
            user_code_length: DEFAULT_USER_CODE_LENGTH,
            generate_device_code: None,
            generate_user_code: None,
            validate_client: None,
            on_device_auth_request: None,
            verification_uri: None,
            schema: DeviceAuthorizationSchema::default(),
            mode: DeviceAuthorizationMode::Standalone,
        }
    }
}

impl DeviceAuthorizationConfig {
    pub fn validate(&self) -> Result<(), DeviceAuthorizationConfigError> {
        validate_length("deviceCodeLength", self.device_code_length)?;
        validate_length("userCodeLength", self.user_code_length)?;
        parse_duration_milliseconds(&self.expires_in)?;
        parse_duration_milliseconds(&self.interval)?;
        super::schema::ResolvedDeviceAuthorizationSchema::new(
            &self.schema,
            self.mode == DeviceAuthorizationMode::OAuthProvider,
        )?;
        Ok(())
    }

    pub fn expires_in_milliseconds(&self) -> Result<f64, DeviceAuthorizationConfigError> {
        parse_duration_milliseconds(&self.expires_in)
    }

    pub fn interval_milliseconds(&self) -> Result<f64, DeviceAuthorizationConfigError> {
        parse_duration_milliseconds(&self.interval)
    }

    pub(crate) fn includes_oauth_fields(&self) -> bool {
        self.mode == DeviceAuthorizationMode::OAuthProvider
    }
}

impl fmt::Debug for DeviceAuthorizationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorizationConfig")
            .field("expires_in", &self.expires_in)
            .field("interval", &self.interval)
            .field("device_code_length", &self.device_code_length)
            .field("user_code_length", &self.user_code_length)
            .field("generate_device_code", &self.generate_device_code.is_some())
            .field("generate_user_code", &self.generate_user_code.is_some())
            .field("validate_client", &self.validate_client.is_some())
            .field(
                "on_device_auth_request",
                &self.on_device_auth_request.is_some(),
            )
            .field("verification_uri", &self.verification_uri)
            .field("schema", &self.schema)
            .field("mode", &self.mode)
            .finish()
    }
}

fn validate_length(
    option: &'static str,
    length: usize,
) -> Result<(), DeviceAuthorizationConfigError> {
    if !(1..=MAX_GENERATED_CODE_CHARACTERS).contains(&length) {
        return Err(DeviceAuthorizationConfigError::InvalidCodeLength { option, length });
    }
    Ok(())
}

/// Parses the exact Better Auth `utils/time` grammar and returns milliseconds.
pub fn parse_duration_milliseconds(original: &str) -> Result<f64, DeviceAuthorizationConfigError> {
    let lower = original.to_ascii_lowercase();
    let (prefix_sign, value) = if let Some(rest) = lower.strip_prefix("+ ") {
        (Some(1.0), rest)
    } else if let Some(rest) = lower.strip_prefix("-") {
        let rest = rest.strip_prefix(' ').unwrap_or(rest);
        (Some(-1.0), rest)
    } else if let Some(rest) = lower.strip_prefix('+') {
        (Some(1.0), rest)
    } else {
        (None, lower.as_str())
    };
    let (value, suffix_sign) = if let Some(base) = value.strip_suffix(" ago") {
        (base, Some(-1.0))
    } else if let Some(base) = value.strip_suffix(" from now") {
        (base, Some(1.0))
    } else {
        (value, None)
    };
    if prefix_sign.is_some() && suffix_sign.is_some() {
        return Err(DeviceAuthorizationConfigError::InvalidDuration(
            original.into(),
        ));
    }

    let digit_count = value.bytes().take_while(u8::is_ascii_digit).count();
    if digit_count == 0 {
        return Err(DeviceAuthorizationConfigError::InvalidDuration(
            original.into(),
        ));
    }
    let mut number_end = digit_count;
    if value.as_bytes().get(number_end) == Some(&b'.') {
        let fraction_start = number_end + 1;
        let fraction_count = value[fraction_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if fraction_count == 0 {
            return Err(DeviceAuthorizationConfigError::InvalidDuration(
                original.into(),
            ));
        }
        number_end = fraction_start + fraction_count;
    }
    let (number, remainder) = value.split_at(number_end);
    let unit = remainder.strip_prefix(' ').unwrap_or(remainder);
    if unit.is_empty() || unit.starts_with(' ') {
        return Err(DeviceAuthorizationConfigError::InvalidDuration(
            original.into(),
        ));
    }
    let amount = number
        .parse::<f64>()
        .map_err(|_| DeviceAuthorizationConfigError::InvalidDuration(original.into()))?;
    let multiplier = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1_000.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_000.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_000.0,
        "d" | "day" | "days" => 86_400_000.0,
        "w" | "week" | "weeks" => 604_800_000.0,
        "mo" | "month" | "months" => 2_592_000_000.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600_000.0,
        _ => {
            return Err(DeviceAuthorizationConfigError::InvalidDuration(
                original.into(),
            ));
        }
    };
    let result = amount * multiplier * prefix_sign.or(suffix_sign).unwrap_or(1.0);
    if !result.is_finite() {
        return Err(DeviceAuthorizationConfigError::InvalidDuration(
            original.into(),
        ));
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceAuthorizationConfigError {
    #[error("{option} must be a positive integer no greater than 191; received {length}")]
    InvalidCodeLength { option: &'static str, length: usize },
    #[error(
        "Invalid time string format: \"{0}\". Use formats like \"7d\", \"30m\", \"1 hour\", etc."
    )]
    InvalidDuration(String),
    #[error("unknown Better Auth Device Authorization field `{field}` on model `deviceCode`")]
    UnknownSchemaField { field: String },
    #[error("invalid {kind} identifier `{identifier}`: {reason}")]
    InvalidSchemaIdentifier {
        kind: &'static str,
        identifier: String,
        reason: &'static str,
    },
    #[error("duplicate field identifier `{identifier}` in the Device Authorization schema")]
    DuplicateSchemaIdentifier { identifier: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_better_auth_1_7_1() {
        let config = DeviceAuthorizationConfig::default();
        assert_eq!(config.expires_in, "30m");
        assert_eq!(config.interval, "5s");
        assert_eq!(config.device_code_length, 40);
        assert_eq!(config.user_code_length, 8);
        assert_eq!(config.expires_in_milliseconds(), Ok(1_800_000.0));
        assert_eq!(config.interval_milliseconds(), Ok(5_000.0));
    }

    #[test]
    fn duration_parser_matches_pinned_grammar_without_positive_fallbacks() {
        for (value, expected) in [
            ("0s", 0.0),
            ("-1.5s", -1_500.0),
            ("+ 2 mins", 120_000.0),
            ("2 months ago", -5_184_000_000.0),
            ("1.25 years from now", 39_447_000_000.0),
        ] {
            assert_eq!(parse_duration_milliseconds(value), Ok(expected), "{value}");
        }
        for value in [".5s", "1.s", " 1s", "1s ", "+  2m", "-1s ago"] {
            assert!(parse_duration_milliseconds(value).is_err(), "{value}");
        }
    }

    #[test]
    fn configured_lengths_are_always_validated() {
        for length in [0, 192] {
            let config = DeviceAuthorizationConfig {
                device_code_length: length,
                generate_device_code: Some(Arc::new(StaticGenerator)),
                ..DeviceAuthorizationConfig::default()
            };
            assert!(config.validate().is_err());
        }
    }

    struct StaticGenerator;

    #[async_trait]
    impl DeviceCodeGenerator for StaticGenerator {
        async fn generate(&self) -> Result<String, AuthError> {
            Ok(String::new())
        }
    }
}
