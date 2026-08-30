use super::DEFAULT_CLOCK_SKEW_MS;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SamlConditions {
    pub not_before: Option<String>,
    pub not_on_or_after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamlTimestampOptions {
    pub clock_skew_ms: i64,
    pub require_timestamps: bool,
}

impl Default for SamlTimestampOptions {
    fn default() -> Self {
        Self {
            clock_skew_ms: DEFAULT_CLOCK_SKEW_MS,
            require_timestamps: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SamlTimestampError {
    #[error("SAML assertion missing required timestamp conditions")]
    Missing,
    #[error("SAML assertion has invalid NotBefore timestamp")]
    InvalidNotBefore,
    #[error("SAML assertion is not yet valid")]
    NotYetValid,
    #[error("SAML assertion has invalid NotOnOrAfter timestamp")]
    InvalidNotOnOrAfter,
    #[error("SAML assertion has expired")]
    Expired,
}

pub fn validate_saml_timestamp(
    conditions: Option<&SamlConditions>,
    options: SamlTimestampOptions,
) -> Result<(), SamlTimestampError> {
    validate_saml_timestamp_at(conditions, options, Utc::now())
}

pub fn validate_saml_timestamp_at(
    conditions: Option<&SamlConditions>,
    options: SamlTimestampOptions,
    now: DateTime<Utc>,
) -> Result<(), SamlTimestampError> {
    let has_timestamp = conditions.is_some_and(|conditions| {
        conditions.not_before.is_some() || conditions.not_on_or_after.is_some()
    });
    if !has_timestamp {
        return if options.require_timestamps {
            Err(SamlTimestampError::Missing)
        } else {
            Ok(())
        };
    }
    let conditions = conditions.expect("timestamp conditions");
    if let Some(value) = &conditions.not_before {
        let not_before = DateTime::parse_from_rfc3339(value)
            .map_err(|_| SamlTimestampError::InvalidNotBefore)?
            .with_timezone(&Utc);
        if now.timestamp_millis() < not_before.timestamp_millis() - options.clock_skew_ms {
            return Err(SamlTimestampError::NotYetValid);
        }
    }
    if let Some(value) = &conditions.not_on_or_after {
        let not_on_or_after = DateTime::parse_from_rfc3339(value)
            .map_err(|_| SamlTimestampError::InvalidNotOnOrAfter)?
            .with_timezone(&Utc);
        if now.timestamp_millis() > not_on_or_after.timestamp_millis() + options.clock_skew_ms {
            return Err(SamlTimestampError::Expired);
        }
    }
    Ok(())
}
