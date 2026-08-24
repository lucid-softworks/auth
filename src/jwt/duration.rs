use super::JwtExpiration;
use crate::{AuthError, JwtError};

pub fn to_exp_jwt(expiration: &JwtExpiration, iat: f64) -> Result<f64, AuthError> {
    match expiration {
        JwtExpiration::NumericDate(value) => Ok(*value),
        JwtExpiration::Date(value) => Ok((value.timestamp_millis() as f64 / 1_000.0).floor()),
        JwtExpiration::Duration(value) => parse_duration_seconds(value)
            .map(|seconds| iat + seconds)
            .filter(|value| value.is_finite())
            .ok_or_else(|| JwtError::InvalidExpiration(value.clone()).into()),
    }
}

fn parse_duration_seconds(input: &str) -> Option<f64> {
    let lower = input.to_ascii_lowercase();
    let (signed, body) = match lower.as_bytes().first() {
        Some(b'+') => (1.0, lower[1..].trim_start()),
        Some(b'-') => (-1.0, lower[1..].trim_start()),
        _ => (1.0, lower.as_str()),
    };
    let (body, suffix_sign) = if let Some(value) = body.strip_suffix(" ago") {
        if signed != 1.0 {
            return None;
        }
        (value, -1.0)
    } else if let Some(value) = body.strip_suffix(" from now") {
        if signed != 1.0 {
            return None;
        }
        (value, 1.0)
    } else {
        (body, signed)
    };
    let split = body.find(|character: char| !(character.is_ascii_digit() || character == '.'))?;
    let number = body[..split].parse::<f64>().ok()?;
    if !number.is_finite() || number < 0.0 {
        return None;
    }
    let unit = body[split..].trim();
    if unit.is_empty() || body[..split].is_empty() {
        return None;
    }
    let seconds = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600.0,
        "d" | "day" | "days" => 86_400.0,
        "w" | "week" | "weeks" => 604_800.0,
        "mo" | "month" | "months" => 2_592_000.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600.0,
        _ => return None,
    };
    Some(js_round(number * seconds * suffix_sign))
}

fn js_round(value: f64) -> f64 {
    (value + 0.5).floor()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_better_auth_runtime_duration_grammar() {
        for (value, expected) in [
            ("15m", 900.0),
            ("1.5 seconds", 2.0),
            ("0.5 seconds ago", 0.0),
            ("2 months", 5_184_000.0),
            ("+ 1 year", 31_557_600.0),
            ("1 day from now", 86_400.0),
        ] {
            assert_eq!(parse_duration_seconds(value), Some(expected), "{value}");
        }
        for value in ["", "15", "- 1d ago", "NaN seconds", "1 fortnight"] {
            assert_eq!(parse_duration_seconds(value), None, "{value}");
        }
    }
}
