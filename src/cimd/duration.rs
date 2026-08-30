use super::{CimdConfigError, CimdDuration};
use std::time::Duration;

pub(super) fn parse_duration(
    value: &CimdDuration,
    option: &'static str,
) -> Result<Duration, CimdConfigError> {
    let seconds = match value {
        CimdDuration::Seconds(seconds) if seconds.is_finite() && *seconds >= 0.0 => *seconds,
        CimdDuration::Seconds(_) => return Err(CimdConfigError::InvalidDuration(option)),
        CimdDuration::Text(value) => parse_duration_seconds(value)
            .ok_or(CimdConfigError::InvalidDuration(option))?,
    };
    Ok(Duration::from_secs_f64(seconds))
}

fn parse_duration_seconds(input: &str) -> Option<f64> {
    let lower = input.to_ascii_lowercase();
    let (signed, body) = match lower.as_bytes().first() {
        Some(b'+') => (1.0, lower[1..].trim_start()),
        Some(b'-') => (-1.0, lower[1..].trim_start()),
        _ => (1.0, lower.as_str()),
    };
    let (body, suffix_sign) = if let Some(value) = body.strip_suffix(" ago") {
        if signed != 1.0 { return None; }
        (value, -1.0)
    } else if let Some(value) = body.strip_suffix(" from now") {
        if signed != 1.0 { return None; }
        (value, 1.0)
    } else {
        (body, signed)
    };
    let split = body.find(|character: char| !(character.is_ascii_digit() || character == '.'))?;
    let number = body[..split].parse::<f64>().ok()?;
    if !number.is_finite() || number < 0.0 { return None; }
    let unit = body[split..].trim();
    let multiplier = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1.0,
        "m" | "min" | "mins" | "minute" | "minutes" => 60.0,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600.0,
        "d" | "day" | "days" => 86_400.0,
        "w" | "week" | "weeks" => 604_800.0,
        "mo" | "month" | "months" => 2_592_000.0,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600.0,
        _ => return None,
    };
    let seconds = (number * multiplier * suffix_sign + 0.5).floor();
    (seconds.is_finite() && seconds >= 0.0).then_some(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_better_auth_duration_inputs() {
        for (value, expected) in [("60m", 3_600), ("1 day", 86_400), ("1.5 seconds", 2)] {
            assert_eq!(
                parse_duration(&CimdDuration::Text(value.into()), "test").unwrap(),
                Duration::from_secs(expected)
            );
        }
        for value in ["", "15", "-1s", "1 fortnight"] {
            assert!(parse_duration(&CimdDuration::Text(value.into()), "test").is_err());
        }
    }
}
