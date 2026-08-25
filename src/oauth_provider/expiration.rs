use chrono::{DateTime, Utc};

use super::OAuthExpiration;

pub(crate) fn expiration_timestamp(
    expiration: &OAuthExpiration,
    issued_at: i64,
) -> Result<i64, String> {
    match expiration {
        OAuthExpiration::Timestamp(timestamp) => Ok(*timestamp),
        OAuthExpiration::Date(date) => Ok(date.timestamp()),
        OAuthExpiration::Duration(value) => issued_at
            .checked_add(parse_duration_seconds(value)?)
            .ok_or_else(|| format!("expiration time overflows for {value:?}")),
    }
}

pub(crate) fn expiration_date(
    expiration: &OAuthExpiration,
    issued_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, String> {
    if matches!(expiration, OAuthExpiration::Timestamp(0)) {
        return Ok(None);
    }
    let timestamp = expiration_timestamp(expiration, issued_at.timestamp())?;
    DateTime::from_timestamp(timestamp, 0)
        .map(Some)
        .ok_or_else(|| format!("expiration timestamp {timestamp} is out of range"))
}

fn parse_duration_seconds(value: &str) -> Result<i64, String> {
    let original = value;
    let mut value = value.to_ascii_lowercase();
    let suffix = if let Some(base) = value.strip_suffix(" from now") {
        value = base.to_owned();
        Some(1_i8)
    } else if let Some(base) = value.strip_suffix(" ago") {
        value = base.to_owned();
        Some(-1_i8)
    } else {
        None
    };
    let (explicit_sign, value) = if let Some(rest) = value.strip_prefix('+') {
        (Some(1_i8), rest.strip_prefix(' ').unwrap_or(rest))
    } else if let Some(rest) = value.strip_prefix('-') {
        (Some(-1_i8), rest.strip_prefix(' ').unwrap_or(rest))
    } else {
        (None, value.as_str())
    };
    if suffix.is_some() && explicit_sign.is_some() {
        return Err(invalid_duration(original));
    }
    let integer_end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    if integer_end == 0 {
        return Err(invalid_duration(original));
    }
    let mut number_end = integer_end;
    if value.as_bytes().get(number_end) == Some(&b'.') {
        let fraction_start = number_end + 1;
        let fraction_len = value[fraction_start..]
            .bytes()
            .take_while(u8::is_ascii_digit)
            .count();
        if fraction_len == 0 {
            return Err(invalid_duration(original));
        }
        number_end = fraction_start + fraction_len;
    }
    let (number, rest) = value.split_at(number_end);
    let unit = rest.strip_prefix(' ').unwrap_or(rest);
    if unit.starts_with(' ') {
        return Err(invalid_duration(original));
    }
    let amount = number
        .parse::<f64>()
        .map_err(|_| invalid_duration(original))?;
    let seconds = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => 1_f64,
        "m" | "min" | "mins" | "minute" | "minutes" => 60_f64,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600_f64,
        "d" | "day" | "days" => 86_400_f64,
        "w" | "week" | "weeks" => 604_800_f64,
        "mo" | "month" | "months" => 2_592_000_f64,
        "y" | "yr" | "yrs" | "year" | "years" => 31_557_600_f64,
        _ => return Err(invalid_duration(original)),
    };
    let sign = explicit_sign.or(suffix).unwrap_or(1) as f64;
    let result = (sign * amount * seconds + 0.5).floor();
    if !result.is_finite() || result < i64::MIN as f64 || result > i64::MAX as f64 {
        return Err(invalid_duration(original));
    }
    Ok(result as i64)
}

fn invalid_duration(value: &str) -> String {
    format!(
        "Invalid time string format: {value:?}. Use formats like \"7d\", \"30m\", \"1 hour\", etc."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_expiration_is_an_absolute_timestamp() {
        assert_eq!(
            expiration_timestamp(&OAuthExpiration::Timestamp(1_700_000_000), 2_000_000_000),
            Ok(1_700_000_000)
        );
    }

    #[test]
    fn duration_parser_matches_better_auth_time_formats() {
        let cases = [
            ("1.5 hours", 5_400),
            ("2 months", 5_184_000),
            (".5h", i64::MIN),
            ("30s ago", -30),
            ("+ 2 mins", 120),
            ("-1.5s", -1),
        ];
        for (value, expected) in cases {
            let parsed = parse_duration_seconds(value);
            if expected == i64::MIN {
                assert!(parsed.is_err(), "{value}");
            } else {
                assert_eq!(parsed, Ok(expected), "{value}");
            }
        }
        assert!(parse_duration_seconds("+ 2 mins ago").is_err());
        for invalid in [" 1h", "1h ", "+  2m", "1  h"] {
            assert!(parse_duration_seconds(invalid).is_err(), "{invalid}");
        }
    }
}
