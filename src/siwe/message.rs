use chrono::{DateTime, Duration, Local, NaiveDate, NaiveDateTime, TimeZone};
use sha3::{Digest, Keccak256};
use std::borrow::Cow;

const HEADER_SUFFIX: &str = " wants you to sign in with your Ethereum account:";
const ADDRESS_LENGTH: usize = 42;
const NONCE_MIN_LENGTH: usize = 8;
const NONCE_MAX_LENGTH: usize = 250;

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct SiweMessage {
    pub(crate) scheme: Option<String>,
    pub(crate) domain: Option<String>,
    pub(crate) address: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) chain_id: Option<f64>,
    pub(crate) nonce: Option<String>,
    pub(crate) issued_at: Option<String>,
    pub(crate) expiration_time: Option<String>,
    pub(crate) not_before: Option<String>,
    pub(crate) request_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SiweTimeGate {
    Valid,
    Expired,
    NotYetValid,
}

pub(crate) fn parse_siwe_message(message: &str) -> SiweMessage {
    let mut lines = message_lines(message);
    let first_line = lines.next();
    let second_line = lines.next();
    let mut parsed = SiweMessage::default();

    if let Some(header) = first_line.and_then(parse_header) {
        parsed.scheme = header.0.map(str::to_owned);
        parsed.domain = Some(header.1.to_owned());
    }
    if let Some(address) = second_line.map(str::trim).filter(|value| is_address(value)) {
        parsed.address = Some(address.to_owned());
    }

    for line in message_lines(message) {
        let Some((key, value)) = line.split_once(": ") else {
            continue;
        };
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphabetic() || byte == b' ')
        {
            continue;
        }
        match key {
            "URI" => parsed.uri = Some(value.to_owned()),
            "Version" => parsed.version = Some(value.to_owned()),
            "Chain ID" => {
                if let Some(chain_id) = parse_javascript_integer(value) {
                    parsed.chain_id = Some(chain_id);
                }
            }
            "Nonce" => parsed.nonce = Some(value.to_owned()),
            "Issued At" => parsed.issued_at = Some(value.to_owned()),
            "Expiration Time" => parsed.expiration_time = Some(value.to_owned()),
            "Not Before" => parsed.not_before = Some(value.to_owned()),
            "Request ID" => parsed.request_id = Some(value.to_owned()),
            _ => {}
        }
    }

    parsed
}

pub(crate) fn normalize_siwe_domain(domain: &str) -> String {
    let normalized = domain.trim().to_lowercase();
    let without_scheme = normalized
        .find("://")
        .filter(|separator| is_scheme(&normalized[..*separator]))
        .map_or(normalized.as_str(), |separator| {
            &normalized[separator + 3..]
        });
    without_scheme
        .split_once('/')
        .map_or(without_scheme, |(authority, _)| authority)
        .to_owned()
}

pub(crate) fn is_valid_siwe_nonce(nonce: &str) -> bool {
    (NONCE_MIN_LENGTH..=NONCE_MAX_LENGTH).contains(&nonce.len())
        && nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

pub(crate) fn to_checksum_address(address: &str) -> Option<String> {
    if !is_address(address) {
        return None;
    }
    let lowercase = address[2..].to_ascii_lowercase();
    let hash = Keccak256::digest(lowercase.as_bytes());
    let mut checksummed = String::with_capacity(ADDRESS_LENGTH);
    checksummed.push_str("0x");
    for (index, character) in lowercase.bytes().enumerate() {
        let nibble = if index % 2 == 0 {
            hash[index / 2] >> 4
        } else {
            hash[index / 2] & 0x0f
        };
        checksummed.push(if nibble >= 8 {
            char::from(character).to_ascii_uppercase()
        } else {
            char::from(character)
        });
    }
    Some(checksummed)
}

pub(crate) fn siwe_time_gate(message: &SiweMessage, now_millis: i64) -> SiweTimeGate {
    if message
        .expiration_time
        .as_deref()
        .and_then(parse_date_millis)
        .is_some_and(|expiration| now_millis >= expiration)
    {
        return SiweTimeGate::Expired;
    }
    if message
        .not_before
        .as_deref()
        .and_then(parse_date_millis)
        .is_some_and(|not_before| now_millis < not_before)
    {
        return SiweTimeGate::NotYetValid;
    }
    SiweTimeGate::Valid
}

fn parse_header(line: &str) -> Option<(Option<&str>, &str)> {
    let authority = line.strip_suffix(HEADER_SUFFIX)?;
    if authority.is_empty() || authority.chars().any(char::is_whitespace) {
        return None;
    }
    let scheme_separator = authority.find("://");
    if let Some(separator) =
        scheme_separator.filter(|separator| is_scheme(&authority[..*separator]))
    {
        let domain = &authority[separator + 3..];
        return (!domain.is_empty()).then_some((Some(&authority[..separator]), domain));
    }
    Some((None, authority))
}

fn is_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
}

fn is_address(value: &str) -> bool {
    value.len() == ADDRESS_LENGTH
        && value.starts_with("0x")
        && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn message_lines(message: &str) -> impl Iterator<Item = &str> {
    message
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
}

fn parse_javascript_integer(value: &str) -> Option<f64> {
    let value = value.trim();
    if value.is_empty() {
        return Some(0.0);
    }
    let number = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hexadecimal) => parse_radix_number(hexadecimal, 16),
        None => match value
            .strip_prefix("0b")
            .or_else(|| value.strip_prefix("0B"))
        {
            Some(binary) => parse_radix_number(binary, 2),
            None => match value
                .strip_prefix("0o")
                .or_else(|| value.strip_prefix("0O"))
            {
                Some(octal) => parse_radix_number(octal, 8),
                None => value.parse::<f64>().ok(),
            },
        },
    }?;
    (number.is_finite() && number.fract() == 0.0).then_some(number)
}

fn parse_radix_number(value: &str, radix: u32) -> Option<f64> {
    if value.is_empty() {
        return None;
    }
    value.chars().try_fold(0.0_f64, |number, character| {
        let digit = character.to_digit(radix)?;
        let number = number.mul_add(f64::from(radix), f64::from(digit));
        number.is_finite().then_some(number)
    })
}

fn parse_date_millis(value: &str) -> Option<i64> {
    let value = value.trim();
    DateTime::parse_from_rfc3339(normalize_iso_fraction(value).as_ref())
        .or_else(|_| DateTime::parse_from_rfc2822(value))
        .ok()
        .map(|date| date.timestamp_millis())
        .or_else(|| parse_javascript_date_only(value))
        .or_else(|| parse_javascript_local_datetime(value))
        .or_else(|| parse_javascript_legacy_date(value))
}

fn normalize_iso_fraction(value: &str) -> Cow<'_, str> {
    let Some(time) = value.find('T') else {
        return Cow::Borrowed(value);
    };
    let Some(relative_dot) = value[time..].find('.') else {
        return Cow::Borrowed(value);
    };
    let dot = time + relative_dot;
    let digits = value[dot + 1..]
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    if digits <= 9 {
        return Cow::Borrowed(value);
    }
    let suffix = dot + 1 + digits;
    Cow::Owned(format!("{}{}", &value[..dot + 10], &value[suffix..]))
}

fn parse_javascript_date_only(value: &str) -> Option<i64> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts
        .next()
        .map_or(Some(1), |month| month.parse::<u32>().ok())?;
    let day = parts
        .next()
        .map_or(Some(1), |day| day.parse::<u32>().ok())?;
    if parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !matches!(value.len(), 4 | 7 | 10)
    {
        return None;
    }
    NaiveDate::from_ymd_opt(year, month, 1)?
        .checked_add_signed(Duration::days(i64::from(day - 1)))?
        .and_hms_opt(0, 0, 0)
        .map(|date| date.and_utc().timestamp_millis())
}

fn parse_javascript_local_datetime(value: &str) -> Option<i64> {
    if let Some(utc) = value.strip_suffix('Z') {
        return ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S%.f"]
            .into_iter()
            .find_map(|format| NaiveDateTime::parse_from_str(utc, format).ok())
            .map(|date| date.and_utc().timestamp_millis());
    }
    [
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S%.f",
    ]
    .into_iter()
    .find_map(|format| NaiveDateTime::parse_from_str(value, format).ok())
    .and_then(|date| Local.from_local_datetime(&date).earliest())
    .map(|date| date.timestamp_millis())
}

fn parse_javascript_legacy_date(value: &str) -> Option<i64> {
    let datetime = [
        "%b %d %Y %H:%M:%S",
        "%B %d %Y %H:%M:%S",
        "%B %d, %Y %H:%M:%S",
        "%d %b %Y %H:%M:%S",
        "%d %B %Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
    ]
    .into_iter()
    .find_map(|format| NaiveDateTime::parse_from_str(value, format).ok());
    if let Some(datetime) = datetime {
        return Local
            .from_local_datetime(&datetime)
            .earliest()
            .map(|date| date.timestamp_millis());
    }
    [
        "%b %d %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%B %d, %Y",
        "%d %b %Y",
        "%d %B %Y",
        "%m/%d/%Y",
    ]
    .into_iter()
    .find_map(|format| NaiveDate::parse_from_str(value, format).ok())
    .and_then(|date| date.and_hms_opt(0, 0, 0))
    .and_then(|date| Local.from_local_datetime(&date).earliest())
    .map(|date| date.timestamp_millis())
}

#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;
